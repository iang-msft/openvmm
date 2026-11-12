// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Linux ptrace collection for child processes.

// UNSAFETY: ptrace, waitpid, kill, and process_vm_readv are Linux process APIs.
#![expect(unsafe_code)]

use crate::TraceConfig;
use fs_err::os::unix::fs::OpenOptionsExt;
use seccompiler::SeccompAction;
use seccompiler::SeccompFilter;
use seccompiler::TargetArch;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

const MAX_STRING_LEN: usize = 16 * 1024;
const TRACE_BUFFER_CAPACITY: usize = 256 * 1024;

// Linux UAPI bindings from include/uapi/linux/ptrace.h:
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/ptrace.h
// libc 0.2.184 exposes these on GNU but not musl; the kernel ABI is the same.
const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;
const PTRACE_SYSCALL_INFO_SECCOMP: u8 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    u: PtraceSyscallInfoData,
}

#[repr(C)]
#[derive(Clone, Copy)]
union PtraceSyscallInfoData {
    entry: PtraceSyscallInfoEntry,
    exit: PtraceSyscallInfoExit,
    seccomp: PtraceSyscallInfoSeccomp,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallInfoEntry {
    nr: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallInfoExit {
    sval: i64,
    is_error: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallInfoSeccomp {
    nr: u64,
    args: [u64; 6],
    ret_data: u32,
}

/// Build the seccomp filter that stops profile-relevant syscalls under ptrace.
pub fn build_seccomp_filter(config: &TraceConfig) -> io::Result<SeccompFilter> {
    // Matching syscalls stop under ptrace, while every other syscall continues normally.
    let rules = config
        .syscalls
        .keys()
        .copied()
        .map(|sys_nr| (sys_nr as libc::c_long, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Trace(0),
        target_arch(),
    )
    .map_err(|error| io::Error::other(format!("seccomp filter creation failed: {error}")))
}

fn target_arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::aarch64
    }
}

/// Represents a child running under ptrace-based syscall tracing.
///
/// [`TracedChild::start`] retains the child handle and starts a dedicated thread
/// to perform blocking ptrace work using its PID. [`TracedChild::wait`] receives
/// the status sent by that thread after tracing finishes.
pub struct TracedChild {
    _child: pal::unix::process::Child,
    completion: Option<async_channel::Receiver<io::Result<ExitStatus>>>,
}

impl TracedChild {
    /// Starts a dedicated ptrace thread before the child begins executing.
    pub fn start(
        child: pal::unix::process::Child,
        process_name: &str,
        config: TraceConfig,
    ) -> io::Result<Self> {
        let child_pid = child.id();
        let process_name = process_name.to_owned();
        let (send, recv) = async_channel::bounded(1);

        // ptrace is driven by blocking waitpid calls. Keep that state machine
        // on a dedicated thread and expose only its completion asynchronously.
        let spawned = std::thread::Builder::new()
            .name(format!("ptrace-{process_name}-{child_pid}"))
            .spawn(move || {
                let result = trace_process(child_pid, &process_name, &config);
                let _ = send.send_blocking(result);
            });

        if let Err(spawn_error) = spawned {
            if let Err(cleanup_error) = reap_child_on_trace_failure(child_pid, false) {
                return Err(io::Error::other(format!(
                    "failed to create tracing thread: {spawn_error}; \
                     worker cleanup also failed: {cleanup_error}"
                )));
            }

            return Err(spawn_error);
        }

        Ok(Self {
            _child: child,
            completion: Some(recv),
        })
    }

    /// Waits for the root child process and its tracer to finish.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.completion
            .take()
            .expect("traced child waited more than once")
            .recv()
            .await
            .map_err(|_| io::Error::other("process tracer exited without reporting status"))?
    }
}

// Seccomp stops a thread before the selected syscall runs, so its arguments
// are available but its result is not. Keep this entry information for that
// thread until ptrace stops it again after the syscall returns.
struct PendingSyscall {
    sys_nr: u64,
    name: String,
    args: [u64; 6],
    started: Instant,
    decoded_args: Value,
    path_metadata: Option<Value>,
    path2_metadata: Option<Value>,
}

// Runs the tracing loop for one child process tree: attaches before exec,
// follows new tasks, pairs selected syscall entries with exits, and serializes
// the resulting activity as JSONL.
fn trace_process(
    child_pid: i32,
    process_name: &str,
    config: &TraceConfig,
) -> io::Result<ExitStatus> {
    let mut child_reaped = false;

    let initialization: io::Result<_> = (|| {
        fs_err::create_dir_all(&config.output_dir)?;

        let trace_path = config.output_dir.join(format!(
            "{}-{}.{child_pid}.jsonl",
            sanitize_name(&config.file_prefix),
            sanitize_name(process_name)
        ));

        // Batch writes so a slow output filesystem cannot stall a traced task at
        // every syscall stop. The buffer is flushed when it fills and at exit.
        let output = BufWriter::with_capacity(TRACE_BUFFER_CAPACITY, File::create(&trace_path)?);

        wait_for_initial_stop(child_pid, &mut child_reaped)?;
        ptrace(
            libc::PTRACE_SEIZE as _,
            child_pid,
            0,
            trace_options() as usize,
        )?;

        // Attachment succeeded; the cleanup scope ends here.
        Ok((trace_path, output))
    })();

    let (trace_path, mut output) = match initialization {
        Ok(initialized) => initialized,
        Err(error) => {
            if let Err(cleanup_error) = reap_child_on_trace_failure(child_pid, child_reaped) {
                return Err(io::Error::other(format!(
                    "{error}; worker cleanup also failed: {cleanup_error}"
                )));
            }

            return Err(error);
        }
    };

    let initial_cwd = fd_target(child_pid, libc::AT_FDCWD as u64);

    // Release the pre-exec group stop. PTRACE_O_TRACEEXEC guarantees another
    // stop before the child's new image executes user code.
    // SAFETY: kill accepts any PID and signal value; errors are reported via errno.
    syscall_result(unsafe { libc::kill(child_pid, libc::SIGCONT) })?;

    write_event(
        &mut output,
        json!({
            "event": "trace_started",
            "pid": child_pid,
            "trace_file": trace_path,
            "cwd": initial_cwd,
        }),
    )?;

    // ptrace reports stops for every followed thread and descendant through
    // one wait queue. The optional value tracks whether that task is between a
    // selected syscall's entry and exit stops.
    let mut tasks = HashMap::<i32, Option<PendingSyscall>>::new();
    tasks.insert(child_pid, None);

    loop {
        let mut status = 0;
        // SAFETY: status points to writable memory, and the options are valid waitpid flags.
        let tid = syscall_result(unsafe {
            libc::waitpid(-1, &mut status, libc::__WALL | libc::__WNOTHREAD)
        })?;

        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            write_event(
                &mut output,
                json!({
                    "event": "task_exit",
                    "pid": child_pid,
                    "tid": tid,
                    "exit_code": libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
                    "signal": libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)),
                }),
            )?;
            tasks.remove(&tid);
            if tid == child_pid {
                output.flush()?;
                return Ok(ExitStatus::from_raw(status));
            }
            continue;
        }

        if !libc::WIFSTOPPED(status) {
            continue;
        }

        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        // Only a seccomp-selected entry switches a task to PTRACE_SYSCALL.
        // All other tasks run with PTRACE_CONT so unrelated syscalls do not
        // generate entry/exit stops.
        if signal == (libc::SIGTRAP | 0x80) {
            handle_syscall_exit(&mut output, child_pid, tid, tasks.entry(tid).or_default())?;
            resume_cont(tid, 0)?;
        } else if signal == libc::SIGTRAP && event == libc::PTRACE_EVENT_SECCOMP {
            handle_seccomp_stop(tid, tasks.entry(tid).or_default(), &config.syscalls)?;
            resume_syscall(tid, 0)?;
        } else if signal == libc::SIGTRAP && event != 0 {
            handle_ptrace_event(&mut output, child_pid, tid, event, &mut tasks)?;
            resume_task(tid, tasks.get(&tid).is_some_and(Option::is_some), 0)?;
        } else {
            // Synthetic SIGTRAP stops were handled above; deliver real traps.
            let deliver = if signal == libc::SIGSTOP { 0 } else { signal };
            resume_task(tid, tasks.get(&tid).is_some_and(Option::is_some), deliver)?;
        }
    }
}

fn wait_for_initial_stop(pid: i32, child_reaped: &mut bool) -> io::Result<()> {
    let status = loop {
        let mut status = 0;
        // SAFETY: status is writable.
        match syscall_result(unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) }) {
            Ok(_) => break status,
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => return Err(error),
        }
    };

    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        *child_reaped = true;
    }

    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        return Err(io::Error::other(format!(
            "child {pid} did not stop before exec: status {status:#x}"
        )));
    }

    Ok(())
}

fn reap_child_on_trace_failure(child_pid: i32, child_reaped: bool) -> io::Result<()> {
    if child_reaped {
        return Ok(());
    }

    if child_pid <= 0 {
        return Err(io::Error::other("invalid cleanup process id"));
    }

    // SAFETY: child_pid identifies the worker we spawned.
    let result = syscall_result(unsafe { libc::kill(child_pid, libc::SIGKILL) });
    if let Err(error) = result {
        // Ignore ESRCH ("No such process"): kill could not find the worker PID.
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }

    loop {
        let mut status = 0;
        // SAFETY: status is writable; flags=0 waits for this untraced child's exit.
        match syscall_result(unsafe { libc::waitpid(child_pid, &mut status, 0) }) {
            Ok(_) => return Ok(()),
            // A signal interrupted the wait; retry instead of abandoning cleanup.
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            // No child with this PID remains for our process to wait for.
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

// Records process-tree changes reported by ptrace and enrolls newly created
// tasks in the per-thread syscall state machine.
fn handle_ptrace_event(
    output: &mut BufWriter<File>,
    root_pid: i32,
    tid: i32,
    event: i32,
    tasks: &mut HashMap<i32, Option<PendingSyscall>>,
) -> io::Result<()> {
    let event_name = match event {
        libc::PTRACE_EVENT_FORK => "fork",
        libc::PTRACE_EVENT_VFORK => "vfork",
        libc::PTRACE_EVENT_CLONE => "clone",
        libc::PTRACE_EVENT_EXEC => "exec",
        libc::PTRACE_EVENT_EXIT => "exit",
        _ => "other",
    };

    let mut new_tid = None;
    if matches!(
        event,
        libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE
    ) {
        let mut message = 0usize;
        ptrace(
            libc::PTRACE_GETEVENTMSG as _,
            tid,
            0,
            std::ptr::from_mut(&mut message) as usize,
        )?;
        let child_tid = i32::try_from(message)
            .map_err(|_| io::Error::other("ptrace returned an invalid child tid"))?;
        // The ptrace follow options attach descendants automatically; adding
        // the new task here gives it independent syscall entry/exit state.
        tasks.insert(child_tid, None);
        new_tid = Some(child_tid);
    }

    write_event(
        output,
        json!({
            "event": "ptrace_event",
            "pid": root_pid,
            "tid": tid,
            "kind": event_name,
            "new_tid": new_tid,
        }),
    )
}

// Captures a selected syscall at entry, including argument data that must be
// read from the tracee before its address space can change.
fn handle_seccomp_stop(
    tid: i32,
    pending: &mut Option<PendingSyscall>,
    traced_syscall_map: &BTreeMap<libc::c_long, String>,
) -> io::Result<()> {
    let mut info = MaybeUninit::<PtraceSyscallInfo>::zeroed();
    let size = size_of::<PtraceSyscallInfo>();
    ptrace(
        PTRACE_GET_SYSCALL_INFO,
        tid,
        size,
        info.as_mut_ptr() as usize,
    )?;
    // SAFETY: the kernel initialized the structure after a successful ptrace.
    let info = unsafe { info.assume_init() };

    if info.op != PTRACE_SYSCALL_INFO_SECCOMP {
        return Err(io::Error::other(format!(
            "unexpected syscall info operation {} at seccomp stop",
            info.op
        )));
    }

    // SAFETY: op identifies the active union member.
    let entry = unsafe { info.u.seccomp };
    let sys_nr = entry.nr;
    let name = traced_syscall_map
        .get(&(sys_nr as libc::c_long))
        .ok_or_else(|| {
            io::Error::other(format!(
                "seccomp reported non-allowlisted syscall number {sys_nr}"
            ))
        })?;
    // Decode pointer arguments while the task is stopped at entry. The child
    // may change or unmap the referenced memory before the syscall returns.
    let started = Instant::now();
    let decoded_args = decode_args(tid, sys_nr, entry.args);
    // Unlink and rename can remove the source before the exit stop.
    let destructive = sys_nr == libc::SYS_unlinkat as u64 || sys_nr == libc::SYS_renameat2 as u64;
    let path_metadata = destructive
        .then(|| snapshot_path_metadata(tid, sys_nr, entry.args, &decoded_args, false))
        .flatten();
    let path2_metadata = (sys_nr == libc::SYS_renameat2 as u64)
        .then(|| snapshot_path_metadata(tid, sys_nr, entry.args, &decoded_args, true))
        .flatten();
    *pending = Some(PendingSyscall {
        sys_nr,
        name: name.clone(),
        args: entry.args,
        started,
        decoded_args,
        path_metadata,
        path2_metadata,
    });
    Ok(())
}

// Completes the syscall record with its return value, error, and elapsed time,
// then clears the per-thread entry state.
fn handle_syscall_exit(
    output: &mut BufWriter<File>,
    root_pid: i32,
    tid: i32,
    pending: &mut Option<PendingSyscall>,
) -> io::Result<()> {
    let mut info = MaybeUninit::<PtraceSyscallInfo>::zeroed();
    let size = size_of::<PtraceSyscallInfo>();
    ptrace(
        PTRACE_GET_SYSCALL_INFO,
        tid,
        size,
        info.as_mut_ptr() as usize,
    )?;
    // SAFETY: the kernel initialized the structure after a successful ptrace.
    let info = unsafe { info.assume_init() };
    if info.op != PTRACE_SYSCALL_INFO_EXIT {
        return Err(io::Error::other(format!(
            "unexpected syscall info operation {} at syscall exit stop",
            info.op
        )));
    }

    // SAFETY: op identifies the active union member.
    let exit = unsafe { info.u.exit };
    let entry = pending
        .take()
        .ok_or_else(|| io::Error::other("syscall exit stop has no pending seccomp event"))?;
    let opened_file = (entry.sys_nr == libc::SYS_openat as u64
        && exit.is_error == 0
        && exit.sval >= 0)
        .then(|| {
            opened_file_metadata(tid, exit.sval).unwrap_or_else(|_| json!({"file_type": "unknown"}))
        });
    let success = exit.is_error == 0 && exit.sval >= 0;
    let path_metadata = success
        .then(|| {
            if entry.sys_nr == libc::SYS_statx as u64 || entry.sys_nr == libc::SYS_newfstatat as u64
            {
                Some(
                    stat_file_metadata(tid, entry.sys_nr, entry.args)
                        .unwrap_or_else(|_| json!({"file_type": "unknown"})),
                )
            } else if entry.sys_nr == libc::SYS_openat as u64 {
                None
            } else {
                entry.path_metadata.or_else(|| {
                    snapshot_path_metadata(
                        tid,
                        entry.sys_nr,
                        entry.args,
                        &entry.decoded_args,
                        false,
                    )
                })
            }
        })
        .flatten();
    let path2_metadata = success.then_some(entry.path2_metadata).flatten();
    write_event(
        output,
        json!({
            "event": "syscall",
            "timestamp_ns": unix_timestamp_ns(),
            "pid": root_pid,
            "tid": tid,
            "syscall": entry.name,
            "sys_nr": entry.sys_nr,
            "args": entry.args,
            "decoded_args": entry.decoded_args,
            "opened_file": opened_file,
            "path_metadata": path_metadata,
            "path2_metadata": path2_metadata,
            "result": exit.sval,
            "errno": (exit.is_error != 0).then(|| -exit.sval),
            "duration_ns": entry.started.elapsed().as_nanos(),
        }),
    )?;
    Ok(())
}

fn opened_file_metadata(tid: i32, fd: i64) -> io::Result<Value> {
    // O_PATH pins the object without reopening the device for I/O. Other
    // threads can still close/reuse the tracee's fd before this snapshot.
    let file = fs_err::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(format!("/proc/{tid}/fd/{fd}"))?;
    let metadata = file.metadata()?;
    let mut snapshot = file_metadata(
        metadata.mode(),
        libc::major(metadata.rdev()),
        libc::minor(metadata.rdev()),
    );
    snapshot["path"] = json!(
        fs_err::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
    );
    Ok(snapshot)
}

fn file_metadata(mode: libc::mode_t, device_major: u32, device_minor: u32) -> Value {
    let file_type = match mode & libc::S_IFMT {
        libc::S_IFREG => "regular_file",
        libc::S_IFDIR => "directory",
        libc::S_IFCHR => "character_device",
        libc::S_IFBLK => "block_device",
        libc::S_IFIFO => "fifo",
        libc::S_IFSOCK => "socket",
        libc::S_IFLNK => "symlink",
        _ => "other",
    };
    let is_device = matches!(file_type, "character_device" | "block_device");
    json!({
        "file_type": file_type,
        "mode": mode,
        "executable": mode & 0o111 != 0,
        "device_major": is_device.then_some(device_major),
        "device_minor": is_device.then_some(device_minor),
    })
}

fn snapshot_path_metadata(
    tid: i32,
    sys_nr: u64,
    args: [u64; 6],
    decoded: &Value,
    second_path: bool,
) -> Option<Value> {
    let path = decoded[if second_path { "path2" } else { "path" }].as_str()?;
    let dirfd = args[if second_path { 2 } else { 0 }] as libc::c_int;
    if path.is_empty() && dirfd != libc::AT_FDCWD {
        return Some(
            opened_file_metadata(tid, dirfd.into())
                .unwrap_or_else(|_| json!({"file_type": "unknown"})),
        );
    }
    let source = if Path::new(path).is_absolute() {
        Path::new(&format!("/proc/{tid}/root")).join(path.trim_start_matches('/'))
    } else {
        let base = if dirfd == libc::AT_FDCWD {
            format!("/proc/{tid}/cwd")
        } else {
            format!("/proc/{tid}/fd/{dirfd}")
        };
        Path::new(&base).join(path)
    };
    let nofollow = !path.is_empty()
        && (sys_nr == libc::SYS_readlinkat as u64
            || sys_nr == libc::SYS_unlinkat as u64
            || sys_nr == libc::SYS_renameat2 as u64
            || (sys_nr == libc::SYS_faccessat2 as u64
                && args[3] & libc::AT_SYMLINK_NOFOLLOW as u64 != 0));
    let snapshot = || -> io::Result<Value> {
        let file = fs_err::OpenOptions::new()
            .read(true)
            .custom_flags(
                libc::O_PATH | libc::O_CLOEXEC | if nofollow { libc::O_NOFOLLOW } else { 0 },
            )
            .open(source)?;
        let metadata = file.metadata()?;
        Ok(file_metadata(
            metadata.mode(),
            libc::major(metadata.rdev()),
            libc::minor(metadata.rdev()),
        ))
    };
    Some(snapshot().unwrap_or_else(|_| json!({"file_type": "unknown"})))
}

fn stat_file_metadata(tid: i32, sys_nr: u64, args: [u64; 6]) -> io::Result<Value> {
    let metadata = if sys_nr == libc::SYS_statx as u64 {
        let bytes = read_process_memory(tid, args[4], 0x88)?;
        parse_statx_metadata(&bytes)
    } else {
        let bytes = read_process_memory(tid, args[2], size_of::<libc::stat>())?;
        parse_stat_metadata(&bytes)
    };
    metadata.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unavailable file type in stat result",
        )
    })
}

fn parse_statx_metadata(bytes: &[u8]) -> Option<Value> {
    // Fixed Linux UAPI layout, including on musl:
    // https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/stat.h
    let mask = u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
    if mask & 1 == 0 {
        return None;
    }
    let mode = u16::from_ne_bytes(bytes.get(0x1c..0x1e)?.try_into().ok()?);
    let major = u32::from_ne_bytes(bytes.get(0x80..0x84)?.try_into().ok()?);
    let minor = u32::from_ne_bytes(bytes.get(0x84..0x88)?.try_into().ok()?);
    let mut snapshot = file_metadata(mode.into(), major, minor);
    if mask & 2 == 0 {
        snapshot["mode"] = Value::Null;
        snapshot["executable"] = Value::Null;
    }
    Some(snapshot)
}

fn parse_stat_metadata(bytes: &[u8]) -> Option<Value> {
    let mode_offset = std::mem::offset_of!(libc::stat, st_mode);
    let device_offset = std::mem::offset_of!(libc::stat, st_rdev);
    let mode = libc::mode_t::from_ne_bytes(
        bytes
            .get(mode_offset..mode_offset + size_of::<libc::mode_t>())?
            .try_into()
            .ok()?,
    );
    let device = libc::dev_t::from_ne_bytes(
        bytes
            .get(device_offset..device_offset + size_of::<libc::dev_t>())?
            .try_into()
            .ok()?,
    );
    Some(file_metadata(
        mode,
        libc::major(device),
        libc::minor(device),
    ))
}

// Converts policy-relevant pointer arguments into stable trace data. Keeping
// this decoding in the tracer lets the profile builder operate entirely on
// JSON without reading child memory.
fn decode_args(tid: i32, sys_nr: u64, args: [u64; 6]) -> Value {
    // Raw register arguments are always emitted. Decode only data needed for
    // filesystem and network policy generation; unreadable tracee memory is
    // represented by a null decoded value rather than aborting collection.
    if sys_nr == libc::SYS_renameat2 as u64 {
        let path = read_c_string(tid, args[1]).ok();
        let path2 = read_c_string(tid, args[3]).ok();
        return json!({
            "path_base": path_base(tid, args[0], path.as_deref()),
            "path2_base": path_base(tid, args[2], path2.as_deref()),
            "path_origin": path_origin(args[0], path.as_deref()),
            "path2_origin": path_origin(args[2], path2.as_deref()),
            "path": path,
            "path2": path2,
        });
    }

    let path_address = if sys_nr == libc::SYS_openat as u64
        || sys_nr == libc::SYS_newfstatat as u64
        || sys_nr == libc::SYS_statx as u64
        || sys_nr == libc::SYS_readlinkat as u64
        || sys_nr == libc::SYS_faccessat as u64
        || sys_nr == libc::SYS_faccessat2 as u64
        || sys_nr == libc::SYS_mkdirat as u64
        || sys_nr == libc::SYS_unlinkat as u64
    {
        Some(args[1])
    } else {
        None
    };

    if let Some(path) = path_address.and_then(|address| read_c_string(tid, address).ok()) {
        return json!({
            "path_base": path_base(tid, args[0], Some(&path)),
            "path_origin": path_origin(args[0], Some(&path)),
            "path_target": empty_path_target(tid, sys_nr, args, &path),
            "path": path,
        });
    }

    let socket_address = if sys_nr == libc::SYS_bind as u64 || sys_nr == libc::SYS_connect as u64 {
        Some((args[1], args[2]))
    } else if sys_nr == libc::SYS_sendto as u64 {
        Some((args[4], args[5]))
    } else {
        None
    };
    if let Some((address, length)) = socket_address {
        return decode_socket_address(tid, address, length).unwrap_or(Value::Null);
    }

    Value::Null
}

fn path_origin(dirfd: u64, path: Option<&str>) -> Option<&'static str> {
    let path = Path::new(path?);
    Some(if path.as_os_str().is_empty() {
        "empty"
    } else if path.is_absolute() {
        "absolute"
    } else if dirfd as libc::c_int == libc::AT_FDCWD {
        "cwd_relative"
    } else {
        "dirfd_relative"
    })
}

fn path_base(tid: i32, dirfd: u64, path: Option<&str>) -> Option<String> {
    let path = Path::new(path?);
    if path.is_absolute() || path.as_os_str().is_empty() {
        return None;
    }

    let base = fd_target(tid, dirfd)?;
    if !Path::new(&base).is_absolute() || base.ends_with(" (deleted)") {
        return None;
    }
    Some(base)
}

fn empty_path_target(tid: i32, sys_nr: u64, args: [u64; 6], path: &str) -> Option<String> {
    if !path.is_empty() {
        return None;
    }
    let uses_descriptor =
        if sys_nr == libc::SYS_newfstatat as u64 || sys_nr == libc::SYS_faccessat2 as u64 {
            args[3] & libc::AT_EMPTY_PATH as u64 != 0
        } else if sys_nr == libc::SYS_statx as u64 {
            args[2] & libc::AT_EMPTY_PATH as u64 != 0
        } else {
            sys_nr == libc::SYS_readlinkat as u64
        };
    uses_descriptor.then(|| fd_target(tid, args[0])).flatten()
}

fn fd_target(tid: i32, dirfd: u64) -> Option<String> {
    // dirfd is an int, even when the syscall register contains a sign-extended value.
    let dirfd = dirfd as libc::c_int;
    let link = if dirfd == libc::AT_FDCWD {
        format!("/proc/{tid}/cwd")
    } else {
        format!("/proc/{tid}/fd/{dirfd}")
    };
    fs_err::read_link(link)
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

fn decode_socket_address(tid: i32, address: u64, length: u64) -> io::Result<Value> {
    // The length originates in the tracee. sockaddr_storage bounds the read
    // while still covering every socket address representation decoded here.
    let length = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(size_of::<libc::sockaddr_storage>());
    let bytes = read_process_memory(tid, address, length)?;
    parse_socket_address(&bytes)
        .map(|(family, address, port)| {
            json!({
                "socket_address": {
                    "family": family,
                    "address": address,
                    "port": port,
                }
            })
        })
        .ok_or_else(|| io::Error::other("unsupported or truncated socket address"))
}

fn parse_socket_address(bytes: &[u8]) -> Option<(&'static str, String, u16)> {
    let family = u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?);
    if family == libc::AF_INET as u16 {
        let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
        let address = Ipv4Addr::new(
            *bytes.get(4)?,
            *bytes.get(5)?,
            *bytes.get(6)?,
            *bytes.get(7)?,
        );
        Some(("AF_INET", address.to_string(), port))
    } else if family == libc::AF_INET6 as u16 {
        let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
        let address = Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(8..24)?).ok()?);
        Some(("AF_INET6", address.to_string(), port))
    } else {
        None
    }
}

fn read_c_string(tid: i32, address: u64) -> io::Result<String> {
    // Trace inputs are not trusted to contain a terminator. Bound the snapshot
    // so malformed pointers cannot cause an unbounded allocation or read.
    let mut bytes = read_process_memory(tid, address, MAX_STRING_LEN)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    bytes.truncate(end);
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// Copies argument data from a stopped tracee without changing its registers or
// injecting operations into the child.
fn read_process_memory(tid: i32, address: u64, length: usize) -> io::Result<Vec<u8>> {
    if address == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "null address"));
    }
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero-length read",
        ));
    }

    let mut bytes = vec![0u8; length];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut c_void,
        iov_len: bytes.len(),
    };
    // The tracee is stopped, so this captures a stable snapshot without
    // injecting helper code or changing the child's address space.
    // SAFETY: local describes the writable byte buffer, and remote is interpreted
    // by the kernel in the tracee's address space.
    let count = syscall_result(unsafe { libc::process_vm_readv(tid, &local, 1, &remote, 1, 0) })?;
    bytes.truncate(count as usize);
    Ok(bytes)
}

fn trace_options() -> libc::c_long {
    // Follow all process/thread creation so activity cannot escape the child
    // trace, and terminate tracees if the tracer itself unexpectedly exits.
    (libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        | libc::PTRACE_O_TRACESECCOMP
        | libc::PTRACE_O_EXITKILL) as libc::c_long
}

fn resume_task(tid: i32, awaiting_syscall_exit: bool, signal: i32) -> io::Result<()> {
    // PTRACE_SYSCALL is used only long enough to collect the return value for a
    // selected syscall; otherwise the task runs until its next real event.
    if awaiting_syscall_exit {
        resume_syscall(tid, signal)
    } else {
        resume_cont(tid, signal)
    }
}

fn resume_cont(tid: i32, signal: i32) -> io::Result<()> {
    resume_ptrace(libc::PTRACE_CONT as _, tid, signal)
}

fn resume_syscall(tid: i32, signal: i32) -> io::Result<()> {
    resume_ptrace(libc::PTRACE_SYSCALL as _, tid, signal)
}

fn resume_ptrace(request: libc::c_uint, tid: i32, signal: i32) -> io::Result<()> {
    // A task may exit between waitpid reporting its stop and this resume.
    // Treat that race as normal completion; all other ptrace errors are fatal.
    match ptrace(request, tid, 0, signal as usize) {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        result => result,
    }
}

fn ptrace(request: libc::c_uint, pid: i32, address: usize, data: usize) -> io::Result<()> {
    // GNU takes c_uint requests, musl takes c_int. All requests used here fit
    // both types; normalize to c_uint internally and cast at the libc boundary.
    // SAFETY: each caller supplies the address and data layout required by the
    // specific ptrace request; kernel errors are returned through errno.
    let result = unsafe {
        libc::ptrace(
            request as _,
            pid,
            address as *mut c_void,
            data as *mut c_void,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn syscall_result<T>(result: T) -> io::Result<T>
where
    T: Copy + PartialOrd + From<i8>,
{
    if result < T::from(0) {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn write_event(output: &mut BufWriter<File>, event: Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, &event)?;
    output.write_all(b"\n")
}

fn unix_timestamp_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::mem::align_of;
    use std::mem::offset_of;
    use std::os::fd::AsFd;
    use std::os::fd::AsRawFd;
    use std::os::fd::BorrowedFd;
    use std::os::unix::fs::PermissionsExt;
    use test_with_tracing::test;

    #[test]
    fn ptrace_syscall_info_matches_linux_abi() {
        assert_eq!(size_of::<PtraceSyscallInfo>(), 88);
        assert_eq!(align_of::<PtraceSyscallInfo>(), 8);
        assert_eq!(offset_of!(PtraceSyscallInfo, op), 0);
        assert_eq!(offset_of!(PtraceSyscallInfo, arch), 4);
        assert_eq!(offset_of!(PtraceSyscallInfo, instruction_pointer), 8);
        assert_eq!(offset_of!(PtraceSyscallInfo, stack_pointer), 16);
        assert_eq!(offset_of!(PtraceSyscallInfo, u), 24);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.entry.nr), 24);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.entry.args), 32);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.exit.sval), 24);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.exit.is_error), 32);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.seccomp.nr), 24);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.seccomp.args), 32);
        assert_eq!(offset_of!(PtraceSyscallInfo, u.seccomp.ret_data), 80);
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn ptrace_syscall_info_matches_libc() {
        assert_eq!(PTRACE_GET_SYSCALL_INFO, libc::PTRACE_GET_SYSCALL_INFO);
        assert_eq!(PTRACE_SYSCALL_INFO_EXIT, libc::PTRACE_SYSCALL_INFO_EXIT);
        assert_eq!(
            PTRACE_SYSCALL_INFO_SECCOMP,
            libc::PTRACE_SYSCALL_INFO_SECCOMP
        );
        assert_eq!(
            size_of::<PtraceSyscallInfo>(),
            size_of::<libc::ptrace_syscall_info>()
        );
        assert_eq!(
            align_of::<PtraceSyscallInfo>(),
            align_of::<libc::ptrace_syscall_info>()
        );

        macro_rules! assert_field_offset {
            ($($field:ident).+) => {
                assert_eq!(
                    offset_of!(PtraceSyscallInfo, $($field).+),
                    offset_of!(libc::ptrace_syscall_info, $($field).+),
                    stringify!($($field).+),
                );
            };
        }

        assert_field_offset!(op);
        assert_field_offset!(arch);
        assert_field_offset!(instruction_pointer);
        assert_field_offset!(stack_pointer);
        assert_field_offset!(u);
        assert_field_offset!(u.entry.nr);
        assert_field_offset!(u.entry.args);
        assert_field_offset!(u.exit.sval);
        assert_field_offset!(u.exit.is_error);
        assert_field_offset!(u.seccomp.nr);
        assert_field_offset!(u.seccomp.args);
        assert_field_offset!(u.seccomp.ret_data);
    }

    #[test]
    fn process_names_are_safe_for_file_names() {
        assert_eq!(sanitize_name("vm"), "vm");
        assert_eq!(sanitize_name("worker/name"), "worker_name");
    }

    #[test]
    fn parses_ipv4_socket_address() {
        let mut bytes = [0u8; 8];
        bytes[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&8080u16.to_be_bytes());
        bytes[4..].copy_from_slice(&[127, 0, 0, 1]);

        assert_eq!(
            parse_socket_address(&bytes),
            Some(("AF_INET", "127.0.0.1".to_string(), 8080))
        );
    }

    #[test]
    fn parses_ipv6_socket_address() {
        let mut bytes = [0u8; 24];
        bytes[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&443u16.to_be_bytes());
        bytes[23] = 1;

        assert_eq!(
            parse_socket_address(&bytes),
            Some(("AF_INET6", "::1".to_string(), 443))
        );
    }

    #[test]
    fn decodes_relative_path_bases() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        let tid = std::process::id() as i32;
        let cwd = std::env::current_dir().unwrap();
        let directory_path = fs_err::canonicalize(dir.path()).unwrap();
        let path = c"glibc-hwcaps/x86-64-v2/libgcc_s.so.1";

        for (dirfd, expected) in [
            (libc::AT_FDCWD as u32 as u64, &cwd),
            (libc::AT_FDCWD as i64 as u64, &cwd),
            (directory.as_raw_fd() as u64, &directory_path),
        ] {
            let decoded = decode_args(
                tid,
                libc::SYS_openat as u64,
                [dirfd, path.as_ptr() as u64, 0, 0, 0, 0],
            );
            assert_eq!(decoded["path"], path.to_str().unwrap());
            assert_eq!(decoded["path_base"], expected.to_str().unwrap());
            assert_eq!(
                decoded["path_origin"],
                if dirfd as libc::c_int == libc::AT_FDCWD {
                    "cwd_relative"
                } else {
                    "dirfd_relative"
                }
            );
        }

        for (dirfd, path) in [
            (directory.as_raw_fd() as u64, c"/absolute/library.so"),
            (directory.as_raw_fd() as u64, c""),
            (u32::MAX as u64, c"relative"),
        ] {
            let decoded = decode_args(
                tid,
                libc::SYS_openat as u64,
                [dirfd, path.as_ptr() as u64, 0, 0, 0, 0],
            );
            assert_eq!(decoded["path"], path.to_str().unwrap());
            assert!(decoded["path_base"].is_null());
        }
    }

    #[test]
    fn decodes_both_rename_path_bases() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let source_fd = File::open(source.path()).unwrap();
        let destination_fd = File::open(destination.path()).unwrap();
        let decoded = decode_args(
            std::process::id() as i32,
            libc::SYS_renameat2 as u64,
            [
                source_fd.as_raw_fd() as u64,
                c"old".as_ptr() as u64,
                destination_fd.as_raw_fd() as u64,
                c"new".as_ptr() as u64,
                0,
                0,
            ],
        );
        assert_eq!(decoded["path"], "old");
        assert_eq!(decoded["path2"], "new");
        assert_eq!(decoded["path_origin"], "dirfd_relative");
        assert_eq!(decoded["path2_origin"], "dirfd_relative");
        assert_eq!(
            decoded["path_base"],
            fs_err::canonicalize(source.path())
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            decoded["path2_base"],
            fs_err::canonicalize(destination.path())
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn decodes_empty_path_descriptor_targets() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        let tid = std::process::id() as i32;
        let file_path = fs_err::canonicalize(file.path()).unwrap();
        let directory_path = fs_err::canonicalize(dir.path()).unwrap();
        let cwd = std::env::current_dir().unwrap();

        for (dirfd, expected) in [
            (file.as_raw_fd() as u64, &file_path),
            (directory.as_raw_fd() as u64, &directory_path),
            (libc::AT_FDCWD as u32 as u64, &cwd),
            (libc::AT_FDCWD as i64 as u64, &cwd),
        ] {
            for (sys_nr, flags_index) in [
                (libc::SYS_newfstatat, Some(3)),
                (libc::SYS_statx, Some(2)),
                (libc::SYS_faccessat2, Some(3)),
                (libc::SYS_readlinkat, None),
            ] {
                let mut args = [dirfd, c"".as_ptr() as u64, 0, 0, 0, 0];
                if let Some(index) = flags_index {
                    args[index] = libc::AT_EMPTY_PATH as u64;
                }
                let decoded = decode_args(tid, sys_nr as u64, args);
                assert_eq!(decoded["path"], "");
                assert!(decoded["path_base"].is_null());
                assert_eq!(decoded["path_target"], expected.to_str().unwrap());
            }
        }
    }

    #[test]
    fn empty_path_targets_require_descriptor_semantics() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let tid = std::process::id() as i32;
        let dirfd = file.as_raw_fd() as u64;
        for sys_nr in [
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_faccessat2,
            libc::SYS_openat,
        ] {
            let decoded = decode_args(tid, sys_nr as u64, [dirfd, c"".as_ptr() as u64, 0, 0, 0, 0]);
            assert_eq!(decoded["path"], "");
            assert!(decoded["path_target"].is_null());
        }
        for (sys_nr, dirfd, path) in [
            (libc::SYS_faccessat, dirfd, c""),
            (libc::SYS_newfstatat, u32::MAX as u64, c""),
            (libc::SYS_newfstatat, dirfd, c"relative"),
        ] {
            let decoded = decode_args(
                tid,
                sys_nr as u64,
                [
                    dirfd,
                    path.as_ptr() as u64,
                    0,
                    libc::AT_EMPTY_PATH as u64,
                    0,
                    0,
                ],
            );
            assert_eq!(decoded["path"], path.to_str().unwrap());
            assert!(decoded["path_target"].is_null());
        }
    }

    #[test]
    fn retains_non_path_and_deleted_descriptor_targets() {
        let tid = std::process::id() as i32;
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deleted");
        let file = File::create(&path).unwrap();
        let file_path = fs_err::canonicalize(&path).unwrap();
        fs_err::remove_file(&path).unwrap();
        for (dirfd, expected) in [
            (
                socket.as_raw_fd() as u64,
                fs_err::read_link(format!("/proc/{tid}/fd/{}", socket.as_raw_fd()))
                    .unwrap()
                    .into_os_string()
                    .into_string()
                    .unwrap(),
            ),
            (
                file.as_raw_fd() as u64,
                format!("{} (deleted)", file_path.display()),
            ),
        ] {
            let decoded = decode_args(
                tid,
                libc::SYS_newfstatat as u64,
                [
                    dirfd,
                    c"".as_ptr() as u64,
                    0,
                    libc::AT_EMPTY_PATH as u64,
                    0,
                    0,
                ],
            );
            assert_eq!(decoded["path"], "");
            assert_eq!(decoded["path_target"], expected);
            assert!(decoded["path_base"].is_null());
        }
    }

    #[test]
    fn snapshots_opened_objects_through_descriptors() {
        let dir = tempfile::tempdir().unwrap();
        let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let directory = File::open(dir.path()).unwrap();
        let alias = dir.path().join("device-alias");
        std::os::unix::fs::symlink("/dev/null", &alias).unwrap();
        let device = fs_err::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&alias)
            .unwrap();
        let tid = std::process::id() as i32;

        for (fd, expected_type, expected_path) in [
            (file.as_raw_fd(), "regular_file", file.path()),
            (directory.as_raw_fd(), "directory", dir.path()),
            (
                device.as_raw_fd(),
                "character_device",
                Path::new("/dev/null"),
            ),
        ] {
            let snapshot = opened_file_metadata(tid, fd as i64).unwrap();
            assert_eq!(snapshot["file_type"], expected_type);
            let mode = fs_err::metadata(expected_path).unwrap().mode();
            assert_eq!(snapshot["mode"], mode);
            assert_eq!(snapshot["executable"], mode & 0o111 != 0);
            assert_eq!(
                snapshot["path"],
                fs_err::canonicalize(expected_path)
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
            if expected_type == "character_device" {
                let metadata = device.metadata().unwrap();
                assert_eq!(snapshot["device_major"], libc::major(metadata.rdev()));
                assert_eq!(snapshot["device_minor"], libc::minor(metadata.rdev()));
            } else {
                assert!(snapshot["device_major"].is_null());
                assert!(snapshot["device_minor"].is_null());
            }
        }

        for mode in [0o644, 0o100, 0o010, 0o001] {
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(mode))
                .unwrap();
            let snapshot = opened_file_metadata(tid, file.as_raw_fd() as i64).unwrap();
            assert_eq!(snapshot["mode"], libc::S_IFREG | mode);
            assert_eq!(snapshot["executable"], mode & 0o111 != 0);
        }
        let original = fs_err::canonicalize(file.path()).unwrap();
        fs_err::remove_file(file.path()).unwrap();
        let snapshot = opened_file_metadata(tid, file.as_raw_fd() as i64).unwrap();
        assert_eq!(snapshot["file_type"], "regular_file");
        assert_eq!(
            snapshot["path"],
            format!("{} (deleted)", original.display())
        );
        assert!(opened_file_metadata(tid, -1).is_err());
        assert!(opened_file_metadata(tid, i64::MAX).is_err());
    }

    #[test]
    fn decodes_stat_result_types_and_device_numbers() {
        for (kind, expected) in [
            (libc::S_IFCHR, "character_device"),
            (libc::S_IFBLK, "block_device"),
            (libc::S_IFREG, "regular_file"),
            (libc::S_IFDIR, "directory"),
            (libc::S_IFLNK, "symlink"),
        ] {
            let mode = kind | 0o751;
            let mut statx = vec![0u8; 0x88];
            statx[..4].copy_from_slice(&3u32.to_ne_bytes());
            statx[0x1c..0x1e].copy_from_slice(&(mode as u16).to_ne_bytes());
            statx[0x80..0x84].copy_from_slice(&1u32.to_ne_bytes());
            statx[0x84..0x88].copy_from_slice(&3u32.to_ne_bytes());
            let mut stat = vec![0u8; size_of::<libc::stat>()];
            let mode_offset = std::mem::offset_of!(libc::stat, st_mode);
            let device_offset = std::mem::offset_of!(libc::stat, st_rdev);
            stat[mode_offset..mode_offset + size_of::<libc::mode_t>()]
                .copy_from_slice(&mode.to_ne_bytes());
            stat[device_offset..device_offset + size_of::<libc::dev_t>()]
                .copy_from_slice(&libc::makedev(1, 3).to_ne_bytes());
            for snapshot in [
                parse_statx_metadata(&statx).unwrap(),
                parse_stat_metadata(&stat).unwrap(),
            ] {
                assert_eq!(snapshot["file_type"], expected);
                assert_eq!(snapshot["mode"], mode);
                assert_eq!(snapshot["executable"], true);
                if matches!(kind, libc::S_IFCHR | libc::S_IFBLK) {
                    assert_eq!(snapshot["device_major"], 1);
                    assert_eq!(snapshot["device_minor"], 3);
                } else {
                    assert!(snapshot["device_major"].is_null());
                    assert!(snapshot["device_minor"].is_null());
                }
            }
            for length in 0..statx.len() {
                assert!(parse_statx_metadata(&statx[..length]).is_none());
            }
            statx[..4].copy_from_slice(&1u32.to_ne_bytes());
            let snapshot = parse_statx_metadata(&statx).unwrap();
            assert_eq!(snapshot["file_type"], expected);
            assert!(snapshot["mode"].is_null());
            assert!(snapshot["executable"].is_null());
            statx[..4].fill(0);
            assert!(parse_statx_metadata(&statx).is_none());
            assert!(parse_stat_metadata(&[]).is_none());
        }
    }

    #[test]
    fn snapshots_path_modes_with_lookup_and_symlink_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(file.path(), &alias).unwrap();
        let directory = File::open(dir.path()).unwrap();
        let tid = std::process::id() as i32;
        for (sys_nr, flags, expected_type) in [
            (libc::SYS_faccessat, 0, "regular_file"),
            (libc::SYS_faccessat2, 0, "regular_file"),
            (libc::SYS_faccessat2, libc::AT_SYMLINK_NOFOLLOW, "symlink"),
            (libc::SYS_readlinkat, 0, "symlink"),
            (libc::SYS_unlinkat, 0, "symlink"),
            (libc::SYS_renameat2, 0, "symlink"),
        ] {
            for (dirfd, path) in [
                (libc::AT_FDCWD, alias.to_str().unwrap()),
                (directory.as_raw_fd(), "alias"),
            ] {
                let metadata = snapshot_path_metadata(
                    tid,
                    sys_nr as u64,
                    [dirfd as u64, 0, 0, flags as u64, 0, 0],
                    &json!({"path": path}),
                    false,
                )
                .unwrap();
                assert_eq!(metadata["file_type"], expected_type);
                assert_eq!(
                    metadata["mode"],
                    if expected_type == "symlink" {
                        fs_err::symlink_metadata(&alias).unwrap().mode()
                    } else {
                        libc::S_IFREG | 0o640
                    }
                );
            }
        }
        let metadata = snapshot_path_metadata(
            tid,
            libc::SYS_renameat2 as u64,
            [0, 0, directory.as_raw_fd() as u64, 0, 0, 0],
            &json!({"path2": file.path().file_name().unwrap().to_str().unwrap()}),
            true,
        )
        .unwrap();
        assert_eq!(metadata["mode"], libc::S_IFREG | 0o640);
    }

    #[test]
    fn traces_device_metadata_queries() {
        for (program, args) in [
            ("/usr/bin/stat", vec!["--format=%F", "/dev/null"]),
            ("/bin/sh", vec!["-c", "test -c /dev/null"]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let config = TraceConfig::new(
                dir.path().to_path_buf(),
                "worker",
                BTreeMap::from([
                    (libc::SYS_statx, "statx".to_string()),
                    (libc::SYS_newfstatat, "newfstatat".to_string()),
                ]),
            );
            let mut command = pal::unix::process::Builder::new(program);
            command.args(args);
            command.set_trace_seccomp_filter(build_seccomp_filter(&config).unwrap());
            let child = command.spawn().unwrap();
            let pid = child.id();
            let mut traced = TracedChild::start(child, "metadata", config).unwrap();
            assert!(
                futures::executor::block_on(traced.wait())
                    .unwrap()
                    .success()
            );
            let contents =
                fs_err::read_to_string(dir.path().join(format!("worker-metadata.{pid}.jsonl")))
                    .unwrap();
            let events = contents
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert!(
                events.iter().any(|event| {
                    event["decoded_args"]["path"] == "/dev/null"
                        && event["result"] == 0
                        && event["path_metadata"]["file_type"] == "character_device"
                        && event["path_metadata"]["device_major"] == 1
                        && event["path_metadata"]["device_minor"] == 3
                        && event["path_metadata"]["mode"]
                            == fs_err::metadata("/dev/null").unwrap().mode()
                        && event["opened_file"].is_null()
                }),
                "{program}: {events:?}"
            );
        }
    }

    #[test]
    fn traces_process_to_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let data = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        data.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let config = TraceConfig::new(
            dir.path().to_path_buf(),
            "worker",
            BTreeMap::from([(libc::SYS_openat, "openat".to_string())]),
        );
        let mut command = pal::unix::process::Builder::new("/usr/bin/cat");
        command.args(["/dev/null", data.path().to_str().unwrap()]);
        command.set_trace_seccomp_filter(build_seccomp_filter(&config).unwrap());
        let child = command.spawn().unwrap();
        let pid = child.id();
        let mut traced = TracedChild::start(child, "test-worker", config).unwrap();

        let status = futures::executor::block_on(traced.wait()).unwrap();
        assert!(status.success());

        let file = File::open(dir.path().join(format!("worker-test-worker.{pid}.jsonl"))).unwrap();
        let events = io::BufReader::new(file)
            .lines()
            .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["decoded_args"]["path"] == data.path().to_str().unwrap()
                && event["result"].as_i64().is_some_and(|fd| fd >= 0)
                && event["opened_file"]["mode"] == libc::S_IFREG | 0o640
                && event["opened_file"]["executable"] == false
        }));
        assert!(
            events
                .iter()
                .all(|event| event.get("version").is_none() && event.get("worker").is_none())
        );
        assert!(events.iter().any(|event| event["event"] == "trace_started"));
        assert!(events.iter().any(|event| {
            event["event"] == "syscall"
                && event["sys_nr"].is_number()
                && event.get("decoded_args").is_some()
                && event.get("number").is_none()
                && event.get("details").is_none()
        }));
        assert!(
            events
                .iter()
                .filter(|event| event["event"] == "syscall")
                .all(|event| {
                    let sys_nr = event["sys_nr"].as_u64().unwrap();
                    sys_nr == libc::SYS_openat as u64 && event["syscall"] == "openat"
                })
        );
        assert!(events.iter().any(|event| event["event"] == "task_exit"));
        assert!(events.iter().any(|event| {
            event["event"] == "syscall"
                && event["decoded_args"]["path"] == "/dev/null"
                && event["opened_file"]["file_type"] == "character_device"
                && event["opened_file"]["path"] == "/dev/null"
                && event["result"].as_i64().is_some_and(|result| result >= 0)
        }));
        assert!(
            events
                .iter()
                .filter(|event| {
                    event["event"] == "syscall"
                        && event["result"].as_i64().is_some_and(|result| result < 0)
                })
                .all(|event| event["opened_file"].is_null())
        );
    }

    #[test]
    fn initialization_failure_reaps_worker() {
        for fail_file_creation in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let output_dir = if fail_file_creation {
                dir.path().to_path_buf()
            } else {
                let path = dir.path().join("output");
                File::create(&path).unwrap();
                path
            };

            let config = TraceConfig::new(
                output_dir,
                "worker",
                BTreeMap::from([(libc::SYS_openat, "openat".to_string())]),
            );

            let mut command = pal::unix::process::Builder::new("/usr/bin/true");
            command.set_trace_seccomp_filter(build_seccomp_filter(&config).unwrap());
            let child = command.spawn().unwrap();
            let child_pid = child.id();
            let pidfd = child.as_fd().try_clone_to_owned().unwrap();

            if fail_file_creation {
                fs_err::create_dir(
                    dir.path()
                        .join(format!("worker-test-worker.{child_pid}.jsonl")),
                )
                .unwrap();
            }

            let mut traced = TracedChild::start(child, "test-worker", config).unwrap();
            let result = futures::executor::block_on(traced.wait());

            assert_worker_reaped(child_pid, pidfd.as_fd());

            let error = result.unwrap_err();
            assert_eq!(
                error.kind(),
                if fail_file_creation {
                    io::ErrorKind::IsADirectory
                } else {
                    io::ErrorKind::AlreadyExists
                }
            );
        }
    }

    #[test]
    fn cleanup_before_tracer_start_reaps_worker() {
        let dir = tempfile::tempdir().unwrap();
        let config = TraceConfig::new(dir.path().to_path_buf(), "worker", BTreeMap::new());

        let mut command = pal::unix::process::Builder::new("/usr/bin/true");
        command.set_trace_seccomp_filter(build_seccomp_filter(&config).unwrap());
        let child = command.spawn().unwrap();
        let child_pid = child.id();

        reap_child_on_trace_failure(child_pid, false).unwrap();

        assert_worker_reaped(child_pid, child.as_fd());
    }

    fn assert_worker_reaped(child_pid: i32, pidfd: BorrowedFd<'_>) {
        let mut status = 0;
        // SAFETY: status is writable.
        let result =
            syscall_result(unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) });

        if matches!(&result, Ok(0)) {
            // Clean up before failing the assertion, using the original worker's pidfd.
            // SAFETY: pidfd identifies this test's worker.
            syscall_result(unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            })
            .unwrap();

            loop {
                // SAFETY: status is writable.
                match syscall_result(unsafe { libc::waitpid(child_pid, &mut status, 0) }) {
                    Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
                    _ => break,
                }
            }
        }

        assert!(
            matches!(result, Err(error) if error.raw_os_error() == Some(libc::ECHILD)),
            "worker {child_pid} was not reaped"
        );
    }

    #[test]
    fn delivers_sigtrap_to_handler() {
        let status = trace_shell("trap 'exit 42' TRAP; kill -TRAP $$; exit 0");
        assert_eq!(status.code(), Some(42), "{status}");
    }

    #[test]
    fn preserves_unhandled_sigtrap() {
        let status = trace_shell("ulimit -c 0; trap - TRAP; kill -TRAP $$; exit 0");
        assert_eq!(status.signal(), Some(libc::SIGTRAP), "{status}");
    }

    fn trace_shell(script: &str) -> ExitStatus {
        let dir = tempfile::tempdir().unwrap();
        let config = TraceConfig::new(
            dir.path().to_path_buf(),
            "worker",
            BTreeMap::from([(libc::SYS_openat, "openat".to_string())]),
        );
        let mut command = pal::unix::process::Builder::new("/bin/sh");
        command
            .args(["-c", script])
            .set_trace_seccomp_filter(build_seccomp_filter(&config).unwrap());
        let child = command.spawn().unwrap();
        let mut traced = TracedChild::start(child, "test-worker", config).unwrap();
        futures::executor::block_on(traced.wait()).unwrap()
    }
}
