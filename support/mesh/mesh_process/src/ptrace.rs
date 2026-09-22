// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Linux ptrace collection for Mesh worker processes.

// UNSAFETY: ptrace, waitpid, kill, and process_vm_readv are Linux process APIs.
#![expect(unsafe_code)]

use crate::ProcessTraceConfig;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

const MAX_STRING_LEN: usize = 16 * 1024;
const TRACE_BUFFER_CAPACITY: usize = 256 * 1024;

pub struct TracedChild {
    completion: Option<mesh::OneshotReceiver<io::Result<ExitStatus>>>,
}

impl TracedChild {
    pub fn start(
        child: pal::unix::process::Child,
        worker_name: &str,
        config: ProcessTraceConfig,
    ) -> io::Result<Self> {
        let pid = child.id();
        let worker_name = worker_name.to_owned();
        let (send, recv) = mesh::oneshot();
        std::thread::Builder::new()
            .name(format!("ptrace-{worker_name}-{pid}"))
            .spawn(move || {
                let result = trace_worker(child, &worker_name, &config);
                send.send(result);
            })?;
        Ok(Self {
            completion: Some(recv),
        })
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.completion
            .take()
            .expect("traced child waited more than once")
            .await
            .map_err(|_| io::Error::other("worker tracer exited without reporting status"))?
    }
}

struct PendingSyscall {
    sys_nr: u64,
    args: [u64; 6],
    started: Instant,
    decoded_args: Value,
}

fn trace_worker(
    child: pal::unix::process::Child,
    worker_name: &str,
    config: &ProcessTraceConfig,
) -> io::Result<ExitStatus> {
    let root_pid = child.id();
    fs_err::create_dir_all(&config.output_dir)?;
    let trace_path = config.output_dir.join(format!(
        "worker-{}.{root_pid}.jsonl",
        sanitize_name(worker_name)
    ));
    // Batch writes so a slow output filesystem cannot stall a traced task at
    // every syscall stop. The buffer is flushed when it fills and at exit.
    let mut output = BufWriter::with_capacity(TRACE_BUFFER_CAPACITY, File::create(&trace_path)?);

    wait_for_initial_stop(root_pid)?;
    ptrace(libc::PTRACE_SEIZE, root_pid, 0, trace_options() as usize)?;
    // Release the pre-exec group stop. PTRACE_O_TRACEEXEC guarantees another
    // stop before the worker's new image executes user code.
    // SAFETY: kill accepts any PID and signal value; errors are reported via errno.
    syscall_result(unsafe { libc::kill(root_pid, libc::SIGCONT) })?;

    write_event(
        &mut output,
        json!({
            "event": "trace_started",
            "pid": root_pid,
            "trace_file": trace_path,
        }),
    )?;

    let mut tasks = HashMap::<i32, Option<PendingSyscall>>::new();
    tasks.insert(root_pid, None);

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
                    "pid": root_pid,
                    "tid": tid,
                    "exit_code": libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
                    "signal": libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)),
                }),
            )?;
            tasks.remove(&tid);
            if tid == root_pid {
                output.flush()?;
                drop(child);
                return Ok(ExitStatus::from_raw(status));
            }
            continue;
        }

        if !libc::WIFSTOPPED(status) {
            continue;
        }

        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        if signal == (libc::SIGTRAP | 0x80) {
            handle_syscall_stop(&mut output, root_pid, tid, tasks.entry(tid).or_default())?;
            resume_syscall(tid, 0)?;
        } else if signal == libc::SIGTRAP && event != 0 {
            handle_ptrace_event(&mut output, root_pid, tid, event, &mut tasks)?;
            resume_syscall(tid, 0)?;
        } else {
            let deliver = if signal == libc::SIGSTOP || signal == libc::SIGTRAP {
                0
            } else {
                signal
            };
            resume_syscall(tid, deliver)?;
        }
    }
}

fn wait_for_initial_stop(pid: i32) -> io::Result<()> {
    let mut status = 0;
    // SAFETY: status points to writable memory, and WUNTRACED is a valid waitpid flag.
    syscall_result(unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) })?;
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        return Err(io::Error::other(format!(
            "worker {pid} did not stop before exec: status {status:#x}"
        )));
    }
    Ok(())
}

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
            libc::PTRACE_GETEVENTMSG,
            tid,
            0,
            std::ptr::from_mut(&mut message) as usize,
        )?;
        let child_tid = i32::try_from(message)
            .map_err(|_| io::Error::other("ptrace returned an invalid child tid"))?;
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

fn handle_syscall_stop(
    output: &mut BufWriter<File>,
    root_pid: i32,
    tid: i32,
    pending: &mut Option<PendingSyscall>,
) -> io::Result<()> {
    let mut info = MaybeUninit::<libc::ptrace_syscall_info>::zeroed();
    let size = size_of::<libc::ptrace_syscall_info>();
    ptrace(
        libc::PTRACE_GET_SYSCALL_INFO,
        tid,
        size,
        info.as_mut_ptr() as usize,
    )?;
    // SAFETY: the kernel initialized the structure after a successful ptrace.
    let info = unsafe { info.assume_init() };

    match info.op {
        libc::PTRACE_SYSCALL_INFO_ENTRY => {
            // SAFETY: op identifies the active union member.
            let entry = unsafe { info.u.entry };
            let sys_nr = entry.nr;
            *pending = Some(PendingSyscall {
                sys_nr,
                args: entry.args,
                started: Instant::now(),
                decoded_args: decode_args(tid, sys_nr, entry.args),
            });
        }
        libc::PTRACE_SYSCALL_INFO_EXIT => {
            // SAFETY: op identifies the active union member.
            let exit = unsafe { info.u.exit };
            let Some(entry) = pending.take() else {
                return Ok(());
            };
            write_event(
                output,
                json!({
                    "event": "syscall",
                    "timestamp_ns": unix_timestamp_ns(),
                    "pid": root_pid,
                    "tid": tid,
                    "syscall": syscall_name(entry.sys_nr),
                    "sys_nr": entry.sys_nr,
                    "args": entry.args,
                    "decoded_args": entry.decoded_args,
                    "result": exit.sval,
                    "errno": (exit.is_error != 0).then(|| -exit.sval),
                    "duration_ns": entry.started.elapsed().as_nanos(),
                }),
            )?;
        }
        _ => {}
    }
    Ok(())
}

fn decode_args(tid: i32, sys_nr: u64, args: [u64; 6]) -> Value {
    let path_address = if sys_nr == libc::SYS_openat as u64
        || sys_nr == libc::SYS_newfstatat as u64
        || sys_nr == libc::SYS_readlinkat as u64
        || sys_nr == libc::SYS_faccessat as u64
        || sys_nr == libc::SYS_faccessat2 as u64
        || sys_nr == libc::SYS_mkdirat as u64
        || sys_nr == libc::SYS_unlinkat as u64
    {
        Some(args[1])
    } else if sys_nr == libc::SYS_execve as u64 {
        Some(args[0])
    } else {
        None
    };

    match path_address.and_then(|address| read_c_string(tid, address).ok()) {
        Some(path) => json!({ "path": path }),
        None => Value::Null,
    }
}

fn read_c_string(tid: i32, address: u64) -> io::Result<String> {
    if address == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "null address"));
    }

    let mut bytes = vec![0u8; MAX_STRING_LEN];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: local describes the writable byte buffer, and remote is interpreted
    // by the kernel in the tracee's address space.
    let count = syscall_result(unsafe { libc::process_vm_readv(tid, &local, 1, &remote, 1, 0) })?;
    bytes.truncate(count as usize);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    bytes.truncate(end);
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn syscall_name(sys_nr: u64) -> &'static str {
    match sys_nr as i64 {
        libc::SYS_read => "read",
        libc::SYS_write => "write",
        libc::SYS_close => "close",
        libc::SYS_openat => "openat",
        libc::SYS_newfstatat => "newfstatat",
        libc::SYS_statx => "statx",
        libc::SYS_readlinkat => "readlinkat",
        libc::SYS_faccessat => "faccessat",
        libc::SYS_faccessat2 => "faccessat2",
        libc::SYS_mkdirat => "mkdirat",
        libc::SYS_unlinkat => "unlinkat",
        libc::SYS_renameat2 => "renameat2",
        libc::SYS_dup => "dup",
        libc::SYS_dup3 => "dup3",
        libc::SYS_fcntl => "fcntl",
        libc::SYS_socket => "socket",
        libc::SYS_socketpair => "socketpair",
        libc::SYS_bind => "bind",
        libc::SYS_connect => "connect",
        libc::SYS_listen => "listen",
        libc::SYS_accept4 => "accept4",
        libc::SYS_sendmsg => "sendmsg",
        libc::SYS_recvmsg => "recvmsg",
        libc::SYS_mmap => "mmap",
        libc::SYS_mprotect => "mprotect",
        libc::SYS_munmap => "munmap",
        libc::SYS_clone => "clone",
        libc::SYS_clone3 => "clone3",
        libc::SYS_execve => "execve",
        libc::SYS_exit => "exit",
        libc::SYS_exit_group => "exit_group",
        libc::SYS_kill => "kill",
        libc::SYS_tkill => "tkill",
        libc::SYS_tgkill => "tgkill",
        libc::SYS_futex => "futex",
        libc::SYS_ioctl => "ioctl",
        libc::SYS_epoll_ctl => "epoll_ctl",
        libc::SYS_epoll_pwait => "epoll_pwait",
        _ => "unknown",
    }
}

fn trace_options() -> libc::c_long {
    (libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        | libc::PTRACE_O_EXITKILL) as libc::c_long
}

fn resume_syscall(tid: i32, signal: i32) -> io::Result<()> {
    ptrace(libc::PTRACE_SYSCALL, tid, 0, signal as usize)
}

fn ptrace(request: libc::c_uint, pid: i32, address: usize, data: usize) -> io::Result<()> {
    // SAFETY: each caller supplies the address and data layout required by the
    // specific ptrace request; kernel errors are returned through errno.
    let result = unsafe { libc::ptrace(request, pid, address as *mut c_void, data as *mut c_void) };
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

    #[test]
    fn worker_names_are_safe_for_file_names() {
        assert_eq!(sanitize_name("vm"), "vm");
        assert_eq!(sanitize_name("worker/name"), "worker_name");
    }

    #[test]
    fn traces_process_to_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = pal::unix::process::Builder::new("/usr/bin/true");
        command.set_trace_before_exec(true);
        let child = command.spawn().unwrap();
        let pid = child.id();
        let mut traced = TracedChild::start(
            child,
            "test-worker",
            ProcessTraceConfig {
                output_dir: dir.path().to_path_buf(),
            },
        )
        .unwrap();

        let status = futures::executor::block_on(traced.wait()).unwrap();
        assert!(status.success());

        let file = File::open(dir.path().join(format!("worker-test-worker.{pid}.jsonl"))).unwrap();
        let events = io::BufReader::new(file)
            .lines()
            .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
            .collect::<Vec<_>>();
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
        assert!(events.iter().any(|event| event["event"] == "task_exit"));
    }
}
