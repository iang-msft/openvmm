// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build candidate OpenVMM sandbox profiles from worker syscall traces.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use anyhow::Context;
use anyhow::ensure;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::BufRead;
use std::net::IpAddr;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

const AT_FDCWD: u64 = u32::MAX as u64 - 99;
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
#[cfg(test)]
const O_PATH: u64 = 0o10_000_000;
const O_TMPFILE: u64 = 0o20_200_000;
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;

/// Inputs used to generate one worker profile.
#[derive(Debug)]
pub struct TraceOptions {
    /// Directory containing worker trace JSONL files, recursively searched.
    pub trace_dir: PathBuf,
    /// Worker name used to select trace files and name the generated profile.
    pub worker: String,
    /// Directory where the generated Rust source and report are written.
    pub profile_dir: PathBuf,
}

// Stores trace report entries, fd-to-resource mappings needed by later events, and
// the policy derived from those events as separate state.
#[derive(Debug, Default)]
struct TraceAnalysis {
    observed_filesystem_paths: BTreeSet<String>,
    observed_network: BTreeSet<String>,
    observed_syscalls: BTreeSet<String>,

    fd_to_path_map: BTreeMap<i64, TrackedFd>,

    absolute_grants: FilesystemGrants,
    cwd_grants: FilesystemGrants,
    initial_cwd: Option<PathBuf>,
    cwd_recorded: bool,
    cwd_relative_path_errors: BTreeSet<String>,
    policy_network: sandbox::Network,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrackedFd {
    Filesystem {
        absolute_path: PathBuf,
        cwd_relative_path: Option<PathBuf>,
    },
    Network {
        scope: sandbox::Network,
    },
}

impl TrackedFd {
    fn absolute_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Filesystem { absolute_path, .. } => Some(absolute_path),
            Self::Network { .. } => None,
        }
    }

    fn network_scope(&self) -> Option<sandbox::Network> {
        match self {
            Self::Network { scope } => Some(*scope),
            Self::Filesystem { .. } => None,
        }
    }
}

/// Filesystem grants sharing a single absolute or worker-CWD-relative anchor.
#[derive(Debug, Default)]
pub struct FilesystemGrants {
    /// Read-only paths.
    pub policy_read_paths: BTreeSet<PathBuf>,
    /// Read-write paths.
    pub policy_read_write_paths: BTreeSet<PathBuf>,
    /// Device-I/O paths.
    pub policy_device_paths: BTreeSet<PathBuf>,
    file_execution: BTreeMap<PathBuf, bool>,
    non_exec_paths: BTreeSet<PathBuf>,
}

impl FilesystemGrants {
    fn is_empty(&self) -> bool {
        self.policy_read_paths.is_empty()
            && self.policy_read_write_paths.is_empty()
            && self.policy_device_paths.is_empty()
    }
}

#[derive(Default)]
struct FilePath<'a> {
    syscall_path_arg: &'a str,
    path_base: Option<&'a Value>,
    opened_file: Option<&'a Value>,
    path_metadata: Option<&'a Value>,
}

/// Generate a sandbox profile template from the worker trace.
pub fn build_profile(trace_options: &TraceOptions) -> anyhow::Result<()> {
    ensure!(
        trace_options.trace_dir.is_dir(),
        "trace directory does not exist: {}",
        trace_options.trace_dir.display()
    );

    let worker_file_name = normalize_file_component(&trace_options.worker);
    ensure!(!worker_file_name.is_empty(), "worker name is empty");
    let rust_identifier = normalize_rust_identifier(&trace_options.worker);
    let module_name = format!("{rust_identifier}_worker");

    // Read optional platform syscall denials and validate their syscall names.
    let optional_syscall_denylist = sandbox::platform_syscall_denylist()
        .filter(|entry| entry.enforcement == sandbox::Enforcement::Optional)
        .copied()
        .collect::<Vec<_>>();
    let optional_deny_syscall_names = optional_syscall_denylist
        .iter()
        .map(|entry| entry.name.to_string())
        .collect::<Vec<_>>();
    pal_tracer::validate_syscall_names(&optional_deny_syscall_names)?;

    // Find the worker's JSONL trace files.
    let trace_files = find_worker_traces(&trace_options.trace_dir, &worker_file_name)?;
    ensure!(
        !trace_files.is_empty(),
        "no JSONL traces for worker '{}' found under {}",
        trace_options.worker,
        trace_options.trace_dir.display()
    );

    // Analyze each JSONL trace file to collect the worker's syscall, filesystem,
    // and network behavior.
    let mut trace_analysis = TraceAnalysis::default();
    for trace_file in &trace_files {
        ingest_trace(
            trace_file,
            &optional_deny_syscall_names,
            &mut trace_analysis,
        )?;
    }
    ensure!(
        trace_analysis.cwd_relative_path_errors.is_empty(),
        "cannot generate working-directory-relative grants:\n{}",
        trace_analysis
            .cwd_relative_path_errors
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Consolidate filesystem permissions collected from all trace files
    // before generating the profile.
    normalize_filesystem_grants(&mut trace_analysis);

    // Create the profile directory.
    fs_err::create_dir_all(&trace_options.profile_dir)
        .with_context(|| format!("failed to create {}", trace_options.profile_dir.display()))?;

    // Write the generated Rust profile to the profile directory.
    let profile_path = trace_options.profile_dir.join(format!("{module_name}.rs"));
    let source = render_profile(
        &worker_file_name,
        &module_name,
        &trace_analysis,
        &optional_syscall_denylist,
    );
    fs_err::write(&profile_path, source)
        .with_context(|| format!("failed to write {}", profile_path.display()))?;

    // Write the observation log to the profile directory.
    let log_path = trace_options
        .profile_dir
        .join(format!("{worker_file_name}_worker.log"));
    let log = render_report(
        &worker_file_name,
        &trace_files,
        &trace_analysis,
        &optional_syscall_denylist,
    );
    fs_err::write(&log_path, log)
        .with_context(|| format!("failed to write {}", log_path.display()))?;

    write_trace_summary(&profile_path, &log_path, &trace_files);
    Ok(())
}

fn write_trace_summary(profile_path: &Path, log_path: &Path, trace_files: &[PathBuf]) {
    println!("generated profile: {}", profile_path.display());
    println!("generated log: {}", log_path.display());
    println!("trace files:");
    for trace_file in trace_files {
        println!("  - {}", trace_file.display());
    }
}

// Recursively search the trace directory and return a sorted list of JSONL traces for the worker.
fn find_worker_traces(trace_dir: &Path, worker_file_name: &str) -> anyhow::Result<Vec<PathBuf>> {
    let mut pending = vec![trace_dir.to_path_buf()];
    let mut traces = Vec::new();
    let current_prefix = format!("worker-{worker_file_name}.");
    let legacy_prefix = format!("{worker_file_name}.");

    // Scan each directory for worker traces, adding subdirectories to the pending list.
    while let Some(dir) = pending.pop() {
        for dir_or_file in fs_err::read_dir(&dir)
            .with_context(|| format!("failed to read trace directory {}", dir.display()))?
        {
            let dir_or_file = dir_or_file?;
            let path = dir_or_file.path();
            if dir_or_file.file_type()?.is_dir() {
                pending.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if path
                .extension()
                .is_some_and(|extension| extension == "jsonl")
                && (name.starts_with(&current_prefix) || name.starts_with(&legacy_prefix))
            {
                traces.push(path);
            }
        }
    }

    // Sort trace files for predictable processing order.
    traces.sort();

    Ok(traces)
}

// Read a JSONL trace file and collect syscall, filesystem, and network
// observations used to generate the sandbox profile.
fn ingest_trace(
    trace_file: &Path,
    optional_deny_syscall_names: &[String],
    trace_analysis: &mut TraceAnalysis,
) -> anyhow::Result<()> {
    // Each trace comes from a separate worker run with its own file descriptors
    // and working directory. Clear the previous run's state so it cannot affect
    // how this trace is interpreted, while keeping the accumulated observations.
    trace_analysis.fd_to_path_map.clear();
    trace_analysis.initial_cwd = None;
    trace_analysis.cwd_recorded = false;

    let file = fs_err::File::open(trace_file)
        .with_context(|| format!("failed to open trace {}", trace_file.display()))?;

    // Read each line in order, parse its JSON event, and collect relevant syscall,
    // filesystem, and network observations.
    for (index, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line =
            line.with_context(|| format!("failed to read {}:{}", trace_file.display(), index + 1))?;
        let event: Value = serde_json::from_str(&line)
            .with_context(|| format!("invalid JSON at {}:{}", trace_file.display(), index + 1))?;

        // Record the worker's initial working directory from the trace-start event.
        if event["event"] == "trace_started" {
            trace_analysis.cwd_recorded = event.get("cwd").is_some();
            trace_analysis.initial_cwd = event["cwd"]
                .as_str()
                .filter(|cwd| Path::new(cwd).is_absolute() && !cwd.ends_with(" (deleted)"))
                .map(PathBuf::from);
        }

        // Analyze syscall events needed to derive filesystem and network permissions.
        // Optional syscalls used by the workers are omitted from the profile.
        if event["event"] == "syscall"
            && let Some(syscall) = event["syscall"].as_str().filter(|syscall| {
                pal_tracer::is_resource_access_syscall(syscall)
                    || optional_deny_syscall_names
                        .iter()
                        .any(|syscall_name| syscall_name == syscall)
            })
        {
            // Extract decoded event details, raw syscall arguments, the return value, and errno.
            let decoded_args = event.get("decoded_args").or_else(|| event.get("details"));
            let args = parse_event_args(&event);
            let retval = event["result"].as_i64();
            let errno = event["errno"].as_i64();

            track_fd_lifecycle(syscall, args, retval, trace_analysis);
            track_filesystem_access(
                syscall,
                args,
                retval,
                errno,
                decoded_args,
                &event,
                trace_analysis,
            );
            track_network_access(syscall, args, retval, errno, decoded_args, trace_analysis);
            trace_analysis.observed_syscalls.insert(syscall.to_string());
        }
    }

    Ok(())
}

// Read up to six raw syscall arguments, using zero for missing or invalid values.
fn parse_event_args(event: &Value) -> [u64; 6] {
    let mut args = [0; 6];
    if let Some(values) = event["args"].as_array() {
        for (arg, value) in args.iter_mut().zip(values) {
            *arg = value.as_u64().unwrap_or_default();
        }
    }
    args
}

//
// open("/tmp/data", O_RDONLY) = 3
// dup(3) = 7
// close(3) = 0
//
// open associates descriptor 3 with /tmp/data. dup creates descriptor 7 for the
// same file, so this function copies 3's mapping to 7. close removes only 3's
// mapping; 7 still refers to /tmp/data, while 3 can be reused for another resource.
//
// Tracking duplication is needed to resolve relative paths accessed through
// duplicated directory descriptors:
//
// open("/var/lib/openvmm", O_DIRECTORY) = 3
// dup(3) = 7
// openat(7, "state/data", O_RDONLY) = 8
//
// To resolve "state/data" to /var/lib/openvmm/state/data, the profiler must know
// that descriptor 7 refers to the same directory as 3. Copying the mapping keeps
// this association even if 3 is subsequently closed. The path resolver uses this
// mapping as a fallback when the trace does not contain an explicit directory base.
fn track_fd_lifecycle(
    syscall: &str,
    args: [u64; 6],
    retval: Option<i64>,
    trace_analysis: &mut TraceAnalysis,
) {
    match syscall {
        // dup(oldfd) -> newfd: args[0] is oldfd.
        // On success, retval holds the newly allocated descriptor, newfd.
        "dup" => map_fd_to_path(args[0], retval, trace_analysis),

        // dup2(oldfd, newfd) -> newfd: args[0] is oldfd; args[1] is newfd.
        // On success, retval holds newfd, the requested descriptor in args[1].
        "dup2" => map_fd_to_path(args[0], retval, trace_analysis),

        // dup3(oldfd, newfd, flags) -> newfd: args[0..=2] hold the three arguments.
        // On success, retval holds newfd, the requested descriptor in args[1].
        "dup3" => map_fd_to_path(args[0], retval, trace_analysis),

        // fcntl(fd, cmd, minfd) -> newfd: args[0..=2] hold the three arguments.
        // Handle only F_DUPFD (0) and F_DUPFD_CLOEXEC (1030).
        // On success, retval holds newfd, the allocated descriptor >= minfd.
        "fcntl" if matches!(args[1], 0 | 1030) => {
            map_fd_to_path(args[0], retval, trace_analysis);
        }

        // close(fd) -> 0 on success: args[0] is fd; retval holds 0 on success.
        // Check retval here and remove args[0]; retval is a status, not a descriptor.
        "close" if retval == Some(0) => {
            let fd = args[0] as i64;
            trace_analysis.fd_to_path_map.remove(&fd);
        }

        _ => {}
    }
}

// Copy old_fd's tracked file paths and network scope to new_fd.
fn map_fd_to_path(old_fd: u64, new_fd: Option<i64>, trace_analysis: &mut TraceAnalysis) {
    let Some(new_fd) = new_fd.filter(|fd| *fd >= 0) else {
        return;
    };
    let old_fd = old_fd as i64;
    if let Some(resource) = trace_analysis.fd_to_path_map.get(&old_fd).cloned() {
        trace_analysis.fd_to_path_map.insert(new_fd, resource);
    } else {
        trace_analysis.fd_to_path_map.remove(&new_fd);
    }
}

// Extract syscall paths and metadata to record filesystem accesses and infer grants.
fn track_filesystem_access(
    syscall: &str,
    args: [u64; 6],
    retval: Option<i64>,
    errno: Option<i64>,
    decoded_args: Option<&Value>,
    event: &Value,
    trace_analysis: &mut TraceAnalysis,
) {
    let opened_file = matches!(syscall, "open" | "openat")
        .then(|| event.get("opened_file"))
        .flatten();
    let path_metadata = event.get("path_metadata");

    // Track decoded_args["path"], falling back to opened_file["path"] for open/openat.
    // For renameat2, path is oldpath (args[1]); olddirfd is args[0].
    if let Some(path) = decoded_args
        .and_then(|decoded_args| decoded_args.get("path"))
        .and_then(Value::as_str)
        .or_else(|| opened_file.and_then(|file| file["path"].as_str()))
    {
        let path_base = decoded_args.and_then(|decoded_args| decoded_args.get("path_base"));
        track_filesystem_path(
            syscall,
            args,
            FilePath {
                syscall_path_arg: path,
                path_base,
                opened_file,
                path_metadata,
            },
            retval,
            errno,
            trace_analysis,
        );
    }

    // Track decoded_args["path2"]: renameat2's newpath (args[3]).
    // Its directory descriptor is newdirfd (args[2]).
    if let Some(path) = decoded_args
        .and_then(|decoded_args| decoded_args.get("path2"))
        .and_then(Value::as_str)
    {
        let mut path_args = args;
        // Put newdirfd in path_args[0] to resolve newpath relative to it.
        path_args[0] = args[2];
        track_filesystem_path(
            syscall,
            path_args,
            FilePath {
                syscall_path_arg: path,
                path_base: decoded_args.and_then(|decoded_args| decoded_args.get("path2_base")),
                opened_file: None,
                path_metadata: event.get("path2_metadata"),
            },
            retval,
            errno,
            trace_analysis,
        );
    }
}

// Determine the absolute path accessed by the worker.
// For example, syscall_path_arg "logs/output.txt" and path_base "/work"
// resolve to "/work/logs/output.txt".
// Record the file access and access mode (read/write/exec), and whether
// the file is a regular file or a device.
fn track_filesystem_path(
    syscall: &str,
    args: [u64; 6],
    file_path: FilePath<'_>,
    retval: Option<i64>,
    errno: Option<i64>,
    trace_analysis: &mut TraceAnalysis,
) {
    let syscall_path_arg = file_path.syscall_path_arg;
    let dirfd = if syscall == "open" { AT_FDCWD } else { args[0] };
    let is_write = is_path_written(syscall, args);
    let access = if is_write { "RW" } else { "RO" };
    let syscalls_status = map_status_to_linux_syscall_status(retval, errno);

    let path = if syscall_path_arg.is_empty() {
        // Empty pathname: record the existing descriptor's file name when available.
        // For example, newfstatat(5, "", &statbuf, AT_EMPTY_PATH) deliberately passes
        // an empty pathname to read metadata for the file already opened as fd 5.
        // If fd 5 refers to "/work/data.txt", path_base contains that name when captured.
        let path = file_path
            .path_base
            .and_then(Value::as_str)
            .filter(|path_base| !path_base.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!("<NO_PATH_BASE; {syscall}; dirfd: {}>", format_dirfd(dirfd))
            });
        trace_analysis
            .observed_filesystem_paths
            .insert(format!("{path}, {access}, {syscalls_status}"));
        return;
    } else if let Some(path) =
        resolve_absolute_path(syscall_path_arg, dirfd, file_path.path_base, trace_analysis)
            .or_else(|| opened_file_absolute_path(file_path.opened_file))
    {
        // Prefer the absolute path constructed from the syscall
        // arguments, preserving the name the worker attempted to access even if
        // the syscall failed. For example, keep "/work/config" when that name is
        // a symlink to "/shared/config". Only if construction fails, use the path
        // captured from the descriptor returned by a successful open/openat.
        path
    } else {
        // Neither the syscall arguments nor the opened-file metadata
        // provided an absolute path.
        trace_analysis
            .observed_filesystem_paths
            .insert(format!("{syscall_path_arg}, {access}, {syscalls_status}"));
        return;
    };

    trace_analysis
        .observed_filesystem_paths
        .insert(format!("{}, {access}, {syscalls_status}", path.display()));

    if matches!(syscall, "open" | "openat")
        && let Some(fd) = retval.filter(|retval| *retval >= 0)
    {
        // Record the path against the fd, so a later relative *at
        // call using this fd can be resolved to an absolute path.
        trace_analysis.fd_to_path_map.insert(
            fd,
            TrackedFd::Filesystem {
                absolute_path: opened_file_absolute_path(file_path.opened_file)
                    .unwrap_or_else(|| path.clone()),
                cwd_relative_path: None,
            },
        );
    }

    // The sandbox creates its own /proc and /tmp mounts. Granting the host
    // versions would give the worker different access from what it requested.
    // A root-wide grant would expose the entire host filesystem.
    if path == Path::new("/") || path.starts_with("/proc") || path.starts_with("/tmp") {
        return;
    }

    // Use metadata from a successful access to identify the file type and execute
    // permission bits, preferring opened-file metadata over path_metadata.
    let path_metadata = retval.filter(|retval| *retval >= 0).and_then(|_| {
        file_path
            .opened_file
            .filter(|file| file.is_object())
            .or(file_path.path_metadata)
    });
    let file_type = path_metadata.and_then(|file| file["file_type"].as_str());
    let is_device = match file_type {
        Some("character_device" | "block_device") => true,
        Some("regular_file" | "directory" | "symlink" | "fifo" | "socket") => false,
        _ => path.starts_with("/dev") && path != Path::new("/dev"),
    };

    // Express the path relative to the startup working directory when appropriate;
    // for example, "config/settings.json" under startup directory "/work" stays
    // relative instead of using "/work/config/settings.json". Otherwise keep it absolute.
    let (path, is_cwd_relative) = match make_path_cwd_relative(
        syscall_path_arg,
        dirfd,
        file_path.path_base,
        &path,
        trace_analysis,
    ) {
        Ok(path) => path,
        Err(reason) => {
            trace_analysis.cwd_relative_path_errors.insert(reason);
            return;
        }
    };

    if matches!(syscall, "open" | "openat")
        && is_cwd_relative
        && let Some(fd) = retval.filter(|fd| *fd >= 0)
        && let Some(TrackedFd::Filesystem {
            cwd_relative_path, ..
        }) = trace_analysis.fd_to_path_map.get_mut(&fd)
    {
        *cwd_relative_path = Some(path.clone());
    }
    let grants = if is_cwd_relative {
        &mut trace_analysis.cwd_grants
    } else {
        &mut trace_analysis.absolute_grants
    };

    if is_device {
        grants.policy_device_paths.insert(path);
        return;
    }
    if file_type == Some("regular_file")
        && let Some(mode) = path_metadata.and_then(|file| file["mode"].as_u64())
    {
        // Keep execution if any successful snapshot observed execute bits.
        *grants.file_execution.entry(path.clone()).or_default() |= mode & 0o111 != 0;
    }

    if is_write {
        grants.policy_read_write_paths.insert(path);
    } else {
        grants.policy_read_paths.insert(path);
    }

    fn opened_file_absolute_path(opened_file: Option<&Value>) -> Option<PathBuf> {
        let path = opened_file?.get("path")?.as_str()?;
        (Path::new(path).is_absolute() && !path.ends_with(" (deleted)"))
            .then(|| normalize_path(Path::new(path)))
    }
}

// Express a relative syscall pathname relative to the worker's startup working
// directory when its recorded base or tracked descriptor establishes that relationship.
// For example, "settings.json" under "/work/config" with startup directory "/work"
// returns ("config/settings.json", true). Absolute syscall paths stay
// absolute and return false. Preserve `..`; return an error if the required
// relationship to the startup directory cannot be established.
fn make_path_cwd_relative(
    syscall_path_arg: &str,
    dirfd: u64,
    path_base: Option<&Value>,
    absolute_path: &Path,
    trace_analysis: &mut TraceAnalysis,
) -> Result<(PathBuf, bool), String> {
    // Keep an explicitly absolute syscall pathname, such as "/etc/hosts", absolute.
    if Path::new(syscall_path_arg).is_absolute() {
        return Ok((absolute_path.to_path_buf(), false));
    }

    // Find the directory syscall_path_arg is relative to. Prefer a captured absolute,
    // non-deleted path_base. Use the tracked descriptor only when path_base is absent.
    let tracked_fd = trace_analysis.fd_to_path_map.get(&(dirfd as i64));
    let base = path_base
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|base| base.is_absolute() && !base.to_string_lossy().ends_with(" (deleted)"))
        .or_else(|| {
            path_base
                .is_none()
                .then(|| tracked_fd.and_then(TrackedFd::absolute_path).cloned())
                .flatten()
        });

    // If startup-directory information was not recorded, use the first available
    // base from an AT_FDCWD access as the initial working directory.
    let is_cwd = dirfd as u32 == AT_FDCWD as u32;
    if is_cwd && !trace_analysis.cwd_recorded && trace_analysis.initial_cwd.is_none() {
        trace_analysis.initial_cwd = base.clone();
    }

    // For a directory-FD lookup, reuse its saved startup-directory-relative path.
    // Without one, keep the access absolute.
    if !is_cwd {
        let Some(TrackedFd::Filesystem {
            absolute_path: tracked_absolute,
            cwd_relative_path: Some(relative),
        }) = tracked_fd
        else {
            return Ok((absolute_path.to_path_buf(), false));
        };

        // Confirm the captured base still matches the tracked directory before
        // combining, e.g. saved "config" plus "settings.json". Drop "." but keep "..".
        if base.as_ref() == Some(tracked_absolute) {
            let relative = relative
                .join(syscall_path_arg)
                .components()
                .filter(|component| *component != Component::CurDir)
                .collect();
            return Ok((relative, true));
        }
    }

    // Otherwise, derive the relative directory from the startup directory:
    // base "/work/config", initial "/work", and syscall_path_arg "settings.json" yield
    // "config/settings.json". Drop "." but preserve symlink-sensitive "..".
    if let (Some(base), Some(initial)) = (&base, &trace_analysis.initial_cwd)
        && let Ok(suffix) = base.strip_prefix(initial)
    {
        let relative = suffix
            .join(syscall_path_arg)
            .components()
            .filter(|component| *component != Component::CurDir)
            .collect();
        return Ok((relative, true));
    }

    // Report why this relative access could not be tied to the startup directory.
    Err(format!(
        "cannot express syscall pathname {syscall_path_arg:?} relative to the startup working directory (pathname base: {base:?}, startup working directory: {:?})",
        trace_analysis.initial_cwd
    ))
}

// Resolve a pathname to a normalized absolute path.
// Return None when the path cannot be resolved.
fn resolve_absolute_path(
    syscall_path_arg: &str,
    dirfd: u64,
    path_base: Option<&Value>,
    trace_analysis: &TraceAnalysis,
) -> Option<PathBuf> {
    let path = Path::new(syscall_path_arg);
    if path.is_absolute() {
        // Normalize an already absolute path.
        return Some(normalize_path(path));
    }

    if let Some(base) = path_base {
        // Resolve a relative path against the path_base.
        let base = Path::new(base.as_str()?);
        return (base.is_absolute() && !syscall_path_arg.is_empty())
            .then(|| normalize_path(&base.join(path)));
    }

    if dirfd as u32 == AT_FDCWD as u32 {
        // A current-directory-relative path cannot be resolved without its base.
        return None;
    }

    // Resolve the relative path against the directory descriptor's tracked path.
    trace_analysis
        .fd_to_path_map
        .get(&(dirfd as i64))
        .and_then(TrackedFd::absolute_path)
        .map(|base| normalize_path(&base.join(path)))
}

// Eliminate redundant filesystem grants.
fn normalize_filesystem_grants(trace_analysis: &mut TraceAnalysis) {
    let grants = &mut trace_analysis.absolute_grants;

    // Collect files observed without execute permission.
    let non_executable_paths = grants
        .file_execution
        .iter()
        .filter(|(_, executable)| !**executable)
        .map(|(path, _)| path);

    // Prevent read grants from adding execution access to writable paths,
    // devices, or files observed without execute permission.
    // Example: RO /data containing RW /data/output makes /data non-executable.
    grants.non_exec_paths.extend(
        grants
            .policy_read_paths
            .iter()
            .filter(|path| {
                grants
                    .policy_read_write_paths
                    .iter()
                    .chain(&grants.policy_device_paths)
                    .chain(non_executable_paths.clone())
                    .any(|restricted| restricted.starts_with(path))
            })
            .cloned(),
    );

    // Keep the device grant when the same path also has a read-write grant.
    // Example: device /dev/kvm + RW /dev/kvm -> device /dev/kvm.
    grants
        .policy_read_write_paths
        .retain(|path| !grants.policy_device_paths.contains(path));

    // Remove read grants covered by read-write grants or matching device grants.
    // Example: RW /data + RO /data/config -> RW /data.
    // Keep RO /data + RW /data/output so the writable exception remains.
    grants.policy_read_paths.retain(|path| {
        !is_covered(path, &grants.policy_read_write_paths)
            && !grants.policy_device_paths.contains(path)
    });

    // Separate read grants by execution permission so collapsing paths within
    // each group preserves executable exceptions under non-executable parents.
    let (executable, read_only): (BTreeSet<_>, BTreeSet<_>) = grants
        .policy_read_paths
        .iter()
        .cloned()
        .partition(|path| read_is_executable(grants, path));

    // Within each permission group, remove descendants covered by an ancestor.
    // Example: RO /data + RO /data/config -> RO /data.
    grants.policy_read_paths = collapse_paths(&read_only);
    grants.policy_read_paths.extend(collapse_paths(&executable));
    grants.policy_read_write_paths = collapse_paths(&grants.policy_read_write_paths);

    if !trace_analysis.cwd_grants.is_empty() {
        // Replace ordinary CWD-relative grants with one read-only grant for ".",
        // preserving device grants and clearing the other CWD-relative state.
        // Example: RO config + RW output + device dev/kvm -> RO "." + device dev/kvm.
        let device_paths = std::mem::take(&mut trace_analysis.cwd_grants.policy_device_paths);
        trace_analysis.cwd_grants = FilesystemGrants {
            policy_read_paths: BTreeSet::from([PathBuf::from(".")]),
            policy_device_paths: device_paths,
            ..Default::default()
        };
    }
}

// Normalize path components lexically by dropping "." and removing the preceding
// component for "..", without consulting the filesystem or following symlinks.
// For example, /var/./lib/openvmm/../data becomes /var/lib/data.
fn normalize_path(path: &Path) -> PathBuf {
    let mut path_normalized = PathBuf::new();
    for path_component in path.components() {
        match path_component {
            Component::Prefix(prefix) => path_normalized.push(prefix.as_os_str()),
            Component::RootDir => path_normalized.push(path_component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                path_normalized.pop();
            }
            Component::Normal(name) => path_normalized.push(name),
        }
    }
    path_normalized
}

// Identify write access from open/openat's access mode and creation flags, or from
// directory creation, removal, and rename operations.
fn is_path_written(syscall: &str, args: [u64; 6]) -> bool {
    match syscall {
        "open" | "openat" => {
            let flags = args[if syscall == "open" { 1 } else { 2 }];
            matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR)
                || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0
                || flags & O_TMPFILE == O_TMPFILE
        }

        "mkdirat" | "unlinkat" | "renameat2" => true,

        _ => false,
    }
}

// Track socket activity and endpoints to infer the required network access.
fn track_network_access(
    syscall: &str,
    args: [u64; 6],
    retval: Option<i64>,
    errno: Option<i64>,
    decoded_args: Option<&Value>,
    trace_analysis: &mut TraceAnalysis,
) {
    // socket identifies the address family. Later calls such as bind and
    // connect determine whether the worker needs loopback or broader access.
    match syscall {
        "socket" => {
            let domain = args[0];
            if let Some(fd) = retval.filter(|retval| *retval >= 0)
                && domain != AF_UNIX
            {
                trace_analysis
                    .observed_network
                    .insert(format!("{} (address family)", address_family_name(domain)));
                if matches!(domain, AF_INET | AF_INET6) {
                    trace_analysis.fd_to_path_map.insert(
                        fd,
                        TrackedFd::Network {
                            scope: sandbox::Network::None,
                        },
                    );
                }
            }
        }

        "accept4" => {
            if let (Some(listener_scope), Some(accepted_fd)) = (
                trace_analysis
                    .fd_to_path_map
                    .get(&(args[0] as i64))
                    .and_then(TrackedFd::network_scope),
                retval.filter(|retval| *retval >= 0),
            ) {
                // If the trace does not show whether the listener is bound
                // only to loopback, assume it may accept non-loopback
                // connections and use Unrestricted.
                let scope = if listener_scope == sandbox::Network::None {
                    sandbox::Network::Unrestricted
                } else {
                    listener_scope
                };
                trace_analysis
                    .observed_network
                    .insert(format!("fd {} (network descriptor)", args[0]));
                trace_analysis
                    .fd_to_path_map
                    .insert(accepted_fd, TrackedFd::Network { scope });
                trace_analysis.policy_network = trace_analysis.policy_network.max(scope);
            }
        }

        "connect" | "bind" | "sendto" if has_syscall_succeeded(syscall, retval, errno) => {
            let fd = args[0] as i64;
            if let Some((scope, endpoint)) = socket_address_scope(decoded_args) {
                trace_analysis
                    .observed_network
                    .insert(format!("{endpoint} (endpoint)"));
                widen_network_fd(fd, scope, trace_analysis);
            } else if let Some(current_scope) = trace_analysis
                .fd_to_path_map
                .get(&fd)
                .and_then(TrackedFd::network_scope)
            {
                let (scope, endpoint) = {
                    // sendto without an address uses the socket's connected
                    // peer, so keep its known scope. For other missing address
                    // data, use Unrestricted because loopback is not proven.
                    let scope = if syscall == "sendto" && current_scope != sandbox::Network::None {
                        current_scope
                    } else {
                        sandbox::Network::Unrestricted
                    };
                    (scope, "unknown address".to_string())
                };
                trace_analysis
                    .observed_network
                    .insert(format!("{endpoint} (endpoint)"));
                widen_network_fd(fd, scope, trace_analysis);
            }
        }

        "listen" | "recvfrom" | "sendmsg" | "recvmsg"
            if retval.is_some_and(|retval| retval >= 0) =>
        {
            let fd = args[0] as i64;
            if let Some(scope) = trace_analysis
                .fd_to_path_map
                .get(&fd)
                .and_then(TrackedFd::network_scope)
            {
                // Successful I/O proves that networking is required. If no
                // endpoint was decoded, use Unrestricted because the trace
                // does not show that the traffic stayed on loopback.
                let scope = if scope == sandbox::Network::None {
                    sandbox::Network::Unrestricted
                } else {
                    scope
                };
                trace_analysis
                    .observed_network
                    .insert(format!("fd {fd} (network descriptor)"));
                widen_network_fd(fd, scope, trace_analysis);
            }
        }

        _ => {}
    }
}

// Return true for a nonnegative syscall result, or for connect with EINPROGRESS
// because an in-progress connection also requires network access.
fn has_syscall_succeeded(syscall: &str, retval: Option<i64>, errno: Option<i64>) -> bool {
    if retval.is_some_and(|retval| retval >= 0) {
        return true;
    }

    // EINPROGRESS means a nonblocking connection was started, so count it
    // as network use even though connect has not completed yet.
    syscall == "connect" && errno == Some(libc::EINPROGRESS as i64)
}

// Parse a decoded IP address and port into an endpoint string and classify its
// network scope as loopback or unrestricted. Return None for missing or invalid data.
fn socket_address_scope(decoded_args: Option<&Value>) -> Option<(sandbox::Network, String)> {
    let socket_address = decoded_args?.get("socket_address")?;
    let address = socket_address.get("address")?.as_str()?;
    let port = socket_address.get("port")?.as_u64()?;
    let address = address.parse::<IpAddr>().ok()?;
    let scope = if address.is_loopback() {
        sandbox::Network::Loopback
    } else {
        sandbox::Network::Unrestricted
    };
    Some((scope, format!("{address}:{port}")))
}

// Keep the broadest requirement seen for this fd and for the worker. A
// later loopback event must not undo an earlier unrestricted event.
fn widen_network_fd(fd: i64, scope: sandbox::Network, trace_analysis: &mut TraceAnalysis) {
    let current = trace_analysis
        .fd_to_path_map
        .get(&fd)
        .and_then(TrackedFd::network_scope)
        .unwrap_or_default();
    trace_analysis.fd_to_path_map.insert(
        fd,
        TrackedFd::Network {
            scope: current.max(scope),
        },
    );
    trace_analysis.policy_network = trace_analysis.policy_network.max(scope);
}

// Determine whether a read grant permits execution using captured file modes
// and non-executable path restrictions.
fn read_is_executable(grants: &FilesystemGrants, path: &Path) -> bool {
    if path.starts_with("/sys") || grants.non_exec_paths.contains(path) {
        return false;
    }
    grants.file_execution.get(path).copied().unwrap_or_else(|| {
        !grants
            .non_exec_paths
            .iter()
            .any(|parent| path.starts_with(parent))
    })
}

// Remove paths already covered by an ancestor with the same permissions.
// 1. Start with an empty collapsed_paths set.
// 2. Iterate paths in BTreeSet order, which visits ancestors before their descendants.
// 3. Keep each path only if no previously kept path covers it.
// Paths containing `..` are compared only for exact matches.
//
// Example:
// /etc/config                 -> keep
// /var/lib/openvmm            -> keep
// /var/lib/openvmm/state      -> skip: covered by /var/lib/openvmm
// /var/lib/openvmm/state/data -> skip: covered by /var/lib/openvmm
// Result: {/etc/config, /var/lib/openvmm}.
fn collapse_paths(paths: &BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
    let mut collapsed_paths = BTreeSet::new();
    for path in paths {
        if !is_covered(path, &collapsed_paths) {
            collapsed_paths.insert(path.clone());
        }
    }
    collapsed_paths
}

// Check whether a grant matches the path or is its ancestor.
// If either path contains `..`, return true only when both paths are equal.
// For example, /data does not cover /data/../secret.
fn is_covered(path: &Path, paths: &BTreeSet<PathBuf>) -> bool {
    paths.iter().any(|grant| {
        path == grant
            || (!path
                .components()
                .chain(grant.components())
                .any(|component| component == Component::ParentDir)
                && path.starts_with(grant))
    })
}

// Format an access result as SUCCESS, a Linux errno name, ERRNO_<number>, or
// UNKNOWN, using the explicit errno first and a negative result as a fallback.
fn map_status_to_linux_syscall_status(retval: Option<i64>, errno: Option<i64>) -> String {
    if retval.is_some_and(|retval| retval >= 0) {
        return "SUCCESS".to_string();
    }
    let Some(errno) = errno
        .filter(|errno| *errno > 0)
        .or_else(|| retval.and_then(i64::checked_neg))
    else {
        return "UNKNOWN".to_string();
    };
    // These are Linux trace errno values, independent of the profiler's host OS.
    let name = match errno {
        1 => "EPERM",
        2 => "ENOENT",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        9 => "EBADF",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        26 => "ETXTBSY",
        27 => "EFBIG",
        28 => "ENOSPC",
        30 => "EROFS",
        31 => "EMLINK",
        36 => "ENAMETOOLONG",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        75 => "EOVERFLOW",
        95 => "EOPNOTSUPP",
        116 => "ESTALE",
        _ => return format!("ERRNO_{errno}"),
    };
    name.to_string()
}

// Render a Rust builder function containing the inferred filesystem grants,
// network scope, and syscall denials.
fn render_profile(
    worker_file_name: &str,
    function_name: &str,
    trace_analysis: &TraceAnalysis,
    syscall_denylist: &[sandbox::DeniedSyscall],
) -> String {
    // Generate the profile header and deny-by-default builder.
    let mut source = String::new();
    writeln!(
        source,
        "// Automatically generated sandbox profile for {worker_file_name} worker\n"
    )
    .unwrap();
    writeln!(source, "use crate::Builder;").unwrap();
    writeln!(source, "use crate::Network;").unwrap();
    writeln!(source, "use crate::Profile;").unwrap();
    writeln!(source, "use crate::Syscalls;\n").unwrap();
    writeln!(source, "pub fn {function_name}() -> Builder {{").unwrap();
    writeln!(source, "    // Deny access by default.").unwrap();
    writeln!(
        source,
        "    let mut profile = Profile::deny_all().name({});",
        rust_string(function_name)
    )
    .unwrap();

    // Generate filesystem grants.
    let has_cwd = !trace_analysis.cwd_grants.is_empty();
    if has_cwd {
        writeln!(
            source,
            "    let cwd = std::env::current_dir().unwrap_or_default();"
        )
        .unwrap();
    }
    render_filesystem_grants(&mut source, trace_analysis);

    // Generate network rules.
    let generated_network = trace_analysis.policy_network;
    writeln!(source, "\n    // Network access.").unwrap();
    writeln!(
        source,
        "    profile = profile.network(Network::{});",
        network_variant(generated_network),
    )
    .unwrap();

    // Generate syscall restrictions.
    let generated_denials = generate_syscall_denials(syscall_denylist, trace_analysis);
    writeln!(source, "\n    // System call restrictions.").unwrap();
    writeln!(source, "    profile = profile.syscalls(Syscalls::deny([").unwrap();
    for syscall in &generated_denials {
        writeln!(source, "        {},", rust_string(syscall)).unwrap();
    }
    writeln!(source, "    ]));").unwrap();

    writeln!(source, "\n    profile").unwrap();
    writeln!(source, "}}").unwrap();
    source
}

// CWD-anchored observations share the first read/execute entry. A failed CWD
// lookup or non-UTF-8 CWD produces an empty string, which the existence check skips.
fn render_filesystem_grants(source: &mut String, trace_analysis: &TraceAnalysis) {
    let mut groups: BTreeMap<&str, Vec<&Path>> = BTreeMap::new();
    let grants = &trace_analysis.absolute_grants;
    for path in &grants.policy_read_paths {
        let method = if !read_is_executable(grants, path)
            || grants
                .policy_device_paths
                .iter()
                .chain(&grants.policy_read_write_paths)
                .any(|restricted| restricted.starts_with(path))
        {
            "read"
        } else {
            "read_exec"
        };
        groups.entry(method).or_default().push(path);
    }
    for (method, paths) in [
        ("read_write", &grants.policy_read_write_paths),
        ("device", &grants.policy_device_paths),
    ] {
        groups
            .entry(method)
            .or_default()
            .extend(paths.iter().map(PathBuf::as_path));
    }
    groups.entry("device").or_default().extend(
        trace_analysis
            .cwd_grants
            .policy_device_paths
            .iter()
            .map(PathBuf::as_path),
    );
    for (method, comment) in [
        ("read", "Read-only paths."),
        ("read_exec", "Read and execute paths."),
        ("read_write", "Read/write paths."),
        ("device", "Device access."),
    ] {
        let paths = groups.get(method).map(Vec::as_slice).unwrap_or_default();
        let include_cwd = method == "read_exec" && !trace_analysis.cwd_grants.is_empty();
        if paths.is_empty() && !include_cwd {
            continue;
        }
        writeln!(source, "\n    // {comment}").unwrap();
        writeln!(source, "    for path in [").unwrap();
        if include_cwd {
            writeln!(
                source,
                "        cwd.to_str().unwrap_or_default(), // Allow read/execute access to the worker's working directory."
            )
            .unwrap();
        }
        for path in paths {
            let path = rust_string(&path.display().to_string());
            writeln!(source, "        {path},").unwrap();
        }
        writeln!(source, "    ] {{").unwrap();
        writeln!(source, "        let path = std::path::Path::new(path);").unwrap();
        if method == "device" && !trace_analysis.cwd_grants.policy_device_paths.is_empty() {
            writeln!(source, "        let resolved_path = cwd.join(path);").unwrap();
            writeln!(source, "        let path = resolved_path.as_path();").unwrap();
        }
        writeln!(source, "        if path.exists() {{").unwrap();
        writeln!(source, "            profile = profile.{method}(path);").unwrap();
        writeln!(source, "        }}").unwrap();
        writeln!(source, "    }}").unwrap();
    }
}

// Render the observation log with filesystem accesses, network accesses,
// observed syscalls, and denylisted syscalls encountered in the traces.
fn render_report(
    worker_file_name: &str,
    trace_files: &[PathBuf],
    trace_analysis: &TraceAnalysis,
    syscall_denylist: &[sandbox::DeniedSyscall],
) -> String {
    let mut report = String::new();
    writeln!(
        report,
        "Sandbox profile report for {worker_file_name} worker"
    )
    .unwrap();
    writeln!(
        report,
        "Generated by sandbox_profiler from {} trace file(s).",
        trace_files.len()
    )
    .unwrap();
    write_report_list(
        &mut report,
        "Observed filesystem accesses",
        trace_analysis.observed_filesystem_paths.iter().cloned(),
    );
    write_report_list(
        &mut report,
        "Observed network accesses",
        trace_analysis.observed_network.iter().cloned(),
    );
    write_report_list(
        &mut report,
        "Observed syscalls",
        trace_analysis.observed_syscalls.iter().cloned(),
    );
    write_report_list(
        &mut report,
        "Syscalls denied by policy but used by the worker",
        observed_policy_denials(syscall_denylist, trace_analysis),
    );
    report
}

// Append a report section with a heading and list entries, or "None." if empty.
fn write_report_list(report: &mut String, heading: &str, values: impl IntoIterator<Item = String>) {
    writeln!(report).unwrap();
    writeln!(report, "{heading}:").unwrap();
    let mut any = false;
    for value in values {
        any = true;
        writeln!(report, "- {value}").unwrap();
    }
    if !any {
        writeln!(report, "- None.").unwrap();
    }
}

// Mandatory denials remain enforced. Optional denials are omitted when the
// trace proves that the worker requires the syscall.
fn generate_syscall_denials(
    syscall_denylist: &[sandbox::DeniedSyscall],
    trace_analysis: &TraceAnalysis,
) -> Vec<String> {
    syscall_denylist
        .iter()
        .filter(|entry| {
            entry.enforcement == sandbox::Enforcement::Mandatory
                || !syscall_was_observed(entry.name, trace_analysis)
        })
        .map(|entry| entry.name.to_string())
        .collect()
}

// List denylisted syscalls used by the worker so reviewers can decide
// whether to change the worker or the denylist.
fn observed_policy_denials(
    syscall_denylist: &[sandbox::DeniedSyscall],
    trace_analysis: &TraceAnalysis,
) -> Vec<String> {
    syscall_denylist
        .iter()
        .filter(|entry| syscall_was_observed(entry.name, trace_analysis))
        .map(|entry| entry.name.to_string())
        .collect()
}

fn syscall_was_observed(name: &str, trace_analysis: &TraceAnalysis) -> bool {
    trace_analysis.observed_syscalls.contains(name)
}

// Create a lowercase filename component, preserving ASCII letters, digits,
// hyphens, and underscores and replacing other characters with underscores.
fn normalize_file_component(worker: &str) -> String {
    worker
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn normalize_rust_identifier(worker: &str) -> String {
    normalize_file_component(worker).replace('-', "_")
}

fn format_dirfd(dirfd: u64) -> String {
    if dirfd as u32 == AT_FDCWD as u32 {
        "AT_FDCWD".to_string()
    } else {
        dirfd.to_string()
    }
}

// Format known socket address families by their AF_* names, or use the numeric
// value for an unrecognized family.
fn address_family_name(domain: u64) -> String {
    match domain {
        0 => "AF_UNSPEC".to_string(),
        1 => "AF_UNIX".to_string(),
        2 => "AF_INET".to_string(),
        10 => "AF_INET6".to_string(),
        16 => "AF_NETLINK".to_string(),
        17 => "AF_PACKET".to_string(),
        _ => domain.to_string(),
    }
}

fn network_variant(network: sandbox::Network) -> &'static str {
    match network {
        sandbox::Network::None => "None",
        sandbox::Network::Loopback => "Loopback",
        sandbox::Network::Unrestricted => "Unrestricted",
    }
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_generated_grant(source: &str, method: &str, path: &str) -> bool {
        source.split("\n    for path in [\n").skip(1).any(|block| {
            let (paths, body) = block.split_once("\n    ]").unwrap();
            paths.lines().any(|line| line.contains(&rust_string(path)))
                && body
                    .split("\n    }\n")
                    .next()
                    .unwrap()
                    .contains(&format!("profile = profile.{method}(path);"))
        })
    }

    #[test]
    fn folds_cwd_paths_into_first_read_exec_entry_and_returns_builder() {
        let mut analysis = TraceAnalysis::default();
        analysis.absolute_grants.policy_read_paths.extend([
            PathBuf::from("/sys/example"),
            PathBuf::from("/captured-only/library.so"),
        ]);
        analysis
            .cwd_grants
            .policy_read_paths
            .insert(PathBuf::from("library.so"));
        for (grants, prefix) in [
            (&mut analysis.absolute_grants, "/captured-only/"),
            (&mut analysis.cwd_grants, ""),
        ] {
            grants
                .policy_read_write_paths
                .insert(PathBuf::from(format!("{prefix}state")));
            grants
                .policy_device_paths
                .insert(PathBuf::from(format!("{prefix}device")));
        }
        normalize_filesystem_grants(&mut analysis);
        assert_eq!(
            analysis.cwd_grants.policy_read_paths,
            BTreeSet::from([PathBuf::from(".")])
        );
        assert!(analysis.cwd_grants.policy_read_write_paths.is_empty());
        assert_eq!(
            analysis.cwd_grants.policy_device_paths,
            BTreeSet::from([PathBuf::from("device")])
        );
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        for (method, path) in [
            ("read", "/sys/example"),
            ("read_exec", "/captured-only/library.so"),
            ("read_write", "/captured-only/state"),
            ("device", "/captured-only/device"),
        ] {
            assert!(has_generated_grant(&source, method, path));
            assert_eq!(
                source
                    .matches(&format!("profile = profile.{method}(path);"))
                    .count(),
                1
            );
        }
        assert_eq!(source.matches("if path.exists() {").count(), 4);
        assert_eq!(
            source
                .matches("let path = std::path::Path::new(path);")
                .count(),
            4
        );
        assert!(source.contains("\n        \"/captured-only/library.so\",\n"));
        assert!(source.contains(
            "// Read and execute paths.\n    for path in [\n        cwd.to_str().unwrap_or_default(), // Allow read/execute access to the worker's working directory.\n"
        ));
        assert_eq!(
            source.matches("cwd.to_str().unwrap_or_default()").count(),
            1
        );
        assert!(source.contains("let cwd = std::env::current_dir().unwrap_or_default();"));
        assert!(!source.contains("Some("));
        assert!(!source.contains(".flatten()"));
        assert!(source.contains("let resolved_path = cwd.join(path);"));
        assert!(has_generated_grant(&source, "device", "device"));
        for path in ["library.so", "state", "device-info"] {
            assert!(!source.contains(&rust_string(path)));
        }
        assert!(source.contains("pub fn vm_worker() -> Builder {"));
        assert!(source.contains("\n    profile\n"));
        assert!(!source.contains("Result<Builder>"));
        let sections = [
            "// Deny access by default.",
            "// Read-only paths.",
            "// Read and execute paths.",
            "// Read/write paths.",
            "// Device access.",
            "// Network access.",
            "// System call restrictions.",
        ];
        let positions: Vec<_> = sections
            .iter()
            .map(|section| source.find(section).unwrap())
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            source
                .lines()
                .filter(|line| line.trim_start().starts_with("//"))
                .all(|line| !line.to_lowercase().contains("stage"))
        );
    }

    #[test]
    fn generates_read_exec_loop_for_cwd_without_absolute_candidates() {
        let mut analysis = TraceAnalysis::default();
        analysis
            .cwd_grants
            .policy_read_paths
            .insert(PathBuf::from("missing.so"));
        normalize_filesystem_grants(&mut analysis);
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert_eq!(source.matches("for path in [").count(), 1);
        assert_eq!(
            source.matches("profile = profile.read_exec(path);").count(),
            1
        );
        assert!(source.contains("\n    ] {\n"));
        assert!(source.contains("let path = std::path::Path::new(path);"));
        assert!(!source.contains(".flatten()"));
        assert!(!source.contains("\"missing.so\""));
        assert!(!source.contains("profile.read_write("));
    }

    #[test]
    fn generates_profile_from_current_trace_schema() {
        let temp = tempfile::tempdir().unwrap();
        let traces = temp.path().join("traces");
        fs_err::create_dir_all(&traces).unwrap();
        fs_err::write(
            traces.join("worker-vm.42.jsonl"),
            concat!(
                "{\"event\":\"syscall\",\"syscall\":\"openat\",\"sys_nr\":257,",
                "\"args\":[4294967196,1,524288,0,0,0],",
                "\"decoded_args\":{\"path\":\"/usr/lib/libexample.so\"},\"result\":3}\n",
                "{\"event\":\"syscall\",\"syscall\":\"openat\",\"sys_nr\":257,",
                "\"args\":[4294967196,1,524288,0,0,0],",
                "\"decoded_args\":{\"path\":\"/sys/devices/system/cpu/online\"},\"result\":5}\n",
                "{\"event\":\"syscall\",\"syscall\":\"openat\",\"args\":[4294967196,1,2,0,0,0],",
                "\"decoded_args\":{\"path\":\"/denied/state/data\"},\"result\":-1,\"errno\":13}\n",
                "{\"event\":\"syscall\",\"syscall\":\"openat\",\"args\":[4294967196,1,0,0,0,0],",
                "\"decoded_args\":{\"path\":\"/usr/lib/libexample.so\"},\"result\":-2}\n",
                "{\"event\":\"syscall\",\"syscall\":\"newfstatat\",\"args\":[3,1,0,4096,0,0],",
                "\"decoded_args\":{\"path\":\"\",",
                "\"path_base\":\"/moved/libexample.so\"},\"result\":0}\n",
                "{\"event\":\"syscall\",\"syscall\":\"socket\",\"sys_nr\":41,",
                "\"args\":[2,1,0,0,0,0],\"decoded_args\":null,\"result\":4}\n",
                "{\"event\":\"syscall\",\"syscall\":\"connect\",\"sys_nr\":42,",
                "\"args\":[4,0,16,0,0,0],",
                "\"decoded_args\":{\"socket_address\":{\"family\":\"AF_INET\",",
                "\"address\":\"127.0.0.1\",\"port\":8080}},\"result\":0}\n",
                "{\"event\":\"syscall\",\"syscall\":\"keyctl\",\"sys_nr\":250,",
                "\"args\":[42,15,0,0,0,0],\"decoded_args\":null,\"result\":0}\n",
                "{\"event\":\"syscall\",\"syscall\":\"read\",\"sys_nr\":0,",
                "\"args\":[0,0,0,0,0,0],\"decoded_args\":null,\"result\":0}\n",
                "{\"event\":\"syscall\",\"syscall\":\"unknown\",\"sys_nr\":999,",
                "\"args\":[0,0,0,0,0,0],\"decoded_args\":null,\"result\":0}\n",
                "{\"event\":\"task_exit\",\"pid\":42,\"tid\":42,\"exit_code\":0,\"signal\":null}\n"
            ),
        )
        .unwrap();

        build_profile(&TraceOptions {
            trace_dir: traces,
            worker: "vm".to_string(),
            profile_dir: temp.path().to_path_buf(),
        })
        .unwrap();

        let generated = fs_err::read_to_string(temp.path().join("vm_worker.rs")).unwrap();
        assert!(generated.contains("\"acct\","));
        assert!(!generated.contains("\"bpf\","));
        assert!(!generated.contains("\"keyctl\","));
        assert!(has_generated_grant(
            &generated,
            "read",
            "/sys/devices/system/cpu/online"
        ));
        assert!(has_generated_grant(
            &generated,
            "read_exec",
            "/usr/lib/libexample.so"
        ));
        assert!(has_generated_grant(
            &generated,
            "read_write",
            "/denied/state/data"
        ));
        assert!(!has_generated_grant(&generated, "read_exec", "/usr/lib"));
        assert!(generated.contains(".network(Network::Loopback)"));
        assert!(generated.starts_with(
            "// Automatically generated sandbox profile for vm worker\n\nuse crate::Builder;"
        ));
        assert!(!generated.contains("Observed filesystem accesses"));
        let log = fs_err::read_to_string(temp.path().join("vm_worker.log")).unwrap();
        assert!(log.contains("Generated by sandbox_profiler from 1 trace file(s)."));
        assert!(log.contains("Observed filesystem accesses"));
        assert!(log.contains("Observed network accesses"));
        assert!(log.contains("Observed syscalls"));
        assert!(!log.contains("Filesystem policy access omissions"));
        assert!(log.contains("/denied/state/data, RW, EACCES"));
        assert!(log.contains("/usr/lib/libexample.so, RO, ENOENT"));
        assert!(log.contains("/usr/lib/libexample.so, RO, SUCCESS"));
        assert!(log.contains("/moved/libexample.so, RO, SUCCESS"));
        assert!(log.contains("/sys/devices/system/cpu/online, RO, SUCCESS"));
        assert!(log.contains("127.0.0.1:8080 (endpoint)"));
        assert!(log.contains("AF_INET (address family)"));
        assert!(!log.contains("did not succeed"));
        assert!(!log.contains("(RO|"));
        assert!(log.contains("Syscalls denied by policy but used by the worker:\n- keyctl"));
        assert!(!log.contains("Configured syscall denial list"));
        assert!(!log.contains("Generated syscall denial list"));
        assert!(generated.contains("Syscalls::deny([\n"));
        assert!(generated.contains(".name(\"vm_worker\")"));
        assert!(!log.contains("- read\n"));
        assert!(!log.contains("unknown(999)"));
        assert!(log.contains(
            "Observed syscalls:\n- connect\n- keyctl\n- newfstatat\n- openat\n- socket\n"
        ));
    }

    #[test]
    fn mandatory_denials_remain_when_observed() {
        let mut trace_analysis = TraceAnalysis::default();
        trace_analysis.observed_syscalls.insert("kill".to_string());
        let denylist = [
            sandbox::DeniedSyscall {
                name: "kill",
                enforcement: sandbox::Enforcement::Mandatory,
                reason: None,
            },
            sandbox::DeniedSyscall {
                name: "tkill",
                enforcement: sandbox::Enforcement::Optional,
                reason: None,
            },
        ];
        trace_analysis.observed_syscalls.insert("tkill".to_string());

        assert_eq!(
            generate_syscall_denials(&denylist, &trace_analysis),
            ["kill".to_string()]
        );
    }

    #[test]
    fn profile_trace_syscalls_resolve_with_sandbox_mapping() {
        let syscalls = pal_tracer::get_syscalls_to_trace().unwrap();

        assert_eq!(
            syscalls.get(&libc::SYS_openat).map(String::as_str),
            Some("openat")
        );
        assert_eq!(
            syscalls.get(&libc::SYS_keyctl).map(String::as_str),
            Some("keyctl")
        );
    }

    #[test]
    fn tracks_open_flags_metadata_and_failed_accesses() {
        let cases = [
            ("read", 0, 5),
            ("read-write", O_RDWR, 6),
            ("create", O_CREAT, 7),
            ("append", O_APPEND, 8),
            ("truncate", O_TRUNC, 9),
            ("temporary", O_TMPFILE, 10),
            ("failed", O_WRONLY, -13),
        ];
        let mut events = cases
            .iter()
            .map(|(name, flags, retval)| {
                let path = format!("/captured-only/{name}");
                serde_json::json!({
                    "event": "syscall", "syscall": "open",
                    "args": [12345, flags, 0o755, 0, 0, 0], "result": retval,
                    "decoded_args": {"path": path},
                    "opened_file": if *retval >= 0 {
                        serde_json::json!({
                            "path": path, "file_type": "regular_file", "mode": 0o100640
                        })
                    } else {
                        Value::Null
                    }
                })
            })
            .collect::<Vec<_>>();
        events.push(serde_json::json!({
            "event": "syscall", "syscall": "open",
            "args": [12345, 0, 0, 0, 0, 0], "result": 11,
            "opened_file": {
                "path": "/captured-only/device", "file_type": "character_device"
            }
        }));
        let analysis = analyze_events(&events);
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        for (name, flags, retval) in cases {
            let path = format!("/captured-only/{name}");
            assert!(has_generated_grant(
                &source,
                if flags == 0 { "read" } else { "read_write" },
                &path
            ));
            assert!(analysis.observed_filesystem_paths.contains(&format!(
                "{path}, {}, {}",
                if flags == 0 { "RO" } else { "RW" },
                if retval >= 0 { "SUCCESS" } else { "EACCES" }
            )));
            if retval >= 0 {
                assert_eq!(
                    analysis.fd_to_path_map.get(&retval),
                    Some(&TrackedFd::Filesystem {
                        absolute_path: PathBuf::from(path),
                        cwd_relative_path: None,
                    })
                );
            }
        }
        assert_eq!(analysis.fd_to_path_map.len(), 7);
        assert!(has_generated_grant(
            &source,
            "device",
            "/captured-only/device"
        ));
    }

    #[test]
    fn tracks_relative_open_directory_through_dup_and_openat() {
        let analysis = analyze_events(&[
            serde_json::json!({
                "event": "trace_started", "cwd": "/captured-only/work"
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "open",
                "args": [12345, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": {
                    "path": "state", "path_base": "/captured-only/work"
                },
                "opened_file": {
                    "path": "/captured-only/work/state", "file_type": "directory"
                }
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "dup",
                "args": [5, 0, 0, 0, 0, 0], "result": 7
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "close",
                "args": [5, 0, 0, 0, 0, 0], "result": 0
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [7, 0, 0, 0, 0, 0], "result": 8,
                "decoded_args": {"path": "data"},
                "opened_file": {
                    "path": "/captured-only/work/state/data", "file_type": "regular_file"
                }
            }),
        ]);
        assert!(!analysis.fd_to_path_map.contains_key(&5));
        for (fd, relative) in [(7, "state"), (8, "state/data")] {
            assert_eq!(
                analysis.fd_to_path_map.get(&fd),
                Some(&TrackedFd::Filesystem {
                    absolute_path: Path::new("/captured-only/work").join(relative),
                    cwd_relative_path: Some(PathBuf::from(relative)),
                })
            );
            assert!(
                analysis
                    .cwd_grants
                    .policy_read_paths
                    .contains(Path::new(relative))
            );
        }
        assert!(analysis.absolute_grants.policy_read_paths.is_empty());
    }

    #[test]
    fn classifies_write_and_implicit_paths() {
        let mut trace_analysis = TraceAnalysis::default();
        track_filesystem_path(
            "openat",
            [AT_FDCWD, 0, O_RDWR | O_CREAT, 0, 0, 0],
            FilePath {
                syscall_path_arg: "/var/lib/openvmm/state",
                ..Default::default()
            },
            Some(5),
            None,
            &mut trace_analysis,
        );
        track_filesystem_path(
            "newfstatat",
            [AT_FDCWD, 0, 0, 0, 0, 0],
            FilePath {
                syscall_path_arg: "/proc/self/maps",
                ..Default::default()
            },
            Some(0),
            None,
            &mut trace_analysis,
        );
        normalize_filesystem_grants(&mut trace_analysis);

        assert_eq!(
            trace_analysis.absolute_grants.policy_read_write_paths,
            BTreeSet::from([PathBuf::from("/var/lib/openvmm/state")])
        );
        assert!(trace_analysis.absolute_grants.policy_read_paths.is_empty());
        assert_eq!(
            trace_analysis.observed_filesystem_paths,
            BTreeSet::from([
                "/proc/self/maps, RO, SUCCESS".to_string(),
                "/var/lib/openvmm/state, RW, SUCCESS".to_string(),
            ])
        );
    }

    #[test]
    fn observed_files_do_not_grant_their_parent_directory() {
        let analysis = analyze_events(&[
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": {"path": "/etc/hosts"},
                "opened_file": {"file_type": "regular_file", "path": "/etc/hosts"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 6,
                "decoded_args": {"path": "/etc/hostname"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "/etc/missing"}, "opened_file": null
            }),
        ]);
        assert_eq!(
            analysis.absolute_grants.policy_read_paths,
            BTreeSet::from([
                PathBuf::from("/etc/hosts"),
                PathBuf::from("/etc/hostname"),
                PathBuf::from("/etc/missing"),
            ])
        );
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert!(!has_generated_grant(&source, "read_exec", "/etc"));
    }

    #[test]
    fn observed_read_directory_allows_non_executable_exact_write_exception() {
        let analysis = analyze_events(&[
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": {"path": "/captured-only/config"},
                "opened_file": {"file_type": "directory", "path": "/captured-only/config"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": -13,
                "decoded_args": {"path": "/captured-only/config/state"}
            }),
        ]);
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert!(has_generated_grant(
            &source,
            "read",
            "/captured-only/config"
        ));
        assert!(has_generated_grant(
            &source,
            "read_write",
            "/captured-only/config/state"
        ));
        assert!(!source.contains(".read_exec("));
    }

    #[test]
    fn classifies_successful_regular_files_using_captured_execute_bits() {
        let mut events = Vec::new();
        let cases = [
            ("plain", "openat", Some(0o100644), 5, 0, "read"),
            ("owner-exec", "openat", Some(0o100100), 5, 0, "read_exec"),
            ("group-exec", "statx", Some(0o100010), 0, 0, "read_exec"),
            (
                "other-exec",
                "newfstatat",
                Some(0o100001),
                0,
                0,
                "read_exec",
            ),
            ("access-only", "faccessat2", Some(0o100400), 0, 0, "read"),
            ("legacy", "openat", None, 5, 0, "read_exec"),
            ("failed", "openat", Some(0o100644), -13, 0, "read_exec"),
            (
                "writable-exec",
                "openat",
                Some(0o100755),
                5,
                O_RDWR,
                "read_write",
            ),
        ];
        for (name, syscall, mode, retval, flags, _) in cases {
            let path = format!("/captured-only/{name}");
            let metadata = serde_json::json!({
                "file_type": "regular_file", "mode": mode, "path": path
            });
            events.push(serde_json::json!({
                "event": "syscall", "syscall": syscall,
                "args": [AT_FDCWD, 0, flags, 0, 0, 0], "result": retval,
                "decoded_args": {"path": path},
                "opened_file": if syscall == "openat" { metadata.clone() } else { Value::Null },
                "path_metadata": if syscall != "openat" { metadata } else { Value::Null }
            }));
        }
        for (name, metadata, method) in [
            (
                "directory",
                serde_json::json!({"file_type": "directory", "mode": 0o40755}),
                "read_exec",
            ),
            (
                "missing-mode",
                serde_json::json!({"file_type": "regular_file"}),
                "read_exec",
            ),
            (
                "invalid-mode",
                serde_json::json!({"file_type": "regular_file", "mode": "0644"}),
                "read_exec",
            ),
        ] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": {"path": format!("/captured-only/{name}")},
                "opened_file": metadata
            }));
            let analysis = analyze_events(&events);
            let source = render_profile("vm", "vm_worker", &analysis, &[]);
            assert!(has_generated_grant(
                &source,
                method,
                &format!("/captured-only/{name}")
            ));
        }
        let mut analysis = analyze_events(&events);
        normalize_filesystem_grants(&mut analysis);
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        for (name, _, _, _, _, method) in cases {
            let path = format!("/captured-only/{name}");
            assert!(
                has_generated_grant(&source, method, &path),
                "{path}: {source}"
            );
            if method == "read" {
                assert!(!has_generated_grant(&source, "read_exec", &path));
            }
        }
    }

    #[test]
    fn executable_mode_evidence_is_order_independent_and_survives_parent_pruning() {
        let mut events = vec![
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": {"path": "/captured-only"},
                "opened_file": {"file_type": "directory", "mode": 0o40755}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 6,
                "decoded_args": {"path": "/captured-only/data"},
                "opened_file": {"file_type": "regular_file", "mode": 0o100644}
            }),
        ];
        for mode in [0o100755, 0o100644] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 0,
                "decoded_args": {"path": "/captured-only/library"},
                "path_metadata": {"file_type": "regular_file", "mode": mode}
            }));
        }
        for _ in 0..2 {
            let mut analysis = analyze_events(&events);
            normalize_filesystem_grants(&mut analysis);
            let source = render_profile("vm", "vm_worker", &analysis, &[]);
            assert!(has_generated_grant(&source, "read", "/captured-only"));
            assert!(has_generated_grant(
                &source,
                "read_exec",
                "/captured-only/library"
            ));
            assert!(!has_generated_grant(&source, "read_exec", "/captured-only"));
            events.reverse();
        }
    }

    #[test]
    fn resolves_paths_through_duplicated_filesystem_fds() {
        let mut trace_analysis = TraceAnalysis::default();
        track_filesystem_path(
            "openat",
            [AT_FDCWD, 0, 0, 0, 0, 0],
            FilePath {
                syscall_path_arg: "/var/lib/openvmm",
                ..Default::default()
            },
            Some(5),
            None,
            &mut trace_analysis,
        );
        track_fd_lifecycle("dup", [5, 0, 0, 0, 0, 0], Some(8), &mut trace_analysis);
        track_fd_lifecycle("dup2", [8, 10, 0, 0, 0, 0], Some(10), &mut trace_analysis);
        track_fd_lifecycle("fcntl", [10, 0, 0, 0, 0, 0], Some(12), &mut trace_analysis);
        track_filesystem_path(
            "openat",
            [12, 0, O_RDWR, 0, 0, 0],
            FilePath {
                syscall_path_arg: "state/../state/data",
                ..Default::default()
            },
            Some(9),
            None,
            &mut trace_analysis,
        );

        assert_eq!(
            trace_analysis
                .fd_to_path_map
                .get(&8)
                .and_then(TrackedFd::absolute_path),
            Some(&PathBuf::from("/var/lib/openvmm"))
        );
        assert_eq!(
            trace_analysis
                .fd_to_path_map
                .get(&10)
                .and_then(TrackedFd::absolute_path),
            Some(&PathBuf::from("/var/lib/openvmm"))
        );
        assert_eq!(
            trace_analysis
                .fd_to_path_map
                .get(&12)
                .and_then(TrackedFd::absolute_path),
            Some(&PathBuf::from("/var/lib/openvmm"))
        );
        assert_eq!(
            trace_analysis
                .fd_to_path_map
                .get(&9)
                .and_then(TrackedFd::absolute_path),
            Some(&PathBuf::from("/var/lib/openvmm/state/data"))
        );
        assert!(
            trace_analysis
                .observed_filesystem_paths
                .contains("/var/lib/openvmm/state/data, RW, SUCCESS")
        );
        assert!(
            trace_analysis
                .absolute_grants
                .policy_read_write_paths
                .contains(Path::new("/var/lib/openvmm/state/data"))
        );

        track_fd_lifecycle("close", [12, 0, 0, 0, 0, 0], Some(0), &mut trace_analysis);
        track_filesystem_path(
            "newfstatat",
            [12, 0, 0, 0, 0, 0],
            FilePath {
                syscall_path_arg: "unresolved",
                ..Default::default()
            },
            Some(-1),
            None,
            &mut trace_analysis,
        );

        assert!(!trace_analysis.fd_to_path_map.contains_key(&12));
        assert!(
            trace_analysis
                .observed_filesystem_paths
                .contains("unresolved, RO, EPERM")
        );
    }

    #[test]
    fn descriptor_replacement_preserves_resource_kind_and_metadata() {
        let filesystem = TrackedFd::Filesystem {
            absolute_path: PathBuf::from("/capture/worker/config"),
            cwd_relative_path: Some(PathBuf::from("config")),
        };
        let network = TrackedFd::Network {
            scope: sandbox::Network::Loopback,
        };
        let mut analysis = TraceAnalysis::default();
        analysis.fd_to_path_map.insert(3, network.clone());
        analysis.fd_to_path_map.insert(7, filesystem.clone());
        analysis.fd_to_path_map.insert(9, filesystem.clone());

        track_fd_lifecycle("dup2", [3, 7, 0, 0, 0, 0], Some(7), &mut analysis);
        assert_eq!(analysis.fd_to_path_map.get(&7), Some(&network));
        track_network_access(
            "sendto",
            [7, 0, 0, 0, 0, 0],
            Some(1),
            None,
            None,
            &mut analysis,
        );
        assert_eq!(analysis.policy_network, sandbox::Network::Loopback);

        track_fd_lifecycle("dup3", [9, 7, 0, 0, 0, 0], Some(7), &mut analysis);
        assert_eq!(analysis.fd_to_path_map.get(&7), Some(&filesystem));
        track_fd_lifecycle("dup2", [7, 7, 0, 0, 0, 0], Some(7), &mut analysis);
        assert_eq!(analysis.fd_to_path_map.get(&7), Some(&filesystem));

        track_fd_lifecycle("dup2", [3, 7, 0, 0, 0, 0], Some(-9), &mut analysis);
        map_fd_to_path(3, None, &mut analysis);
        track_fd_lifecycle("close", [7, 0, 0, 0, 0, 0], Some(-9), &mut analysis);
        assert_eq!(analysis.fd_to_path_map.get(&7), Some(&filesystem));
        track_fd_lifecycle("close", [7, 0, 0, 0, 0, 0], Some(0), &mut analysis);
        assert!(!analysis.fd_to_path_map.contains_key(&7));

        track_fd_lifecycle("dup2", [99, 3, 0, 0, 0, 0], Some(3), &mut analysis);
        assert!(!analysis.fd_to_path_map.contains_key(&3));
    }

    #[test]
    fn resolves_recorded_bases_for_relative_paths() {
        let trace_analysis = analyze_events(&[
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {
                    "path": "glibc-hwcaps/x86-64-v2/libgcc_s.so.1",
                    "path_base": "/work"
                }
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [7, 0, 0, 0, 0, 0], "result": 8,
                "decoded_args": {"path": "plugin.so", "path_base": "/opt/libs"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 9,
                "decoded_args": {"path": "settings", "path_base": "/work/next/config"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "renameat2",
                "args": [7, 0, 10, 0, 0, 0], "result": 0,
                "decoded_args": {
                    "path": "items/old", "path_base": "/source",
                    "path2": "items/new", "path2_base": "/destination"
                }
            }),
        ]);

        assert_eq!(
            trace_analysis.observed_filesystem_paths,
            BTreeSet::from([
                "/work/glibc-hwcaps/x86-64-v2/libgcc_s.so.1, RO, ENOENT".to_string(),
                "/opt/libs/plugin.so, RO, SUCCESS".to_string(),
                "/work/next/config/settings, RO, SUCCESS".to_string(),
                "/source/items/old, RW, SUCCESS".to_string(),
                "/destination/items/new, RW, SUCCESS".to_string(),
            ])
        );
        assert_eq!(
            trace_analysis.absolute_grants.policy_read_paths,
            BTreeSet::from([PathBuf::from("/opt/libs/plugin.so"),])
        );
        assert_eq!(
            trace_analysis.cwd_grants.policy_read_paths,
            BTreeSet::from([
                PathBuf::from("next/config/settings"),
                PathBuf::from("glibc-hwcaps/x86-64-v2/libgcc_s.so.1"),
            ])
        );
        assert_eq!(
            trace_analysis.absolute_grants.policy_read_write_paths,
            BTreeSet::from([
                PathBuf::from("/source/items/old"),
                PathBuf::from("/destination/items/new"),
            ])
        );
    }

    #[test]
    fn failed_filesystem_accesses_keep_exact_grants_and_results() {
        let trace_analysis = analyze_events(&[
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "/missing/libraries/libexample.so"},
                "opened_file": null
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, O_RDWR | O_CREAT, 0, 0, 0], "result": -13,
                "decoded_args": {"path": "/denied/state/data"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "mkdirat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -17,
                "decoded_args": {"path": "/existing/directory"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "unlinkat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "/missing/state/data"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "renameat2",
                "args": [AT_FDCWD, 0, AT_FDCWD, 0, 0, 0], "result": -2,
                "decoded_args": {
                    "path": "/missing/source/old", "path2": "/missing/destination/new"
                }
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0],
                "decoded_args": {"path": "/unknown/result/file"}
            }),
        ]);

        assert_eq!(
            trace_analysis.observed_filesystem_paths,
            BTreeSet::from([
                "/missing/libraries/libexample.so, RO, ENOENT".to_string(),
                "/denied/state/data, RW, EACCES".to_string(),
                "/existing/directory, RW, EEXIST".to_string(),
                "/missing/state/data, RW, ENOENT".to_string(),
                "/missing/source/old, RW, ENOENT".to_string(),
                "/missing/destination/new, RW, ENOENT".to_string(),
                "/unknown/result/file, RO, UNKNOWN".to_string(),
            ])
        );
        assert_eq!(
            trace_analysis.absolute_grants.policy_read_paths,
            BTreeSet::from([
                PathBuf::from("/missing/libraries/libexample.so"),
                PathBuf::from("/unknown/result/file"),
            ])
        );
        assert_eq!(
            trace_analysis.absolute_grants.policy_read_write_paths,
            BTreeSet::from([
                PathBuf::from("/denied/state/data"),
                PathBuf::from("/existing/directory"),
                PathBuf::from("/missing/state/data"),
                PathBuf::from("/missing/source/old"),
                PathBuf::from("/missing/destination/new"),
            ])
        );
        assert!(trace_analysis.fd_to_path_map.is_empty());
    }

    #[test]
    fn requested_permissions_combine_without_tracking_failed_descriptors() {
        let mut trace_analysis = TraceAnalysis::default();
        track_filesystem_path(
            "openat",
            [AT_FDCWD, 0, O_RDWR | O_CREAT, 0, 0, 0],
            FilePath {
                syscall_path_arg: "/var/lib/openvmm/state",
                ..Default::default()
            },
            Some(-13),
            None,
            &mut trace_analysis,
        );
        track_filesystem_path(
            "openat",
            [AT_FDCWD, 0, 0, 0, 0, 0],
            FilePath {
                syscall_path_arg: "/var/lib/openvmm/state",
                ..Default::default()
            },
            Some(0),
            None,
            &mut trace_analysis,
        );

        normalize_filesystem_grants(&mut trace_analysis);
        assert!(trace_analysis.absolute_grants.policy_read_paths.is_empty());
        assert_eq!(
            trace_analysis.absolute_grants.policy_read_write_paths,
            BTreeSet::from([PathBuf::from("/var/lib/openvmm/state")])
        );
        assert!(!trace_analysis.fd_to_path_map.contains_key(&-13));
        assert_eq!(
            trace_analysis
                .fd_to_path_map
                .get(&0)
                .and_then(TrackedFd::absolute_path),
            Some(&PathBuf::from("/var/lib/openvmm/state"))
        );
    }

    #[test]
    fn recorded_bases_override_legacy_fd_tracking() {
        let mut events = vec![
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 8,
                "decoded_args": {"path": "/stale/base"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [8, 0, 0, 0, 0, 0], "result": 9,
                "decoded_args": {"path": "file", "path_base": "/moved/base"}
            }),
        ];
        for base in [
            Value::Null,
            serde_json::json!("relative"),
            serde_json::json!(42),
        ] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [8, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "unresolved", "path_base": base}
            }));
        }
        let trace_analysis = analyze_events(&events);

        assert_eq!(
            trace_analysis.observed_filesystem_paths,
            BTreeSet::from([
                "/stale/base, RO, SUCCESS".to_string(),
                "/moved/base/file, RO, SUCCESS".to_string(),
                "unresolved, RO, ENOENT".to_string(),
            ])
        );
    }

    #[test]
    fn records_empty_path_accesses_without_pathname_grants() {
        let trace_analysis = analyze_events(&[
            serde_json::json!({
                "event": "syscall", "syscall": "newfstatat",
                "args": [4, 0, 0, 4096, 0, 0], "result": 0,
                "decoded_args": {"path": "", "path_base": null}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [8, 0, 4096, 0, 0, 0], "result": 0,
                "decoded_args": {"path": ""}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [u64::MAX - 99, 0, O_RDWR, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "", "path_base": null}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "newfstatat",
                "args": [9, 0, 0, 4096, 0, 0],
                "decoded_args": {"path": ""}
            }),
        ]);

        assert_eq!(
            trace_analysis.observed_filesystem_paths,
            BTreeSet::from([
                "<NO_PATH_BASE; newfstatat; dirfd: 4>, RO, SUCCESS".to_string(),
                "<NO_PATH_BASE; newfstatat; dirfd: 9>, RO, UNKNOWN".to_string(),
                "<NO_PATH_BASE; openat; dirfd: AT_FDCWD>, RW, ENOENT".to_string(),
                "<NO_PATH_BASE; statx; dirfd: 8>, RO, SUCCESS".to_string(),
            ])
        );
        assert!(trace_analysis.absolute_grants.policy_read_paths.is_empty());
        assert!(
            trace_analysis
                .absolute_grants
                .policy_read_write_paths
                .is_empty()
        );
        assert!(trace_analysis.fd_to_path_map.is_empty());
    }

    #[test]
    fn observes_recorded_descriptor_targets_without_pathname_grants() {
        let mut events = Vec::new();
        for path_base in [
            "/inherited/file",
            "/work",
            "anon_inode:[eventpoll]",
            "/removed/file (deleted)",
        ] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 4096, 0, 0, 0], "result": 0,
                "decoded_args": {
                    "path": "", "path_base": path_base
                }
            }));
        }
        events.push(serde_json::json!({
            "event": "syscall", "syscall": "newfstatat",
            "args": [7, 0, 0, 4096, 0, 0], "result": -13, "errno": 13,
            "decoded_args": {"path": "", "path_base": "/denied/file"}
        }));
        for path_base in [Value::Null, serde_json::json!(42), serde_json::json!("")] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [8, 0, 4096, 0, 0, 0], "result": 0,
                "decoded_args": {"path": "", "path_base": path_base}
            }));
        }
        let trace_analysis = analyze_events(&events);
        assert_eq!(
            trace_analysis.observed_filesystem_paths,
            BTreeSet::from([
                "/inherited/file, RO, SUCCESS".to_string(),
                "/work, RO, SUCCESS".to_string(),
                "anon_inode:[eventpoll], RO, SUCCESS".to_string(),
                "/removed/file (deleted), RO, SUCCESS".to_string(),
                "/denied/file, RO, EACCES".to_string(),
                "<NO_PATH_BASE; statx; dirfd: 8>, RO, SUCCESS".to_string(),
            ])
        );
        assert!(trace_analysis.absolute_grants.policy_read_paths.is_empty());
        assert!(
            trace_analysis
                .absolute_grants
                .policy_read_write_paths
                .is_empty()
        );
        assert!(trace_analysis.fd_to_path_map.is_empty());
    }

    #[test]
    fn generates_exact_device_grants_from_captured_open_types() {
        let events = [
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [7, 0, O_RDWR, 0, 0, 0], "result": 5,
                "decoded_args": {"path": "vfio", "path_base": "/dev/vfio"},
                "opened_file": {"file_type": "character_device", "path": "/dev/vfio/vfio"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 6,
                "decoded_args": {"path": "/devices/alias"},
                "opened_file": {"file_type": "character_device", "path": "/dev/zero"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": 7,
                "decoded_args": {"path": "/captured-only/disks/vda"},
                "opened_file": {"file_type": "block_device", "path": "/captured-only/disks/vda"}
            }),
        ];
        let temp = tempfile::tempdir().unwrap();
        let traces = temp.path().join("traces");
        fs_err::create_dir(&traces).unwrap();
        fs_err::write(
            traces.join("worker-vm.42.jsonl"),
            events
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        )
        .unwrap();
        build_profile(&TraceOptions {
            trace_dir: traces,
            worker: "vm".to_string(),
            profile_dir: temp.path().join("profiles"),
        })
        .unwrap();
        let source =
            fs_err::read_to_string(temp.path().join("profiles").join("vm_worker.rs")).unwrap();
        assert!(!source.contains("profile.read("));
        assert!(!source.contains("profile.read_exec("));
        assert!(!source.contains("profile.read_write("));
        for path in [
            "/captured-only/disks/vda",
            "/dev/vfio/vfio",
            "/devices/alias",
        ] {
            assert!(has_generated_grant(&source, "device", path));
        }
        let log =
            fs_err::read_to_string(temp.path().join("profiles").join("vm_worker.log")).unwrap();
        assert!(log.contains("/dev/vfio/vfio, RW, SUCCESS"));
        assert!(log.contains("/devices/alias, RO, SUCCESS"));
        assert!(log.contains("/captured-only/disks/vda, RW, SUCCESS"));
    }

    #[test]
    fn preserves_device_exceptions_and_compatible_directory_grants() {
        let mut events = Vec::new();
        for (path, file_type, flags) in [
            ("/captured-only/devices", "directory", 0),
            ("/captured-only/devices/first", "character_device", O_RDWR),
            (
                "/captured-only/devices/writable/state",
                "regular_file",
                O_RDWR,
            ),
            (
                "/captured-only/devices/writable/second",
                "block_device",
                O_RDWR,
            ),
        ] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, flags, 0, 0, 0], "result": 5,
                "decoded_args": {"path": path},
                "opened_file": {"file_type": file_type, "path": path}
            }));
        }
        let mut analysis = analyze_events(&events);
        normalize_filesystem_grants(&mut analysis);
        assert_eq!(analysis.absolute_grants.policy_device_paths.len(), 2);
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert!(has_generated_grant(
            &source,
            "read",
            "/captured-only/devices"
        ));
        assert!(has_generated_grant(
            &source,
            "read_write",
            "/captured-only/devices/writable/state"
        ));
        assert!(!source.contains(".read_exec("));
        assert!(has_generated_grant(
            &source,
            "device",
            "/captured-only/devices/first"
        ));
        assert!(has_generated_grant(
            &source,
            "device",
            "/captured-only/devices/writable/second"
        ));
    }

    #[test]
    fn device_snapshots_grant_device_io_without_requiring_an_io_open() {
        let mut events = Vec::new();
        for (name, flags, retval, opened_file) in [
            (
                "path-only",
                O_PATH,
                5,
                serde_json::json!({
                    "file_type": "character_device", "path": "/devices/path-only"
                }),
            ),
            (
                "failed",
                O_RDWR,
                -13,
                serde_json::json!({
                    "file_type": "character_device", "path": "/devices/failed"
                }),
            ),
            (
                "missing-target",
                0,
                5,
                serde_json::json!({"file_type": "character_device"}),
            ),
            (
                "relative-target",
                0,
                5,
                serde_json::json!({
                    "file_type": "character_device", "path": "relative/device"
                }),
            ),
            (
                "deleted",
                0,
                5,
                serde_json::json!({
                    "file_type": "character_device", "path": "/devices/deleted (deleted)"
                }),
            ),
            ("unknown", 0, 5, serde_json::json!({"file_type": "unknown"})),
            ("null", 0, 5, Value::Null),
            ("malformed", 0, 5, serde_json::json!({"file_type": 42})),
            (
                "private",
                0,
                5,
                serde_json::json!({
                    "file_type": "character_device", "path": "/tmp/private-device"
                }),
            ),
        ] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, flags, 0, 0, 0], "result": retval,
                "decoded_args": {"path": format!("/devices/{name}")},
                "opened_file": opened_file
            }));
        }
        events.push(serde_json::json!({
            "event": "syscall", "syscall": "statx",
            "args": [5, 0, 4096, 0, 0, 0], "result": 0,
            "decoded_args": {"path": "", "path_base": "/devices/metadata-only"},
            "opened_file": {"file_type": "character_device", "path": "/devices/metadata-only"}
        }));
        let analysis = analyze_events(&events);
        assert_eq!(analysis.observed_filesystem_paths.len(), events.len());
        assert_eq!(
            analysis.absolute_grants.policy_device_paths,
            BTreeSet::from([
                PathBuf::from("/devices/path-only"),
                PathBuf::from("/devices/missing-target"),
                PathBuf::from("/devices/relative-target"),
                PathBuf::from("/devices/deleted"),
                PathBuf::from("/devices/private"),
            ])
        );
        assert_eq!(
            analysis.absolute_grants.policy_read_paths,
            BTreeSet::from([
                PathBuf::from("/devices/unknown"),
                PathBuf::from("/devices/null"),
                PathBuf::from("/devices/malformed"),
            ])
        );
        assert_eq!(
            analysis.absolute_grants.policy_read_write_paths,
            BTreeSet::from([PathBuf::from("/devices/failed")])
        );
    }

    #[test]
    fn uses_descriptor_snapshot_when_open_path_is_unavailable() {
        let analysis = analyze_events(&[
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": null,
                "opened_file": {"file_type": "character_device", "path": "/devices/unreadable"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": 6,
                "decoded_args": {"path": "relative", "path_base": null},
                "opened_file": {"file_type": "block_device", "path": "/devices/relative"}
            }),
        ]);
        assert_eq!(
            analysis.absolute_grants.policy_device_paths,
            BTreeSet::from([PathBuf::from("/devices/unreadable"),])
        );
        assert!(!analysis.cwd_relative_path_errors.is_empty());
        assert!(analysis.absolute_grants.policy_read_paths.is_empty());
        assert!(analysis.absolute_grants.policy_read_write_paths.is_empty());
    }

    #[test]
    fn known_non_device_objects_keep_ordinary_grants() {
        let events = [
            ("regular_file", "/dev/captured-regular"),
            ("directory", "/dev/captured-directory"),
            ("symlink", "/dev/captured-symlink"),
            ("fifo", "/captured-only/fifo"),
            ("socket", "/captured-only/socket"),
        ]
        .map(|(file_type, path)| {
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": 5,
                "decoded_args": {"path": path},
                "opened_file": {"file_type": file_type, "path": path}
            })
        });
        let analysis = analyze_events(&events);
        assert!(analysis.absolute_grants.policy_device_paths.is_empty());
        assert_eq!(
            analysis.absolute_grants.policy_read_write_paths,
            BTreeSet::from([
                PathBuf::from("/dev/captured-regular"),
                PathBuf::from("/dev/captured-directory"),
                PathBuf::from("/dev/captured-symlink"),
                PathBuf::from("/captured-only/fifo"),
                PathBuf::from("/captured-only/socket"),
            ])
        );
    }

    #[test]
    fn metadata_queries_grant_exact_device_io_paths() {
        let mut events = Vec::new();
        for (syscall, path, kind) in [
            ("statx", "/dev/vfio/vfio", "character_device"),
            ("newfstatat", "/captured-only/disks/vda", "block_device"),
        ] {
            events.push(serde_json::json!({
                "event": "syscall", "syscall": syscall,
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 0,
                "decoded_args": {"path": path},
                "path_metadata": {
                    "file_type": kind, "device_major": 1, "device_minor": 3
                }
            }));
        }
        events.push(serde_json::json!({
            "event": "syscall", "syscall": "statx",
            "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 0,
            "decoded_args": {"path": "alias", "path_base": "/devices"},
            "path_metadata": {"file_type": "character_device"}
        }));
        let mut analysis = analyze_events(&events);
        normalize_filesystem_grants(&mut analysis);
        assert_eq!(
            analysis.absolute_grants.policy_device_paths,
            BTreeSet::from([
                PathBuf::from("/dev/vfio/vfio"),
                PathBuf::from("/captured-only/disks/vda"),
            ])
        );
        assert_eq!(
            analysis.cwd_grants.policy_read_paths,
            BTreeSet::from([PathBuf::from(".")])
        );
        assert_eq!(
            analysis.cwd_grants.policy_device_paths,
            BTreeSet::from([PathBuf::from("alias")])
        );
        assert!(analysis.absolute_grants.policy_read_paths.is_empty());
        assert!(analysis.absolute_grants.policy_read_write_paths.is_empty());
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert!(has_generated_grant(&source, "device", "/dev/vfio/vfio"));
        assert!(has_generated_grant(
            &source,
            "device",
            "/captured-only/disks/vda"
        ));
        assert!(source.contains("cwd.to_str().unwrap_or_default()"));
        assert!(has_generated_grant(&source, "device", "alias"));
        assert!(source.contains("let resolved_path = cwd.join(path);"));
        assert_eq!(source.matches("profile.read_exec(path)").count(), 1);
    }

    #[test]
    fn device_grants_preserve_ancestors_regardless_of_io_open() {
        for opened in [false, true] {
            let mut events = vec![
                serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 4,
                    "decoded_args": {"path": "/dev"},
                    "opened_file": {"file_type": "directory", "path": "/dev"}
                }),
                serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -13,
                    "decoded_args": {"path": "/dev/null"}, "opened_file": null
                }),
                serde_json::json!({
                    "event": "syscall", "syscall": "statx",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 0,
                    "decoded_args": {"path": "/dev/null"},
                    "path_metadata": {"file_type": "character_device"}
                }),
            ];
            if opened {
                events.push(serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                    "decoded_args": {"path": "/dev/null"},
                    "opened_file": {"file_type": "character_device", "path": "/dev/null"}
                }));
                events.push(serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": -13,
                    "decoded_args": {"path": "/dev/null"}, "opened_file": null
                }));
            }
            let mut analysis = analyze_events(&events);
            normalize_filesystem_grants(&mut analysis);
            let source = render_profile("vm", "vm_worker", &analysis, &[]);
            assert!(has_generated_grant(&source, "read", "/dev"));
            assert!(!source.contains(".read_exec("));
            assert!(has_generated_grant(&source, "device", "/dev/null"));
            assert!(!has_generated_grant(&source, "read", "/dev/null"));
            assert!(!has_generated_grant(&source, "read_write", "/dev/null"));
        }
    }

    #[test]
    fn unknown_and_failed_dev_queries_grant_exact_device_paths() {
        let events = [
            (
                "/dev/failed",
                -2,
                serde_json::json!({"file_type": "character_device"}),
            ),
            (
                "/dev/unknown",
                0,
                serde_json::json!({"file_type": "unknown"}),
            ),
            ("/dev/null-metadata", 0, Value::Null),
            ("/dev/malformed", 0, serde_json::json!({"file_type": 42})),
            (
                "/proc/device",
                0,
                serde_json::json!({"file_type": "character_device"}),
            ),
            (
                "/tmp/device",
                0,
                serde_json::json!({"file_type": "block_device"}),
            ),
        ]
        .map(|(path, retval, metadata)| {
            serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": retval,
                "decoded_args": {"path": path}, "path_metadata": metadata
            })
        });
        let analysis = analyze_events(&events);
        assert_eq!(analysis.observed_filesystem_paths.len(), events.len());
        assert_eq!(
            analysis.absolute_grants.policy_device_paths,
            BTreeSet::from([
                PathBuf::from("/dev/failed"),
                PathBuf::from("/dev/unknown"),
                PathBuf::from("/dev/null-metadata"),
                PathBuf::from("/dev/malformed"),
            ])
        );
        assert!(analysis.absolute_grants.policy_read_paths.is_empty());
        assert!(analysis.absolute_grants.policy_read_write_paths.is_empty());
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        for path in &analysis.absolute_grants.policy_device_paths {
            assert!(has_generated_grant(
                &source,
                "device",
                path.to_str().unwrap()
            ));
        }
        assert!(!source.contains("profile.read_exec(path)"));
    }

    #[test]
    fn unknown_dev_paths_use_resolved_names_and_preserve_cwd_device_exceptions() {
        let mut analysis = analyze_events(&[
            serde_json::json!({"event": "trace_started", "cwd": "/dev"}),
            serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "sev", "path_base": "/dev"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [7, 0, O_RDWR, 0, 0, 0], "result": -13,
                "decoded_args": {"path": "vfio/vfio", "path_base": "/dev"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "/devices/unknown"}
            }),
        ]);
        normalize_filesystem_grants(&mut analysis);
        assert_eq!(
            analysis.cwd_grants.policy_device_paths,
            BTreeSet::from([PathBuf::from("sev")])
        );
        assert_eq!(
            analysis.absolute_grants.policy_device_paths,
            BTreeSet::from([PathBuf::from("/dev/vfio/vfio")])
        );
        assert_eq!(
            analysis.absolute_grants.policy_read_paths,
            BTreeSet::from([PathBuf::from("/devices/unknown")])
        );
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert!(has_generated_grant(&source, "device", "sev"));
        assert!(has_generated_grant(&source, "device", "/dev/vfio/vfio"));
        assert!(!has_generated_grant(&source, "read_exec", "sev"));
    }

    #[test]
    fn portable_grants_keep_anchors_and_minimize_observed_ancestors() {
        let mut analysis = analyze_events(&[
            serde_json::json!({"event": "trace_started", "cwd": "/capture/container-a"}),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": -13,
                "decoded_args": {"path": "state/data", "path_base": "/capture/container-a"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "statx",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 0,
                "decoded_args": {"path": "state", "path_base": "/capture/container-a"},
                "path_metadata": {"file_type": "directory"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 7,
                "decoded_args": {"path": "lib", "path_base": "/capture/container-a"},
                "opened_file": {"file_type": "directory", "path": "/capture/container-a/lib"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [7, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "plugin.so", "path_base": "/capture/container-a/lib"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [8, 0, 0, 0, 0, 0], "result": 9,
                "decoded_args": {"path": "outside.so", "path_base": "/opt/libs"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "links/../data", "path_base": "/capture/container-a"}
            }),
        ]);
        assert!(analysis.cwd_relative_path_errors.is_empty());
        normalize_filesystem_grants(&mut analysis);
        let source = render_profile("vm", "vm_worker", &analysis, &[]);
        assert!(source.contains("-> Builder"));
        assert!(source.contains("let cwd = std::env::current_dir().unwrap_or_default();"));
        assert!(source.contains("cwd.to_str().unwrap_or_default()"));
        for path in ["state", "state/data", "lib", "links/../data"] {
            assert!(!source.contains(&rust_string(path)));
        }
        assert!(has_generated_grant(
            &source,
            "read_exec",
            "/opt/libs/outside.so"
        ));
        assert!(!source.contains("/capture/container-a"));
        assert!(
            analysis
                .observed_filesystem_paths
                .contains("/capture/container-a/lib/plugin.so, RO, ENOENT")
        );
        assert!(!is_covered(
            Path::new("links/../data"),
            &BTreeSet::from([PathBuf::from("links")])
        ));
    }

    #[test]
    fn deduplicates_portable_paths_across_runs_without_absorbing_absolute_grants() {
        let temp = tempfile::tempdir().unwrap();
        for id in ["first", "second"] {
            let events = [
                serde_json::json!({"event": "trace_started", "cwd": format!("/capture/{id}")}),
                serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                    "decoded_args": {"path": "libc.so.6", "path_base": format!("/capture/{id}")}
                }),
                serde_json::json!({
                    "event": "syscall", "syscall": "statx",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 0,
                    "decoded_args": {"path": "/capture/first"},
                    "path_metadata": {"file_type": "directory"}
                }),
            ];
            fs_err::write(
                temp.path().join(format!("worker-vm.{id}.jsonl")),
                events
                    .iter()
                    .map(|event| format!("{event}\n"))
                    .collect::<String>(),
            )
            .unwrap();
        }
        build_profile(&TraceOptions {
            trace_dir: temp.path().to_path_buf(),
            worker: "vm".into(),
            profile_dir: temp.path().join("profiles"),
        })
        .unwrap();
        let source =
            fs_err::read_to_string(temp.path().join("profiles").join("vm_worker.rs")).unwrap();
        assert!(!source.contains("profile.read_write("));
        assert!(source.contains("profile.read_exec(path)"));
        assert_eq!(
            source.matches("cwd.to_str().unwrap_or_default()").count(),
            1
        );
        assert!(!source.contains("\"libc.so.6\""));
        let log =
            fs_err::read_to_string(temp.path().join("profiles").join("vm_worker.log")).unwrap();
        for id in ["first", "second"] {
            assert!(log.contains(&format!("/capture/{id}/libc.so.6, RO, ENOENT")));
        }
        assert!(has_generated_grant(&source, "read_exec", "/capture/first"));
    }

    #[test]
    fn rejects_cwd_lookups_outside_the_startup_anchor() {
        let analysis = analyze_events(&[
            serde_json::json!({"event": "trace_started", "cwd": "/capture/first"}),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                "decoded_args": {"path": "libc.so.6", "path_base": "/unrelated"}
            }),
        ]);
        assert!(!analysis.cwd_relative_path_errors.is_empty());
        assert!(analysis.absolute_grants.is_empty());
        assert!(analysis.cwd_grants.is_empty());
    }

    #[test]
    fn portable_fd_origins_follow_duplication_and_are_invalidated_on_replacement() {
        let mut analysis = analyze_events(&[
            serde_json::json!({"event": "trace_started", "cwd": "/capture/worker"}),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": 5,
                "decoded_args": {"path": "config", "path_base": "/capture/worker"},
                "opened_file": {"file_type": "directory", "path": "/capture/worker/config"}
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "dup",
                "args": [5, 0, 0, 0, 0, 0], "result": 8
            }),
            serde_json::json!({
                "event": "syscall", "syscall": "openat",
                "args": [8, 0, O_RDWR, 0, 0, 0], "result": -13,
                "decoded_args": {"path": "state", "path_base": "/capture/worker/config"}
            }),
        ]);
        assert!(
            analysis
                .cwd_grants
                .policy_read_write_paths
                .contains(Path::new("config/state"))
        );
        track_fd_lifecycle("dup2", [99, 8, 0, 0, 0, 0], Some(8), &mut analysis);
        assert!(!analysis.fd_to_path_map.contains_key(&8));
        track_fd_lifecycle("close", [5, 0, 0, 0, 0, 0], Some(0), &mut analysis);
        assert!(!analysis.fd_to_path_map.contains_key(&5));
    }

    #[test]
    fn minimization_keeps_stronger_children_independent_of_observation_order() {
        for parent_write in [false, true] {
            let mut events = vec![
                serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, if parent_write { O_RDWR } else { 0 }, 0, 0, 0], "result": -13,
                    "decoded_args": {"path": "/data"}
                }),
                serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, O_RDWR, 0, 0, 0], "result": -13,
                    "decoded_args": {"path": "/data/state"}
                }),
                serde_json::json!({
                    "event": "syscall", "syscall": "openat",
                    "args": [AT_FDCWD, 0, 0, 0, 0, 0], "result": -2,
                    "decoded_args": {"path": "/data/config"}
                }),
            ];
            for _ in 0..2 {
                let mut analysis = analyze_events(&events);
                normalize_filesystem_grants(&mut analysis);
                assert_eq!(
                    analysis.absolute_grants.policy_read_write_paths,
                    BTreeSet::from([PathBuf::from(if parent_write {
                        "/data"
                    } else {
                        "/data/state"
                    })])
                );
                assert_eq!(
                    analysis.absolute_grants.policy_read_paths,
                    if parent_write {
                        BTreeSet::new()
                    } else {
                        BTreeSet::from([PathBuf::from("/data")])
                    }
                );
                events.reverse();
            }
        }
    }

    fn analyze_events(events: &[Value]) -> TraceAnalysis {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trace.jsonl");
        let contents = events
            .iter()
            .map(|event| format!("{event}\n"))
            .collect::<String>();
        fs_err::write(&path, contents).unwrap();
        let mut trace_analysis = TraceAnalysis::default();
        ingest_trace(&path, &[], &mut trace_analysis).unwrap();
        trace_analysis
    }

    #[test]
    fn generates_loopback_network_policy() {
        let mut trace_analysis = TraceAnalysis::default();
        track_network_access(
            "socket",
            [AF_INET, 1, 0, 0, 0, 0],
            Some(4),
            None,
            None,
            &mut trace_analysis,
        );
        track_network_access(
            "connect",
            [4, 0, 0, 0, 0, 0],
            Some(0),
            None,
            Some(&serde_json::json!({
                "socket_address": {
                    "family": "AF_INET",
                    "address": "127.0.0.1",
                    "port": 8080
                }
            })),
            &mut trace_analysis,
        );
        track_network_access(
            "sendto",
            [4, 0, 0, 0, 0, 0],
            Some(12),
            None,
            None,
            &mut trace_analysis,
        );

        assert_eq!(trace_analysis.policy_network, sandbox::Network::Loopback);
    }

    #[test]
    fn generates_unrestricted_network_policy() {
        let mut trace_analysis = TraceAnalysis::default();
        track_network_access(
            "connect",
            [4, 0, 0, 0, 0, 0],
            Some(0),
            None,
            Some(&serde_json::json!({
                "socket_address": {
                    "family": "AF_INET6",
                    "address": "2001:db8::1",
                    "port": 443
                }
            })),
            &mut trace_analysis,
        );

        assert_eq!(
            trace_analysis.policy_network,
            sandbox::Network::Unrestricted
        );
    }
}
