// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build candidate OpenVMM sandbox profiles from worker syscall traces.

#![forbid(unsafe_code)]

use anyhow::Context;
use anyhow::ensure;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::BufRead;
use std::path::Path;
use std::path::PathBuf;

const AT_FDCWD: u64 = u32::MAX as u64 - 99;
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_TMPFILE: u64 = 0o20_200_000;
const AF_UNIX: u64 = 1;
const DEFAULT_SYSCALL_DENYLIST: [&str; 3] = ["kill", "tkill", "tgkill"];

/// Inputs used to generate one worker profile.
#[derive(Debug)]
pub struct BuildOptions {
    /// Directory containing worker trace JSONL files, recursively searched.
    pub trace_dir: PathBuf,
    /// Worker name used to select trace files and name the generated profile.
    pub worker: String,
    /// Directory where the generated Rust source file is written.
    pub output_dir: PathBuf,
}

/// Summary of a generated profile.
#[derive(Debug)]
pub struct BuildReport {
    /// Generated Rust source file.
    pub profile_path: PathBuf,
    /// Trace files consumed.
    pub trace_files: Vec<PathBuf>,
    /// Read-only directory grants emitted.
    pub read_paths: Vec<PathBuf>,
    /// Read-write directory grants emitted.
    pub read_write_paths: Vec<PathBuf>,
    /// Network operations observed in the trace.
    pub network_observations: Vec<String>,
    /// Filesystem behavior that was not converted into an explicit grant.
    pub filesystem_notes: Vec<String>,
    /// Syscall names observed in the trace.
    pub syscalls: Vec<String>,
    /// Default syscall denials that were not observed and were emitted.
    pub generated_syscall_denials: Vec<String>,
}

#[derive(Debug, Default)]
struct Evidence {
    read_paths: BTreeSet<PathBuf>,
    read_write_paths: BTreeSet<PathBuf>,
    network_observations: BTreeSet<String>,
    filesystem_notes: BTreeSet<String>,
    syscalls: BTreeSet<String>,
    unknown_syscall_nrs: BTreeSet<u64>,
    network_fds: BTreeSet<i64>,
}

/// Generate a sandbox profile template from worker trace evidence.
pub fn build_profile(options: &BuildOptions) -> anyhow::Result<BuildReport> {
    ensure!(
        options.trace_dir.is_dir(),
        "trace directory does not exist: {}",
        options.trace_dir.display()
    );

    let worker_file_name = sanitize_file_component(&options.worker);
    ensure!(!worker_file_name.is_empty(), "worker name is empty");
    let rust_identifier = sanitize_rust_identifier(&options.worker);
    let module_name = format!("{rust_identifier}_worker");
    let trace_files = find_worker_traces(&options.trace_dir, &worker_file_name)?;
    ensure!(
        !trace_files.is_empty(),
        "no JSONL traces for worker '{}' found under {}",
        options.worker,
        options.trace_dir.display()
    );

    let mut evidence = Evidence::default();
    for path in &trace_files {
        ingest_trace(path, &mut evidence)?;
    }
    normalize_grants(&mut evidence);

    fs_err::create_dir_all(&options.output_dir)
        .with_context(|| format!("failed to create {}", options.output_dir.display()))?;
    let profile_path = options.output_dir.join(format!("{module_name}.rs"));
    let source = render_profile(&options.worker, &module_name, &trace_files, &evidence);
    fs_err::write(&profile_path, source)
        .with_context(|| format!("failed to write {}", profile_path.display()))?;
    let generated_syscall_denials = generated_syscall_denials(&evidence);

    Ok(BuildReport {
        profile_path,
        trace_files,
        read_paths: evidence.read_paths.into_iter().collect(),
        read_write_paths: evidence.read_write_paths.into_iter().collect(),
        network_observations: evidence.network_observations.into_iter().collect(),
        filesystem_notes: evidence.filesystem_notes.into_iter().collect(),
        syscalls: evidence.syscalls.into_iter().collect(),
        generated_syscall_denials: generated_syscall_denials
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
}

fn find_worker_traces(root: &Path, worker: &str) -> anyhow::Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut traces = Vec::new();
    let current_prefix = format!("worker-{worker}.");
    let legacy_prefix = format!("{worker}.");

    while let Some(dir) = pending.pop() {
        for entry in fs_err::read_dir(&dir)
            .with_context(|| format!("failed to read trace directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
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
    traces.sort();
    Ok(traces)
}

fn ingest_trace(path: &Path, evidence: &mut Evidence) -> anyhow::Result<()> {
    let file = fs_err::File::open(path)
        .with_context(|| format!("failed to open trace {}", path.display()))?;
    for (index, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line =
            line.with_context(|| format!("failed to read {}:{}", path.display(), index + 1))?;
        let event: Value = serde_json::from_str(&line)
            .with_context(|| format!("invalid JSON at {}:{}", path.display(), index + 1))?;
        if event["event"] != "syscall" {
            continue;
        }

        let syscall = event["syscall"].as_str().unwrap_or("unknown");
        let sys_nr = event["sys_nr"]
            .as_u64()
            .or_else(|| event["number"].as_u64());
        if syscall == "unknown" {
            if let Some(sys_nr) = sys_nr {
                if let Some(name) = default_syscall_name(sys_nr) {
                    evidence.syscalls.insert(name.to_string());
                } else {
                    evidence.unknown_syscall_nrs.insert(sys_nr);
                }
            }
        } else {
            evidence.syscalls.insert(syscall.to_string());
        }

        let args = parse_args(&event);
        observe_network(syscall, args, event["result"].as_i64(), evidence);

        let decoded = event.get("decoded_args").or_else(|| event.get("details"));
        let Some(path) = decoded
            .and_then(|decoded| decoded.get("path"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        observe_path(syscall, args, path, evidence);
    }
    Ok(())
}

fn parse_args(event: &Value) -> [u64; 6] {
    let mut args = [0; 6];
    if let Some(values) = event["args"].as_array() {
        for (destination, value) in args.iter_mut().zip(values) {
            *destination = value.as_u64().unwrap_or_default();
        }
    }
    args
}

fn observe_path(syscall: &str, args: [u64; 6], raw_path: &str, evidence: &mut Evidence) {
    let path = Path::new(raw_path);
    if !path.is_absolute() {
        let dirfd = if syscall == "execve" {
            None
        } else {
            Some(args[0])
        };
        evidence.filesystem_notes.insert(format!(
            "Relative path `{raw_path}` from `{syscall}` was not converted to a grant (dirfd: {}).",
            dirfd.map_or_else(|| "n/a".to_string(), format_dirfd)
        ));
        return;
    }

    if path.starts_with("/proc") {
        evidence.filesystem_notes.insert(format!(
            "`{}` is provided by the sandbox's implicit `/proc` mount.",
            path.display()
        ));
        return;
    }
    if path.starts_with("/tmp") {
        evidence.filesystem_notes.insert(format!(
            "`{}` is under the sandbox's implicit empty writable `/tmp`; verify that host contents are not required.",
            path.display()
        ));
        return;
    }

    let grant_path = directory_grant(path);
    if grant_path == Path::new("/") {
        evidence.filesystem_notes.insert(format!(
            "`{}` would require granting `/`; no filesystem grant was generated.",
            path.display()
        ));
        return;
    }

    if path_is_written(syscall, args) {
        evidence.read_write_paths.insert(grant_path);
    } else {
        evidence.read_paths.insert(grant_path);
    }
}

fn directory_grant(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(Path::new("/")).to_path_buf()
    }
}

fn path_is_written(syscall: &str, args: [u64; 6]) -> bool {
    match syscall {
        "openat" => {
            let flags = args[2];
            matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR)
                || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0
                || flags & O_TMPFILE == O_TMPFILE
        }
        "mkdirat" | "unlinkat" | "renameat2" => true,
        _ => false,
    }
}

fn observe_network(syscall: &str, args: [u64; 6], result: Option<i64>, evidence: &mut Evidence) {
    match syscall {
        "socket" => {
            let domain = args[0];
            if domain != AF_UNIX {
                evidence.network_observations.insert(format!(
                    "`socket` requested address family {}.",
                    address_family_name(domain)
                ));
                if let Some(fd) = result.filter(|fd| *fd >= 0) {
                    evidence.network_fds.insert(fd);
                }
            }
        }
        "accept4" => {
            if evidence.network_fds.contains(&(args[0] as i64)) {
                evidence
                    .network_observations
                    .insert(format!("`accept4` used network fd {}.", args[0]));
                if let Some(fd) = result.filter(|fd| *fd >= 0) {
                    evidence.network_fds.insert(fd);
                }
            }
        }
        "connect" | "bind" | "listen" | "sendmsg" | "recvmsg" => {
            if evidence.network_fds.contains(&(args[0] as i64)) {
                evidence
                    .network_observations
                    .insert(format!("`{syscall}` used network fd {}.", args[0]));
            }
        }
        "dup" => copy_network_fd(args[0], result, evidence),
        "dup3" => copy_network_fd(
            args[0],
            result.filter(|fd| *fd >= 0).map(|_| args[1] as i64),
            evidence,
        ),
        "fcntl" if matches!(args[1], 0 | 1030) => copy_network_fd(args[0], result, evidence),
        "close" => {
            evidence.network_fds.remove(&(args[0] as i64));
        }
        _ => {}
    }
}

fn copy_network_fd(source: u64, destination: Option<i64>, evidence: &mut Evidence) {
    if evidence.network_fds.contains(&(source as i64)) {
        if let Some(destination) = destination.filter(|fd| *fd >= 0) {
            evidence.network_fds.insert(destination);
        }
    }
}

fn normalize_grants(evidence: &mut Evidence) {
    evidence
        .read_paths
        .retain(|path| !is_covered(path, &evidence.read_write_paths));
    evidence.read_paths = collapse_paths(&evidence.read_paths);
    evidence.read_write_paths = collapse_paths(&evidence.read_write_paths);
}

fn collapse_paths(paths: &BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
    let mut collapsed = BTreeSet::new();
    for path in paths {
        if !is_covered(path, &collapsed) {
            collapsed.insert(path.clone());
        }
    }
    collapsed
}

fn is_covered(path: &Path, grants: &BTreeSet<PathBuf>) -> bool {
    grants.iter().any(|grant| path.starts_with(grant))
}

fn render_profile(
    worker: &str,
    function_name: &str,
    trace_files: &[PathBuf],
    evidence: &Evidence,
) -> String {
    let generated_denials = generated_syscall_denials(evidence);
    let mut source = String::new();
    writeln!(source, "// Copyright (c) Microsoft Corporation.").unwrap();
    writeln!(source, "// Licensed under the MIT License.\n").unwrap();
    writeln!(
        source,
        "//! Automatically generated sandbox profile for `{worker}`."
    )
    .unwrap();
    writeln!(source, "//!").unwrap();
    writeln!(
        source,
        "//! Generated by `sandbox_profile_builder` from {} trace file(s).",
        trace_files.len()
    )
    .unwrap();
    write_comment_list(
        &mut source,
        "Observed syscalls",
        evidence.syscalls.iter().cloned().chain(
            evidence
                .unknown_syscall_nrs
                .iter()
                .map(|nr| format!("unknown({nr})")),
        ),
    );
    write_comment_list(
        &mut source,
        "Default syscall denial list",
        DEFAULT_SYSCALL_DENYLIST.map(str::to_string),
    );
    write_comment_list(
        &mut source,
        "Generated syscall denial list",
        generated_denials.iter().map(|name| (*name).to_string()),
    );
    write_comment_list(
        &mut source,
        "Network observations",
        evidence.network_observations.iter().cloned(),
    );
    write_comment_list(
        &mut source,
        "Filesystem notes",
        evidence.filesystem_notes.iter().cloned(),
    );
    writeln!(source).unwrap();
    writeln!(source, "use crate::Builder;").unwrap();
    writeln!(source, "use crate::Network;").unwrap();
    writeln!(source, "use crate::Profile;").unwrap();
    writeln!(source, "use crate::Syscalls;\n").unwrap();
    writeln!(
        source,
        "/// Automatically generated profile from observed worker behavior."
    )
    .unwrap();
    writeln!(source, "pub fn {function_name}() -> Builder {{").unwrap();
    writeln!(source, "    Profile::deny_all()").unwrap();
    writeln!(source, "        .name({})", rust_string(function_name)).unwrap();
    for path in &evidence.read_paths {
        writeln!(
            source,
            "        .read({})",
            rust_string(&path.display().to_string())
        )
        .unwrap();
    }
    for path in &evidence.read_write_paths {
        writeln!(
            source,
            "        .read_write({})",
            rust_string(&path.display().to_string())
        )
        .unwrap();
    }
    write!(source, "        .syscalls(Syscalls::Deny(&[").unwrap();
    for (index, syscall) in generated_denials.iter().enumerate() {
        if index != 0 {
            write!(source, ", ").unwrap();
        }
        write!(source, "{}", rust_string(syscall)).unwrap();
    }
    writeln!(source, "]))").unwrap();
    writeln!(source, "        .network(Network::None)").unwrap();
    writeln!(source, "}}").unwrap();
    source
}

fn write_comment_list(
    output: &mut String,
    heading: &str,
    values: impl IntoIterator<Item = String>,
) {
    writeln!(output, "//!").unwrap();
    writeln!(output, "//! {heading}:").unwrap();
    let mut any = false;
    for value in values {
        any = true;
        writeln!(output, "//! - {value}").unwrap();
    }
    if !any {
        writeln!(output, "//! - None.").unwrap();
    }
}

fn generated_syscall_denials(evidence: &Evidence) -> Vec<&'static str> {
    DEFAULT_SYSCALL_DENYLIST
        .into_iter()
        .filter(|name| !syscall_was_observed(name, evidence))
        .collect()
}

fn syscall_was_observed(name: &str, evidence: &Evidence) -> bool {
    if evidence.syscalls.contains(name) {
        return true;
    }
    default_syscall_nr(name).is_some_and(|nr| evidence.unknown_syscall_nrs.contains(&nr))
}

#[cfg(target_os = "linux")]
fn default_syscall_nr(name: &str) -> Option<u64> {
    match name {
        "kill" => Some(libc::SYS_kill as u64),
        "tkill" => Some(libc::SYS_tkill as u64),
        "tgkill" => Some(libc::SYS_tgkill as u64),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn default_syscall_name(sys_nr: u64) -> Option<&'static str> {
    DEFAULT_SYSCALL_DENYLIST
        .into_iter()
        .find(|name| default_syscall_nr(name) == Some(sys_nr))
}

#[cfg(not(target_os = "linux"))]
fn default_syscall_nr(_name: &str) -> Option<u64> {
    None
}

#[cfg(not(target_os = "linux"))]
fn default_syscall_name(_sys_nr: u64) -> Option<&'static str> {
    None
}

fn sanitize_file_component(worker: &str) -> String {
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

fn sanitize_rust_identifier(worker: &str) -> String {
    sanitize_file_component(worker).replace('-', "_")
}

fn format_dirfd(dirfd: u64) -> String {
    if dirfd == AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        dirfd.to_string()
    }
}

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

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
                "{\"event\":\"syscall\",\"syscall\":\"socket\",\"sys_nr\":41,",
                "\"args\":[2,1,0,0,0,0],\"decoded_args\":null,\"result\":4}\n",
                "{\"event\":\"syscall\",\"syscall\":\"tgkill\",\"sys_nr\":234,",
                "\"args\":[42,42,15,0,0,0],\"decoded_args\":null,\"result\":0}\n",
                "{\"event\":\"task_exit\",\"pid\":42,\"tid\":42,\"exit_code\":0,\"signal\":null}\n"
            ),
        )
        .unwrap();

        let report = build_profile(&BuildOptions {
            trace_dir: traces,
            worker: "vm".to_string(),
            output_dir: temp.path().to_path_buf(),
        })
        .unwrap();

        assert_eq!(report.read_paths, vec![PathBuf::from("/usr/lib")]);
        assert_eq!(
            report.network_observations,
            vec!["`socket` requested address family AF_INET."]
        );
        let generated = fs_err::read_to_string(report.profile_path).unwrap();
        assert!(generated.contains(".read(\"/usr/lib\")"));
        assert!(generated.contains(".network(Network::None)"));
        assert!(generated.contains("Observed syscalls"));
        assert!(generated.contains("Default syscall denial list"));
        assert!(generated.contains("Generated syscall denial list"));
        assert!(generated.contains("Syscalls::Deny(&[\"kill\", \"tkill\"])"));
        assert!(generated.contains(".name(\"vm_worker\")"));
        assert_eq!(
            report.generated_syscall_denials,
            vec!["kill".to_string(), "tkill".to_string()]
        );
    }

    #[test]
    fn classifies_write_and_implicit_paths() {
        let mut evidence = Evidence::default();
        observe_path(
            "openat",
            [AT_FDCWD, 0, O_RDWR | O_CREAT, 0, 0, 0],
            "/var/lib/openvmm/state",
            &mut evidence,
        );
        observe_path(
            "newfstatat",
            [AT_FDCWD, 0, 0, 0, 0, 0],
            "/proc/self/maps",
            &mut evidence,
        );
        normalize_grants(&mut evidence);

        assert_eq!(
            evidence.read_write_paths,
            BTreeSet::from([PathBuf::from("/var/lib/openvmm")])
        );
        assert!(evidence.read_paths.is_empty());
        assert!(
            evidence
                .filesystem_notes
                .iter()
                .any(|note| note.contains("implicit `/proc`"))
        );
    }
}
