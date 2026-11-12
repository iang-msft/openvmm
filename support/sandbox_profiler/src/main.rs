// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate a candidate sandbox profile from worker trace JSONL files.

#![forbid(unsafe_code)]

use clap::Parser;
use sandbox_profiler::TraceOptions;
use sandbox_profiler::TraceReport;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "sandbox_profiler")]
#[command(about = "Generate a candidate OpenVMM sandbox profile from worker traces")]
struct Options {
    /// Directory containing worker JSONL trace files.
    trace_dir: PathBuf,

    /// Worker type/name, such as vm or dpm.
    worker: String,

    /// Directory for the generated profile and report. Defaults to TRACE_DIR.
    #[arg(long)]
    profile_dir: Option<PathBuf>,
}

fn write_log_file(trace_report: &TraceReport) {
    println!("generated profile: {}", trace_report.profile_path.display());
    println!("generated log: {}", trace_report.log_path.display());
    println!("trace files: {}", trace_report.trace_files.len());

    if trace_report.observed_filesystem.is_empty() {
        println!("filesystem accesses: none observed");
    } else {
        println!("filesystem accesses observed:");
        for observation in &trace_report.observed_filesystem {
            println!("  - {observation}");
        }
    }

    if trace_report.observed_network.is_empty() {
        println!("network accesses: none observed");
    } else {
        println!("network accesses observed:");
        for observation in &trace_report.observed_network {
            println!("  - {observation}");
        }
    }

    println!(
        "observed syscalls: {}",
        trace_report.observed_syscalls.len()
    );

    println!(
        "read-only grants: {}",
        trace_report.policy_read_paths.len() + trace_report.policy_cwd.policy_read_paths.len()
    );
    println!(
        "read-write grants: {}",
        trace_report.policy_read_write_paths.len()
            + trace_report.policy_cwd.policy_read_write_paths.len()
    );
    println!(
        "device grants: {}",
        trace_report.policy_device_paths.len() + trace_report.policy_cwd.policy_device_paths.len()
    );
    println!(
        "worker-CWD-relative grants: {}",
        trace_report.policy_cwd.policy_read_paths.len()
            + trace_report.policy_cwd.policy_read_write_paths.len()
            + trace_report.policy_cwd.policy_device_paths.len()
    );
    println!(
        "generated network policy: {:?}",
        trace_report.policy_network
    );
    println!(
        "generated syscall denials: {}",
        trace_report.policy_syscalls.join(", ")
    );
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let profile_dir = options
        .profile_dir
        .unwrap_or_else(|| options.trace_dir.clone());
    let trace_report = sandbox_profiler::build_profile(&TraceOptions {
        trace_dir: options.trace_dir,
        worker: options.worker,
        profile_dir,
    })?;

    write_log_file(&trace_report);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_profile_directory_without_legacy_alias() {
        let options = Options::try_parse_from([
            "sandbox_profiler",
            "traces",
            "vm",
            "--profile-dir",
            "profiles",
        ])
        .unwrap();
        assert_eq!(options.profile_dir, Some(PathBuf::from("profiles")));

        let error = Options::try_parse_from([
            "sandbox_profiler",
            "traces",
            "vm",
            "--output-dir",
            "profiles",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
