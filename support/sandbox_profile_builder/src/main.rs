// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate a candidate sandbox profile from worker trace JSONL files.

#![forbid(unsafe_code)]

use clap::Parser;
use sandbox_profile_builder::BuildOptions;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "sandbox_profile_builder")]
#[command(about = "Generate a candidate OpenVMM sandbox profile from worker traces")]
struct Options {
    /// Directory containing worker JSONL trace files.
    trace_dir: PathBuf,

    /// Worker type/name, such as `vm` or `dpm`.
    worker: String,

    /// Override the output directory. Defaults to TRACE_DIR.
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Override the platform syscall denylist JSON file.
    #[arg(long)]
    syscall_denylist: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let output_dir = options
        .output_dir
        .unwrap_or_else(|| options.trace_dir.clone());
    let report = sandbox_profile_builder::build_profile(&BuildOptions {
        trace_dir: options.trace_dir,
        worker: options.worker,
        output_dir,
        syscall_denylist_path: options.syscall_denylist,
    })?;

    println!("generated profile: {}", report.profile_path.display());
    println!(
        "syscall denylist: {}",
        report.syscall_denylist_path.display()
    );
    println!("trace files: {}", report.trace_files.len());
    println!("read-only grants: {}", report.read_paths.len());
    println!("read-write grants: {}", report.read_write_paths.len());
    println!("observed syscalls: {}", report.syscalls.len());
    println!("generated network policy: {:?}", report.generated_network);
    println!(
        "generated syscall denials: {}",
        report.generated_syscall_denials.join(", ")
    );

    if report.network_observations.is_empty() {
        println!("network activity: none observed");
    } else {
        println!("network activity observed:");
        for observation in &report.network_observations {
            println!("  - {observation}");
        }
    }
    if !report.filesystem_notes.is_empty() {
        println!("filesystem notes:");
        for note in &report.filesystem_notes {
            println!("  - {note}");
        }
    }
    Ok(())
}
