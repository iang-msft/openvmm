// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate a candidate sandbox profile from worker trace JSONL files.

#![forbid(unsafe_code)]

use clap::Parser;
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

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use sandbox_profiler::TraceOptions;

    let options = Options::parse();
    let profile_dir = options
        .profile_dir
        .unwrap_or_else(|| options.trace_dir.clone());
    sandbox_profiler::build_profile(&TraceOptions {
        trace_dir: options.trace_dir,
        worker: options.worker,
        profile_dir,
    })
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("sandbox_profiler is supported only on Linux")
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
