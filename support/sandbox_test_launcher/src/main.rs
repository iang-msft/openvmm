// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone CLI for exercising the [`sandbox`] crate.
//!
//! Use this launcher to invoke sandboxing primitives from the command line
//! outside of openvmm/openhcl, e.g. for iterating on new sandbox profiles.

#![forbid(unsafe_code)]

use sandbox::Identity;
use sandbox::Restrictions;
use sandbox::profiles;

fn main() -> anyhow::Result<()> {
    let profile = profiles::minimal().name("sandbox_test_launcher").build();
    let preparation = sandbox::prepare(&profile, &Identity::default(), &[])?;

    enter_namespaces(&preparation)?;
    run_sandbox_stage("apply", sandbox::apply(&profile));

    let restrictions = Restrictions::none().syscalls(&["socket"]).build();
    run_sandbox_stage("tighten", sandbox::tighten(&restrictions));

    println!("sandbox applied and tightened successfully");
    Ok(())
}

fn run_sandbox_stage(stage: &str, result: Result<(), sandbox::Error>) {
    if let Err(error) = result {
        eprintln!("sandbox {stage} failed: {error}");
        std::process::exit(sandbox::EXIT_SANDBOX_FAILED);
    }
}

#[cfg(target_os = "linux")]
fn enter_namespaces(preparation: &sandbox::SandboxProcessConfig) -> anyhow::Result<()> {
    use anyhow::Context;
    use anyhow::ensure;
    use nix::sched::CloneFlags;
    use nix::sched::unshare;
    use nix::unistd::getgid;
    use nix::unistd::getuid;

    let raw_flags = i32::try_from(preparation.clone_flags)
        .context("sandbox clone flags do not fit in Linux clone flags")?;
    let flags = CloneFlags::from_bits(raw_flags)
        .context("sandbox requested unrecognized Linux clone flags")?;
    let supported = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET;
    let unsupported = flags & !supported;
    ensure!(
        unsupported.is_empty(),
        "sandbox requested unsupported namespace flags: {unsupported:?}"
    );

    if flags.contains(CloneFlags::CLONE_NEWUSER) {
        let uid = getuid().as_raw();
        let gid = getgid().as_raw();

        unshare(CloneFlags::CLONE_NEWUSER).context("failed to create user namespace")?;
        std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
            .context("failed to configure user namespace uid map")?;
        std::fs::write("/proc/self/setgroups", "deny\n")
            .context("failed to disable setgroups in user namespace")?;
        std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
            .context("failed to configure user namespace gid map")?;
    }

    let remaining = flags & !CloneFlags::CLONE_NEWUSER;
    if !remaining.is_empty() {
        unshare(remaining).context("failed to create sandbox namespaces")?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enter_namespaces(_preparation: &sandbox::SandboxProcessConfig) -> anyhow::Result<()> {
    Ok(())
}
