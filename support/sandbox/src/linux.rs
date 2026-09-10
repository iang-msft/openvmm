// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The Linux backend for [`apply`](crate::apply) and [`tighten`](crate::tighten).
//!
//! On Linux the worker starts inside the user, mount, and network namespaces
//! requested by [`prepare`](crate::prepare), then configures the namespaces
//! selected by the profile here: a `pivot_root` onto a purpose-built root,
//! capability drop and securebits lock, process-hardening `prctl`s`,
//! `no_new_privs`, and an optional seccomp filter. The composition order is
//! load-bearing and mirrors the order validated against Bubblewrap, `runc`,
//! systemd, Firejail, and the Chromium sandbox.
//!
//! # Failure policy
//!
//! Every primitive this backend applies is *required*: if it fails, the worker
//! aborts via [`Error`] rather than run with a weaker sandbox than its profile
//! declares (fail-closed). Namespaces, the `pivot_root` scaffold, capability
//! drop, securebits, filesystem grants, `PR_SET_DUMPABLE`, `PR_SET_PDEATHSIG`,
//! and `no_new_privs` all abort on failure.
//!
//! The two deliberate exceptions are *supplementary* layers whose failure
//! policy differs. **Landlock** (an FS-isolation supplement to the mount
//! namespace, ABI-degraded on older kernels per D11/D16) logs and continues on
//! failure; the mount namespace remains the primary FS boundary. **Seccomp** is
//! *opt-in* per worker class (D13) — the deny-all default installs no filter —
//! but once a profile opts in with [`Syscalls::Deny`] or [`Syscalls::Allow`],
//! applying it is required and a failure aborts.

use crate::Error;
use crate::profile::Access;
use crate::profile::FsGrant;
use crate::profile::Network;
use crate::profile::Profile;
use crate::profile::Restrictions;
use crate::profile::Syscalls;
use crate::unix::hardening;
use crate::unix::mount_namespace;
use crate::unix::network_namespace;
use crate::unix::seccomp;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// Staging path for the tmpfs that becomes `/` after `pivot_root`.
///
/// It exists only inside our fresh mount namespace, so it can never collide
/// with another process's view of the filesystem.
const STAGING_ROOT: &str = "/tmp/.sandbox-root";

/// Apply `profile` to the current process. See the module docs for ordering
/// and failure policy.
pub fn apply(profile: &Profile) -> Result<(), Error> {
    let p = &profile.inner;

    // Step 1 — detach propagation in the mount namespace created with the
    // child. Even a profile with no filesystem grants pivots to a minimal
    // tmpfs root; an empty grant set must deny rather than preserve the host
    // filesystem view.
    mount_namespace::make_root_private().map_err(required("mount_namespace"))?;

    // Step 2 — configure an isolated network namespace, when requested, before
    // filesystem setup so any FS step that could reach the network is already
    // contained.
    apply_network(p.network)?;

    // Step 3 — filesystem: tmpfs root, per-grant binds, /proc, /tmp,
    // pivot_root, then opportunistic Landlock.
    apply_filesystem(&p.fs)?;

    // Step 4 — lock securebits *before* the capability drop, while we still
    // hold CAP_SETPCAP. Required (design §9): a worker that can regain root-like
    // authority across an execve is not sandboxed.
    hardening::lock_securebits().map_err(required("securebits"))?;

    // Step 5 — drop every capability. Required: this is the deny-all base.
    drop_all_capabilities()?;

    hardening::set_dumpable_off().map_err(required("dumpable"))?;
    // PR_SET_PDEATHSIG must come after any credential change (none here, but the
    // ordering is preserved so identity work added later stays correct).
    hardening::set_pdeathsig_kill().map_err(required("pdeathsig"))?;

    // Step 6 — no_new_privs. Required, and a prerequisite for unprivileged
    // seccomp below.
    hardening::set_no_new_privs().map_err(required("no_new_privs"))?;

    // Step 7 — seccomp, *opt-in* per worker class (design D13). The deny-all
    // default (`Syscalls::Unfiltered`) installs no filter. Denylists extend the
    // dangerous-syscall baseline; allowlists deny everything else while still
    // refusing to re-enable anything from that baseline.
    match &p.syscalls {
        Syscalls::Unfiltered => {}
        Syscalls::Deny(names) => {
            seccomp::apply_denylist(names, seccomp_deny_action()).map_err(required("seccomp"))?;
        }
        Syscalls::Allow(names) => {
            seccomp::apply_allowlist(names, seccomp_deny_action()).map_err(required("seccomp"))?;
        }
    }

    tracing::debug!(profile = p.name, "sandbox applied");
    Ok(())
}

/// Stack additional, strictly-narrowing restrictions onto an already-applied
/// sandbox. Runs after the worker has initialized and may be multi-threaded.
pub fn tighten(restrictions: &Restrictions) -> Result<(), Error> {
    let r = &restrictions.inner;

    // Path revocation via a stacked Landlock ruleset needs the base profile's
    // full grant set to re-express (Landlock layers intersect), which is not
    // available here. Rather than silently fail open, reject it (R-S12).
    if !r.revoke_paths.is_empty() {
        return Err(Error::RequiredPrimitiveUnavailable(
            "path revocation via tighten is not supported in v1",
        ));
    }

    // Stack an additional syscall denylist. Filters compose; the kernel takes
    // the most restrictive verdict across every installed filter.
    if let Some(names) = r.syscalls {
        seccomp::apply_denylist(names, seccomp_deny_action()).map_err(required("seccomp"))?;
    }

    Ok(())
}

/// Configure the network namespace to match `scope`. Required: a failure
/// aborts.
fn apply_network(scope: Network) -> Result<(), Error> {
    match scope {
        Network::None | Network::Unrestricted => Ok(()),
        Network::Loopback => network_namespace::bring_up_loopback(),
    }
    .map_err(required("network_namespace"))
}

/// Real filesystem setup: tmpfs staging root, per-grant bind mounts,
/// `pivot_root`, old-root cleanup, and layered Landlock enforcement.
fn apply_filesystem(grants: &[FsGrant]) -> Result<(), Error> {
    let staging = Path::new(STAGING_ROOT);

    fs_err::create_dir_all(staging).map_err(fs_required)?;
    mount_namespace::mount_tmpfs(staging).map_err(fs_required)?;

    // Bind each grant into the staging root at the same path
    // (source `/bin` => `staging/bin`).
    for grant in grants {
        let source = grant.path.as_path();
        if !source.exists() {
            return Err(Error::ApplyFailed {
                primitive: "filesystem",
                source: io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "filesystem grant source does not exist: {}",
                        source.display()
                    ),
                ),
            });
        }
        let target = join_under(staging, source);
        let flags = mount_flags_for_access(grant.access);
        mount_namespace::bind_mount(source, &target, flags).map_err(fs_required)?;
    }

    // Best-effort `/proc`: works cleanly in a PID namespace and is still useful
    // for `/proc/self` when we don't have one.
    let proc_target = staging.join("proc");
    if mount_namespace::mount_proc(&proc_target).is_err() {
        let _ = mount_namespace::bind_mount(
            Path::new("/proc"),
            &proc_target,
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        );
    }

    // Writable tmpfs at `/tmp` inside the sandbox.
    let tmp_target = staging.join("tmp");
    fs_err::create_dir_all(&tmp_target).map_err(fs_required)?;
    mount_namespace::mount_tmpfs(&tmp_target).map_err(fs_required)?;

    // Pivot root: staging becomes `/`, old root moves to `staging/.old_root`.
    let old_root = staging.join(".old_root");
    fs_err::create_dir_all(&old_root).map_err(fs_required)?;
    mount_namespace::pivot_root(staging, &old_root).map_err(fs_required)?;
    std::env::set_current_dir("/").map_err(fs_required)?;

    // Detach and remove the old root so nothing leaks through.
    mount_namespace::umount(Path::new("/.old_root")).map_err(fs_required)?;
    let _ = fs_err::remove_dir("/.old_root");

    // Landlock is a supplementary, opportunistic layer (design D11/D16): a
    // failure degrades rather than aborts.
    if let Err(e) = apply_landlock(grants) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "could not apply Landlock ruleset; relying on mount namespace only",
        );
    }

    Ok(())
}

/// Translate a policy [`Access`] into `MS_*` remount flags.
///
/// `MS_NOSUID` and `MS_NODEV` are always set — no setuid execution and no
/// device-node creation inside the sandbox, regardless of the grant.
fn mount_flags_for_access(access: Access) -> libc::c_ulong {
    const BASE: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV;
    match access {
        Access::ReadExec => BASE | libc::MS_RDONLY,
        Access::ReadWrite => BASE | libc::MS_NOEXEC,
    }
}

/// Compose `root/relative(path)`: `Path::join` returns `path` unchanged when it
/// is absolute, so strip the leading separator first.
fn join_under(root: &Path, path: &Path) -> PathBuf {
    let stripped = path.strip_prefix("/").unwrap_or(path);
    root.join(stripped)
}

/// Install a Landlock ruleset covering every grant, then `restrict_self`.
///
/// Requests the highest known Landlock ABI and lets the `landlock` crate
/// downgrade automatically on older kernels.
fn apply_landlock(grants: &[FsGrant]) -> io::Result<()> {
    use landlock::ABI;
    use landlock::Access as _;
    use landlock::AccessFs;
    use landlock::Ruleset;
    use landlock::RulesetAttr;
    use landlock::RulesetCreatedAttr;
    use landlock::path_beneath_rules;

    let abi = ABI::V5;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(landlock_err)?
        .create()
        .map_err(landlock_err)?;

    let from_read = AccessFs::from_read(abi);
    let from_write = AccessFs::from_write(abi);

    for grant in grants {
        let source = grant.path.as_path();
        if !source.exists() {
            continue;
        }
        let rights = match grant.access {
            Access::ReadExec => from_read,
            Access::ReadWrite => (from_read & !AccessFs::Execute) | from_write,
        };
        ruleset = ruleset
            .add_rules(path_beneath_rules(&[source], rights))
            .map_err(landlock_err)?;
    }

    let tmp_rights = (from_read & !AccessFs::Execute) | from_write;
    ruleset = ruleset
        .add_rules(path_beneath_rules(&[Path::new("/tmp")], tmp_rights))
        .map_err(landlock_err)?;

    let status = ruleset.restrict_self().map_err(landlock_err)?;
    tracing::debug!(
        ruleset = ?status.ruleset,
        no_new_privs = status.no_new_privs,
        "applied Landlock ruleset",
    );
    Ok(())
}

fn landlock_err(e: landlock::RulesetError) -> io::Error {
    io::Error::other(format!("landlock: {e}"))
}

/// Drop every OS capability from the current thread's Ambient, Bounding,
/// Inheritable, Effective, and Permitted sets.
///
/// Order matters: Ambient first (independent), then Bounding (needs
/// `CAP_SETPCAP`, still in Effective), then Inheritable, then Effective, then
/// Permitted. Clearing Effective before Permitted preserves the kernel's
/// `Effective ⊆ Permitted` invariant.
fn drop_all_capabilities() -> Result<(), Error> {
    for set in [
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Inheritable,
        caps::CapSet::Effective,
        caps::CapSet::Permitted,
    ] {
        caps::clear(None, set).map_err(|e| Error::ApplyFailed {
            primitive: "capabilities",
            source: io::Error::other(format!("caps::clear({set:?}): {e}")),
        })?;
    }
    Ok(())
}

/// The seccomp deny action: kill the process in production (design D13), log
/// (allow + record) in dev so the tuning loop can observe missing syscalls.
/// The action taken when a denied syscall is invoked.
///
/// Release builds `KillProcess` — the denied set is a fixed, intentional list
/// of escape vectors, so hitting one is a hard fault. Debug builds return
/// `EPERM` instead: still enforced (unlike `Log`, which allows the call), but
/// survivable, so a developer sees the `errno` rather than an opaque kill.
fn seccomp_deny_action() -> seccompiler::SeccompAction {
    if cfg!(debug_assertions) {
        seccompiler::SeccompAction::Errno(libc::EPERM as u32)
    } else {
        seccompiler::SeccompAction::KillProcess
    }
}

/// Build a closure mapping an [`io::Error`] to a required-primitive
/// [`Error::ApplyFailed`].
fn required(primitive: &'static str) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::ApplyFailed { primitive, source }
}

/// Shorthand for the required filesystem-scaffold steps.
fn fs_required(source: io::Error) -> Error {
    Error::ApplyFailed {
        primitive: "filesystem",
        source,
    }
}
