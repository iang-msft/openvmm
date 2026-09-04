// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mount namespaces (`CLONE_NEWNS`) and helpers for building a sandbox
//! root filesystem.

use crate::unix::SyscallResult;
use std::ffi::CString;
use std::io;
use std::path::Path;

/// Detach the current mount namespace from its parent's propagation.
///
/// Sets the root subtree's propagation type first to `MS_SLAVE` (always
/// allowed from within a fresh user+mount namespace) and then to
/// `MS_PRIVATE`, so subsequent mounts and unmounts inside this namespace
/// don't propagate into the parent namespace.
///
/// This is the standard first step after
/// entering the mount namespace. Bubblewrap, systemd's mount namespace setup,
/// and every OCI runtime do the same.
pub fn make_root_private() -> io::Result<()> {
    set_root_propagation(libc::MS_REC | libc::MS_SLAVE)?;
    set_root_propagation(libc::MS_REC | libc::MS_PRIVATE)?;
    Ok(())
}

/// Change the mount-propagation type of `/`.
///
/// Typically called via [`make_root_private`]; exposed separately for
/// callers that need finer control (e.g., recursively marking `/` as
/// `MS_SHARED` for a different reason).
pub fn set_root_propagation(flags: libc::c_ulong) -> io::Result<()> {
    let c_root = CString::new("/").expect("literal has no NUL");
    // SAFETY: mount() with a valid target and null source/type/data as
    // documented for propagation-flag remounts.
    unsafe {
        libc::mount(
            std::ptr::null(),
            c_root.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    }
    .syscall_result()?;
    Ok(())
}

/// Mount a tmpfs at the given path.
pub fn mount_tmpfs(target: &Path) -> io::Result<()> {
    let c_target = path_to_cstring(target)?;
    let c_fstype = CString::new("tmpfs").expect("literal has no NUL");
    let c_source = CString::new("none").expect("literal has no NUL");

    // SAFETY: mount() with valid NUL-terminated C strings.
    unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    }
    .syscall_result()?;
    Ok(())
}

/// Recursively bind-mount `source` at `target`, then remount with the
/// caller-supplied flags.
///
/// The two-step (bind then remount) sequence is required because
/// per-mount flags such as `MS_RDONLY`, `MS_NOEXEC`, `MS_NOSUID`, and
/// `MS_NODEV` are silently ignored on the initial `MS_BIND` call and
/// only take effect on a subsequent `MS_REMOUNT | MS_BIND` call. When
/// `remount_flags` is zero the remount step is skipped.
///
/// The target directory is created if it doesn't already exist.
pub fn bind_mount(source: &Path, target: &Path, remount_flags: libc::c_ulong) -> io::Result<()> {
    let c_source = path_to_cstring(source)?;
    let c_target = path_to_cstring(target)?;

    fs_err::create_dir_all(target)?;

    // SAFETY: mount() with valid NUL-terminated C strings; MS_BIND
    // ignores the filesystem-type argument, so passing NULL is
    // documented.
    unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    }
    .syscall_result()?;

    if remount_flags != 0 {
        // SAFETY: same rationale as the bind above; source and data are
        // documented to be ignored for a remount.
        unsafe {
            libc::mount(
                std::ptr::null(),
                c_target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC | libc::MS_REMOUNT | remount_flags,
                std::ptr::null(),
            )
        }
        .syscall_result()?;
    }

    Ok(())
}

/// Mount a proc filesystem at the given path.
///
/// Requires being in a PID namespace for a fully isolated `/proc`, but is
/// still useful for providing `/proc/self` etc.
pub fn mount_proc(target: &Path) -> io::Result<()> {
    let c_target = path_to_cstring(target)?;
    let c_fstype = CString::new("proc").expect("literal has no NUL");
    let c_source = CString::new("proc").expect("literal has no NUL");

    fs_err::create_dir_all(target)?;

    // SAFETY: mount() with valid NUL-terminated C strings and no flags
    // or data pointer.
    unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    }
    .syscall_result()?;
    Ok(())
}

/// Pivot the root filesystem to a new root, putting the old root at
/// `old_root`.
///
/// After this call, `new_root` becomes `/` and the previous root is
/// accessible at `old_root` (relative to `new_root`). Typically you then
/// unmount `old_root`.
pub fn pivot_root(new_root: &Path, old_root: &Path) -> io::Result<()> {
    let c_new = path_to_cstring(new_root)?;
    let c_old = path_to_cstring(old_root)?;

    // SAFETY: pivot_root(2) with valid NUL-terminated path pointers.
    unsafe { libc::syscall(libc::SYS_pivot_root, c_new.as_ptr(), c_old.as_ptr()) }
        .syscall_result()?;
    Ok(())
}

/// Unmount a filesystem. Uses `MNT_DETACH` for lazy unmount to avoid
/// `EBUSY`.
pub fn umount(target: &Path) -> io::Result<()> {
    let c_target = path_to_cstring(target)?;

    // SAFETY: umount2() with a valid NUL-terminated path pointer.
    unsafe { libc::umount2(c_target.as_ptr(), libc::MNT_DETACH) }.syscall_result()?;
    Ok(())
}

/// Convert a `Path` to a `CString` for use with libc, mapping embedded
/// NUL bytes to an [`io::Error`].
fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null byte in path"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use test_with_tracing::test;

    #[test]
    fn mount_operations_work_in_namespace() {
        let exe = std::env::current_exe().expect("failed to get test executable path");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--pid", "--fork"])
            .arg(exe)
            .args([
                "--exact",
                "unix::mount_namespace::tests::helper_mount_operations",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .expect("failed to spawn mount namespace helper");

        assert!(
            output.status.success(),
            "mount namespace helper failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn mount_namespace_is_isolated_from_parent() {
        let mountpoint = format!("/tmp/sandbox-mount-test-{}", std::process::id());
        fs_err::create_dir_all(&mountpoint).expect("failed to create parent mountpoint");
        let exe = std::env::current_exe().expect("failed to get test executable path");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount"])
            .env("SANDBOX_MOUNT_TEST_PATH", &mountpoint)
            .arg(exe)
            .args([
                "--exact",
                "unix::mount_namespace::tests::helper_isolated_mount",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .expect("failed to spawn isolated mount helper");
        assert!(
            output.status.success(),
            "isolated mount helper failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let mounts =
            fs_err::read_to_string("/proc/self/mountinfo").expect("failed to read mountinfo");
        assert!(!mounts.contains(&mountpoint));
        fs_err::remove_dir(&mountpoint).expect("failed to remove parent mountpoint");
    }

    #[test]
    #[ignore]
    fn helper_isolated_mount() {
        let mountpoint = std::env::var_os("SANDBOX_MOUNT_TEST_PATH")
            .map(PathBuf::from)
            .expect("missing mount test path");

        make_root_private().expect("failed to make root private");
        mount_tmpfs(&mountpoint).expect("failed to mount tmpfs");
        fs_err::write(mountpoint.join("marker"), "isolated").expect("failed to write marker");
    }

    #[test]
    #[ignore]
    fn helper_mount_operations() {
        make_root_private().expect("failed to make root private");

        let base = PathBuf::from(format!("/tmp/sandbox-mount-{}", std::process::id()));
        fs_err::create_dir_all(&base).expect("failed to create tmpfs mountpoint");
        mount_tmpfs(&base).expect("failed to mount tmpfs");
        fs_err::write(base.join("tmpfs-marker"), "tmpfs").expect("failed to write to tmpfs");

        let source = base.join("source");
        let target = base.join("target");
        fs_err::create_dir(&source).expect("failed to create bind source");
        fs_err::write(source.join("marker"), "bind").expect("failed to populate bind source");
        bind_mount(&source, &target, libc::MS_RDONLY).expect("failed to create read-only bind");
        assert_eq!(
            fs_err::read_to_string(target.join("marker")).expect("failed to read bind target"),
            "bind"
        );
        assert!(
            fs_err::write(target.join("new-file"), "denied").is_err(),
            "read-only bind mount allowed a write"
        );

        let proc_target = base.join("proc");
        mount_proc(&proc_target).expect("failed to mount proc");
        assert!(proc_target.join("self/status").exists());
        umount(&proc_target).expect("failed to unmount proc");
        umount(&target).expect("failed to unmount bind target");
        umount(&base).expect("failed to unmount tmpfs");

        let new_root = PathBuf::from(format!("/tmp/sandbox-root-{}", std::process::id()));
        fs_err::create_dir_all(&new_root).expect("failed to create new root");
        mount_tmpfs(&new_root).expect("failed to mount new root");
        fs_err::write(new_root.join("marker"), "new root").expect("failed to populate new root");
        let old_root = new_root.join(".old_root");
        fs_err::create_dir(&old_root).expect("failed to create old-root directory");

        pivot_root(&new_root, &old_root).expect("failed to pivot root");
        std::env::set_current_dir("/").expect("failed to change to new root");
        assert_eq!(
            fs_err::read_to_string("/marker").expect("new root marker is inaccessible"),
            "new root"
        );
        assert!(Path::new("/.old_root/proc/self/status").exists());
        umount(Path::new("/.old_root")).expect("failed to detach old root");
        assert!(!Path::new("/.old_root/proc/self/status").exists());
    }
}
