// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Syscall tracing for child processes.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod ptrace;

#[cfg(target_os = "linux")]
pub use ptrace::TracedChild;
#[cfg(target_os = "linux")]
pub use ptrace::build_seccomp_filter;

// Syscalls used to infer filesystem and network policy, including descriptor tracking.
// C-style syscall argument signatures; mode and fcntl's arg are shown explicitly.
#[rustfmt::skip]
pub const RESOURCE_ACCESS_SYSCALLS: &[&str] = &[
    // Filesystem access
    "open",           // int open(const char *path, int flags, mode_t mode)
    "openat",         // int openat(int dirfd, const char *path, int flags, mode_t mode)
    "newfstatat",     // int newfstatat(int dirfd, const char *path, struct stat *statbuf, int flags)
    "statx",          // int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *statxbuf)
    "readlinkat",     // ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
    "faccessat",      // int faccessat(int dirfd, const char *path, int mode)
    "faccessat2",     // int faccessat2(int dirfd, const char *path, int mode, int flags)
    "mkdirat",        // int mkdirat(int dirfd, const char *path, mode_t mode)
    "unlinkat",       // int unlinkat(int dirfd, const char *path, int flags)
    "renameat2",      // int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
    // Descriptor lifecycle shared by filesystem and network access
    "dup",            // int dup(int oldfd)
    "dup2",           // int dup2(int oldfd, int newfd)
    "dup3",           // int dup3(int oldfd, int newfd, int flags)
    "fcntl",          // int fcntl(int fd, int cmd, unsigned long arg)
    "close",          // int close(int fd)
    // Network access
    "socket",         // int socket(int domain, int type, int protocol)
    "socketpair",     // int socketpair(int domain, int type, int protocol, int sv[2])
    "bind",           // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    "connect",        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    "listen",         // int listen(int sockfd, int backlog)
    "accept4",        // int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
    "sendto",         // ssize_t sendto(int sockfd, const void *buf, size_t size, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
    "recvfrom",       // ssize_t recvfrom(int sockfd, void *buf, size_t size, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
    "sendmsg",        // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
    "recvmsg",        // ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
];

// Error returned when a syscall cannot be selected for profile tracing.
#[derive(Debug, thiserror::Error)]
pub enum TraceSyscallError {
    // A built-in profile syscall has no native syscall number.
    #[error("worker trace parsing support needs to be added for built-in syscall {0:?}")]
    UnsupportedBuiltIn(&'static str),
    // A configured syscall name is not recognized.
    #[error("worker trace parsing support needs to be added for configured syscall {0:?}")]
    UnsupportedConfigured(String),
}

// Return whether `syscall` is needed to derive filesystem or network policy.
pub fn is_resource_access_syscall(syscall: &str) -> bool {
    RESOURCE_ACCESS_SYSCALLS.contains(&syscall)
}

// Build a number-to-name map combining filesystem and network syscalls
// with optional entries from the platform syscall denylist.
// Return an error for unsupported syscall names and skip syscalls unavailable
// on the current architecture.
#[cfg(target_os = "linux")]
pub fn get_syscalls_to_trace() -> Result<BTreeMap<i64, String>, TraceSyscallError> {
    // Read optional platform syscall denials and validate their syscall names.
    let optional_deny_syscall_names = sandbox::platform_syscall_denylist()
        .filter(|entry| entry.enforcement == sandbox::Enforcement::Optional)
        .map(|entry| entry.name.to_string())
        .collect::<Vec<_>>();
    validate_syscall_names(&optional_deny_syscall_names)?;

    // Map filesystem and network syscalls to their numbers, skipping known
    // architecture exceptions and rejecting unsupported names.
    let mut syscall_number_to_name_map = BTreeMap::new();
    for &syscall_name in RESOURCE_ACCESS_SYSCALLS {
        match sandbox::nr_for_name(syscall_name) {
            Some(syscall_number) => {
                syscall_number_to_name_map.insert(syscall_number, syscall_name.to_string());
            }
            None if is_syscall_unavailable_on_arch(syscall_name) => continue,
            None => return Err(TraceSyscallError::UnsupportedBuiltIn(syscall_name)),
        }
    }

    // Add optionally denied syscalls that have numbers on the current architecture.
    for optional_deny_syscall_name in optional_deny_syscall_names {
        if let Some(syscall_number) = sandbox::nr_for_name(&optional_deny_syscall_name) {
            syscall_number_to_name_map.insert(syscall_number, optional_deny_syscall_name);
        }
    }

    Ok(syscall_number_to_name_map)
}

// Check if syscall names resolve to syscall numbers,
// and are available on the current architecture.
// Return an error for the first unsupported name.
#[cfg(target_os = "linux")]
pub fn validate_syscall_names(syscall_names: &[String]) -> Result<(), TraceSyscallError> {
    if let Some(syscall_name) = syscall_names
        .iter()
        .find(|syscall_name| {
            sandbox::nr_for_name(syscall_name).is_none()
                && !is_syscall_unavailable_on_arch(syscall_name.as_str())
        })
        .cloned()
    {
        return Err(TraceSyscallError::UnsupportedConfigured(syscall_name));
    }
    Ok(())
}

// Return whether the syscall is known to be unavailable on the target architecture.
#[cfg(target_os = "linux")]
fn is_syscall_unavailable_on_arch(syscall: &str) -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        matches!(
            syscall,
            "create_module" | "dup2" | "fork" | "ioperm" | "iopl" | "open"
        )
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let _ = syscall;
        false
    }
}

// Child-process syscall-tracing configuration.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    // Directory in which the per-process JSONL trace is written.
    pub output_dir: PathBuf,
    // Prefix used for trace file names.
    #[cfg(target_os = "linux")]
    file_prefix: String,
    #[cfg(target_os = "linux")]
    syscalls: BTreeMap<i64, String>,
}

impl TraceConfig {
    // Creates a tracing configuration for the supplied native syscall map.
    #[cfg(target_os = "linux")]
    pub fn new(
        output_dir: PathBuf,
        file_prefix: impl Into<String>,
        syscalls: BTreeMap<i64, String>,
    ) -> Self {
        Self {
            output_dir,
            file_prefix: file_prefix.into(),
            syscalls,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn profile_trace_syscalls_include_only_optional_platform_denials() {
        let syscalls = get_syscalls_to_trace().unwrap();

        for entry in sandbox::platform_syscall_denylist() {
            match sandbox::nr_for_name(entry.name) {
                Some(syscall_number) => {
                    if entry.enforcement == sandbox::Enforcement::Optional
                        || is_resource_access_syscall(entry.name)
                    {
                        assert_eq!(
                            syscalls.get(&syscall_number).map(String::as_str),
                            Some(entry.name)
                        );
                    } else {
                        assert!(!syscalls.contains_key(&syscall_number), "{}", entry.name);
                    }
                }
                None => assert!(is_syscall_unavailable_on_arch(entry.name)),
            }
        }
    }

    #[test]
    fn validate_syscall_names_reject_unknown_names() {
        for name in ["not_a_syscall", "umount"] {
            let error = validate_syscall_names(&[name.to_string()]).unwrap_err();
            assert!(matches!(
                error,
                TraceSyscallError::UnsupportedConfigured(rejected) if rejected == name
            ));
        }
    }

    #[test]
    fn profile_trace_syscalls_resolve_supported_built_ins() {
        let syscalls = get_syscalls_to_trace().unwrap();

        for &syscall_name in RESOURCE_ACCESS_SYSCALLS {
            match sandbox::nr_for_name(syscall_name) {
                Some(syscall_number) => {
                    assert_eq!(
                        syscalls.get(&syscall_number).map(String::as_str),
                        Some(syscall_name)
                    );
                }
                None => assert!(is_syscall_unavailable_on_arch(syscall_name)),
            }
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn profile_trace_syscalls_skip_architecture_absent_built_ins() {
        validate_syscall_names(&["dup2".to_string(), "open".to_string()]).unwrap();
        let syscalls = get_syscalls_to_trace().unwrap();

        assert!(!syscalls.values().any(|name| name == "dup2"));
        assert!(!syscalls.values().any(|name| name == "open"));
        assert_eq!(
            syscalls.get(&libc::SYS_dup3).map(String::as_str),
            Some("dup3")
        );
    }
}
