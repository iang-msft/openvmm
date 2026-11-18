// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Builder;
use crate::Network;
use crate::Profile;
use crate::Syscalls;

/// Profile derived from observed worker behavior.
pub fn tpm_worker() -> Builder {
    // Deny access by default.
    let mut profile = Profile::deny_all().name("tpm_worker");
    let cwd = std::env::current_dir().unwrap_or_default();

    // Read-only paths.
    for path in ["/etc/ld.so.cache", "/etc/pki/tls/openssl.cnf"] {
        let path = std::path::Path::new(path);
        if path.exists() {
            profile = profile.read(path);
        }
    }

    // Read and execute paths.
    for path in [
        cwd.to_str().unwrap_or_default(), // Allow read/execute access to the worker's working directory.
        "/etc/ssl/openssl.cnf",
        "/opt/containerd/lib",
        "/usr/lib/libc.so.6",
        "/usr/lib/libgcc_s.so.1",
        "/usr/lib/libm.so.6",
        "/usr/local/ssl/openssl.cnf",
    ] {
        let path = std::path::Path::new(path);
        if path.exists() {
            profile = profile.read_exec(path);
        }
    }

    // Network access.
    profile = profile.network(Network::None);

    // System call restrictions.
    profile = profile.syscalls(Syscalls::deny([
        "acct",
        "add_key",
        "io_uring_enter",
        "io_uring_register",
        "io_uring_setup",
        "kcmp",
        "keyctl",
        "mbind",
        "request_key",
    ]));

    profile
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn syscall_names_resolve() {
        let profile = tpm_worker().build();
        let Syscalls::Deny(names) = profile.inner.syscalls else {
            panic!("TPM worker must use syscall filtering");
        };
        for name in names {
            assert!(
                crate::nr_for_name(&name).is_some(),
                "TPM worker syscall does not resolve: {name}",
            );
        }
    }
}
