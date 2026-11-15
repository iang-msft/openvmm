// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Builder;
use crate::Network;
use crate::Profile;
use crate::Syscalls;

/// Profile derived from observed worker behavior.
pub fn vm_worker() -> Builder {
    // Deny access by default.
    let mut profile = Profile::deny_all().name("vm_worker");
    let cwd = std::env::current_dir().unwrap_or_default();

    // Read-only paths.
    for path in [
        "/etc/host.conf",
        "/etc/hosts",
        "/etc/ld.so.cache",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/sys/bus/pci/devices",
        "/sys/devices",
    ] {
        let path = std::path::Path::new(path);
        if path.exists() {
            profile = profile.read(path);
        }
    }

    // Read and execute paths.
    for path in [
        cwd.to_str().unwrap_or_default(), // Allow read/execute access to the worker's working directory.
        "/etc/gai.conf",
        "/opt/containerd/lib",
        "/usr/lib/libc.so.6",
        "/usr/lib/libgcc_s.so.1",
        "/usr/lib/libm.so.6",
    ] {
        let path = std::path::Path::new(path);
        if path.exists() {
            profile = profile.read_exec(path);
        }
    }

    // Device access.
    for path in ["/dev/sev", "/dev/vfio/vfio"] {
        let path = std::path::Path::new(path);
        if path.exists() {
            profile = profile.device(path);
        }
    }

    // Network access.
    profile = profile.network(Network::Unrestricted);

    // System call restrictions.
    profile = profile.syscalls(Syscalls::deny([
        "acct",
        "add_key",
        "kcmp",
        "keyctl",
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
        let profile = vm_worker().build();
        let Syscalls::Deny(names) = profile.inner.syscalls else {
            panic!("VM worker must use syscall filtering");
        };
        for name in names {
            assert!(
                crate::nr_for_name(&name).is_some(),
                "VM worker syscall does not resolve: {name}",
            );
        }
    }
}
