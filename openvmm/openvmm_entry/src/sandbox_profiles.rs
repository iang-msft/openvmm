// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sandbox policy definitions for OpenVMM worker hosts.

#[derive(Copy, Clone)]
pub(crate) enum SandboxRole {
    Vm,
    Tpm,
}

impl SandboxRole {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::Tpm => "tpm",
        }
    }

    pub(crate) fn profile(self) -> sandbox::Profile {
        match self {
            Self::Vm => sandbox::profiles::minimal()
                .name(self.name())
                .read("/usr")
                .read("/etc")
                .read("/dev")
                .syscalls(sandbox::Syscalls::Deny(&["kill"]))
                .build(),
            Self::Tpm => sandbox::Profile::deny_all()
                .name(self.name())
                .network(sandbox::Network::None)
                .syscalls(sandbox::Syscalls::Deny(&["kill", "tkill", "tgkill"]))
                .build(),
        }
    }
}
