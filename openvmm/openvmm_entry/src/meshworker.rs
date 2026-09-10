// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Functions and types for running a mesh for OpenVMM and launching workers
//! within it.

use anyhow::Context;
use inspect::Inspect;
use mesh_process::Mesh;
use mesh_process::ProcessConfig;
use mesh_process::try_run_mesh_host;
use mesh_worker::RegisteredWorkers;
use mesh_worker::WorkerHost;
use openvmm_defs::entrypoint::MeshHostParams;
use pal_async::task::Spawn;
use pal_async::task::Task;
use std::path::PathBuf;

const SANDBOX_ROLE_ARG: &str = "--openvmm-sandbox-role=";

#[derive(Copy, Clone)]
pub(crate) enum SandboxRole {
    Vm,
    Tpm,
}

impl SandboxRole {
    fn name(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::Tpm => "tpm",
        }
    }

    fn profile(self) -> sandbox::Profile {
        let profile = sandbox::profiles::minimal()
            .name(self.name())
            .read("/usr")
            .read("/etc")
            .read("/dev");
        match self {
            Self::Vm => profile.syscalls(sandbox::Syscalls::Deny(&["kill"])).build(),
            Self::Tpm => profile.build(),
        }
    }
}

pub(crate) fn run_vmm_mesh_host() -> anyhow::Result<()> {
    try_run_mesh_host("openvmm", async |params: MeshHostParams| {
        params.runner.run(RegisteredWorkers).await;
        Ok(())
    })
}

pub(crate) fn apply_vmm_mesh_host_sandbox() -> anyhow::Result<()> {
    if let Some(role) = sandbox_role_from_args()? {
        sandbox::apply(&role.profile()).context("failed to apply worker host sandbox")?;
    }
    Ok(())
}

fn sandbox_role_from_args() -> anyhow::Result<Option<SandboxRole>> {
    let mut role = None;
    for arg in std::env::args() {
        let Some(value) = arg.strip_prefix(SANDBOX_ROLE_ARG) else {
            continue;
        };
        let parsed = match value {
            "vm" => SandboxRole::Vm,
            "tpm" => SandboxRole::Tpm,
            _ => anyhow::bail!("unknown OpenVMM sandbox role `{value}`"),
        };
        if role.replace(parsed).is_some() {
            anyhow::bail!("OpenVMM sandbox role specified more than once");
        }
    }
    Ok(role)
}

#[cfg(target_os = "linux")]
struct LinuxSandboxProfile {
    clone_flags: i32,
    self_map_user_namespace: bool,
}

#[cfg(target_os = "linux")]
impl mesh_process::SandboxProfile for LinuxSandboxProfile {
    fn apply(&mut self, builder: &mut pal::unix::process::Builder<'_>) {
        builder
            .set_clone_flags(self.clone_flags)
            .set_user_namespace_self_map(self.self_map_user_namespace);
    }
}

#[derive(Inspect)]
pub(crate) struct VmmMesh {
    #[inspect(flatten)]
    mesh: Option<Mesh>,
    #[inspect(skip)]
    local_host: WorkerHost,
    #[inspect(skip)]
    _task: Task<()>,
}

impl VmmMesh {
    pub fn new(spawn: &impl Spawn, single_process: bool) -> anyhow::Result<Self> {
        let mesh = if single_process {
            None
        } else {
            Some(Mesh::new("openvmm".to_string())?)
        };
        let (local_host, runner) = mesh_worker::worker_host();
        let task = spawn.spawn("worker-host", runner.run(RegisteredWorkers));
        Ok(Self {
            mesh,
            local_host,
            _task: task,
        })
    }

    pub async fn make_host(
        &self,
        name: impl Into<String>,
        log_file: Option<PathBuf>,
    ) -> anyhow::Result<WorkerHost> {
        self.make_host_inner(name.into(), log_file, None).await
    }

    pub async fn make_sandboxed_host(
        &self,
        role: SandboxRole,
        log_file: Option<PathBuf>,
    ) -> anyhow::Result<WorkerHost> {
        self.make_host_inner(role.name().to_string(), log_file, Some(role))
            .await
    }

    async fn make_host_inner(
        &self,
        name: String,
        log_file: Option<PathBuf>,
        sandbox_role: Option<SandboxRole>,
    ) -> anyhow::Result<WorkerHost> {
        #[cfg(not(target_os = "linux"))]
        if sandbox_role.is_some() {
            return Err(sandbox::Error::UnsupportedPlatform.into());
        }

        let log_file: Option<std::fs::File> = if let Some(file) = &log_file {
            Some(
                std::fs::File::create(file)
                    .with_context(|| format!("failed to create log file {}", file.display()))?,
            )
        } else {
            None
        };

        let host = if let Some(mesh) = &self.mesh {
            let (host, runner) = mesh_worker::worker_host();
            #[cfg(target_os = "linux")]
            let process_config = match sandbox_role {
                Some(role) => {
                    let preparation =
                        sandbox::prepare(&role.profile(), &sandbox::Identity::default(), &[])?;
                    let clone_flags = preparation
                        .clone_flags
                        .try_into()
                        .context("sandbox clone flags do not fit in i32")?;
                    ProcessConfig::new_with_sandbox(
                        role.name(),
                        Box::new(LinuxSandboxProfile {
                            clone_flags,
                            self_map_user_namespace: clone_flags != 0,
                        }),
                    )
                    .args([format!("{SANDBOX_ROLE_ARG}{}", role.name())])
                    .stderr(log_file)
                }
                None => ProcessConfig::new(name).stderr(log_file),
            };
            #[cfg(not(target_os = "linux"))]
            let process_config = ProcessConfig::new(name).stderr(log_file);
            mesh.launch_host(process_config, MeshHostParams { runner })
                .await?;
            host
        } else {
            self.local_host.clone()
        };
        Ok(host)
    }

    pub async fn shutdown(self) {
        if let Some(mesh) = self.mesh {
            mesh.shutdown().await;
        }
    }
}
