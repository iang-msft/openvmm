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
#[cfg(target_os = "linux")]
use pal_tracer::TraceConfig;
use std::path::PathBuf;

pub(crate) fn run_vmm_mesh_host() -> anyhow::Result<()> {
    try_run_mesh_host("openvmm", async |params: MeshHostParams| {
        params.runner.run(RegisteredWorkers).await;
        Ok(())
    })
}

#[derive(Inspect)]
pub(crate) struct VmmMesh {
    #[inspect(flatten)]
    mesh: Option<Mesh>,
    #[inspect(skip)]
    local_host: WorkerHost,
    #[inspect(skip)]
    _task: Task<()>,
    #[cfg(target_os = "linux")]
    #[inspect(skip)]
    worker_trace: Option<TraceConfig>,
}

impl VmmMesh {
    pub fn new(
        spawn: &impl Spawn,
        single_process: bool,
        #[cfg(target_os = "linux")] worker_trace_dir: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        anyhow::ensure!(
            !single_process || worker_trace_dir.is_none(),
            "worker tracing requires separate worker processes"
        );
        let mesh = if single_process {
            None
        } else {
            Some(Mesh::new("openvmm".to_string())?)
        };
        let (local_host, runner) = mesh_worker::worker_host();
        let task = spawn.spawn("worker-host", runner.run(RegisteredWorkers));
        #[cfg(target_os = "linux")]
        let worker_trace = worker_trace_dir
            .map(|output_dir| {
                let deny_syscalls = sandbox::load_platform_syscall_denylist()
                    .context("failed to load worker trace syscall denylist")?
                    .into_iter()
                    .map(|entry| entry.name)
                    .collect::<Vec<_>>();
                let syscalls =
                    pal_tracer::resolve_trace_syscalls(&deny_syscalls, sandbox::nr_for_name)?;
                Ok::<_, anyhow::Error>(TraceConfig::new(output_dir, "worker", syscalls))
            })
            .transpose()?;
        Ok(Self {
            mesh,
            local_host,
            _task: task,
            #[cfg(target_os = "linux")]
            worker_trace,
        })
    }

    pub async fn make_host(
        &self,
        name: impl Into<String>,
        log_file: Option<PathBuf>,
    ) -> anyhow::Result<WorkerHost> {
        let log_file: Option<std::fs::File> = if let Some(file) = &log_file {
            Some(
                std::fs::File::create(file)
                    .with_context(|| format!("failed to create log file {}", file.display()))?,
            )
        } else {
            None
        };

        let name = name.into();
        let host = if let Some(mesh) = &self.mesh {
            let (host, runner) = mesh_worker::worker_host();
            let config = ProcessConfig::new(name.clone()).stderr(log_file);
            #[cfg(target_os = "linux")]
            let config = if let Some(trace) = &self.worker_trace {
                config.trace(trace.clone())
            } else {
                config
            };
            mesh.launch_host(config, MeshHostParams { runner }).await?;
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
