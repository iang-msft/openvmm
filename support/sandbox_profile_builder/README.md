# Sandbox Profile Builder

`sandbox_profile_builder` converts Linux OpenVMM worker syscall traces into a
Rust sandbox profile template. The generated template is written beside the
traces by default so feature teams can own and refine it independently from the
predefined profiles in `support/sandbox/src/profiles`.

## Build

The tool is a default workspace member and is built with OpenVMM:

```shell
cargo build
```

The executable is:

```text
target/debug/sandbox_profile_builder
```

## Collect worker traces

Worker tracing is available on Linux debug builds. Build OpenVMM, create a
trace directory, disable the existing sandbox while collecting its required
accesses, and launch OpenVMM with `--worker-trace-dir`:

```shell
mkdir -p /tmp/openvmm-worker-traces

OPENVMM_SANDBOX_DISABLE=1 \
target/debug/openvmm \
    --worker-trace-dir /tmp/openvmm-worker-traces \
    --processors 4 \
    --memory 2GB \
    --kernel /path/to/vmlinux \
    --initrd /path/to/initrd \
    --cmdline "console=ttyS0 single" \
    --com1 console
```

OpenVMM launches each separate Mesh worker under the in-process `ptrace`
collector. Each worker produces one JSON Lines file:

```text
worker-<worker-name>.<pid>.jsonl
```

Tracing significantly slows worker execution and is intended for profile
development. It is not supported with OpenVMM single-process mode.

## Generate a profile

Pass the directory containing the traces and the worker name:

```shell
cargo run -p sandbox_profile_builder -- /tmp/openvmm-worker-traces vm
```

The default output is:

```text
/tmp/openvmm-worker-traces/vm_worker.rs
```

Use `--output-dir` to select another location:

```shell
cargo run -p sandbox_profile_builder -- \
    /tmp/openvmm-worker-traces vm \
    --output-dir /path/to/feature/source
```

The tool recursively selects trace files matching the requested worker. It
turns observed absolute file paths into directory grants because the sandbox
bind-mounts granted directories at the same absolute paths. Read-like
operations produce `.read(...)` grants, while observed write-like operations
produce `.read_write(...)` grants. `/proc` and `/tmp` use the sandbox's
implicit mounts and are reported under **Filesystem notes**.

The generated source contains these evidence sections:

- **Observed syscalls**
- **Default syscall denial list**
- **Generated syscall denial list**
- **Network observations**
- **Filesystem notes**

The configurable default syscall denial list is `kill`, `tkill`, and `tgkill`.
Any of those observed in the trace are removed from the generated list. The
result is emitted through `Syscalls::Deny`. The sandbox implementation also
applies its mandatory dangerous-syscall baseline whenever `Syscalls::Deny` is
selected.

Network activity is reported but does not automatically widen the profile;
the generated template retains `Network::None`.
