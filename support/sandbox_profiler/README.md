# Sandbox Profiler

Without this tool, developers must identify a worker's resource requirements
and write its sandbox profile manually, which is tedious and error-prone.
`sandbox_profiler` translates recorded worker behavior into a candidate
profile by converting observed filesystem, network, and system call activity
into the corresponding sandbox policy.

Automatic profile generation has two steps. First, run OpenVMM with worker
tracing enabled. OpenVMM runs VM-related work in separate Mesh worker
processes, with each worker performing a specific function such as running a
VM or emulating a device. The tracer records the files, network endpoints, and
system calls used by the selected worker. Second, run
`sandbox_profiler` against the trace to generate the candidate Rust
sandbox profile.

## Build

Build the standalone profile-builder binary with:

```shell
cargo build -p sandbox_profiler
```

The executable is:

```text
target/debug/sandbox_profiler
```

## Collect worker traces

Worker tracing follows each separate Mesh worker with `ptrace`. It requires
separate worker processes and is not available in single-process mode, where
OpenVMM runs the control logic and all worker roles in one process.

Create a directory for the traces and pass it to OpenVMM:

```shell
mkdir -p <TRACE_DIR>

OPENVMM_SANDBOX_DISABLE=1 \
target/debug/openvmm \
    --worker-trace-dir <TRACE_DIR> \
    --processors 4 \
    --memory 2GB \
    --kernel /path/to/vmlinux \
    --initrd /path/to/initrd \
    --cmdline "console=ttyS0 single" \
    --com1 console
```

`OPENVMM_SANDBOX_DISABLE=1` disables sandbox application at runtime in debug
builds so tracing can observe the resources required by an unrestricted
worker. Release builds ignore this environment variable. Each worker writes
one `.jsonl` trace file named:

```text
worker-<worker-name>.<pid>.jsonl
```

The seccomp filter reports only profile-relevant filesystem, network, and
file-descriptor tracking system calls, plus the system calls in the platform
denylist, to `ptrace`. Other system calls execute normally without being
intercepted, which reduces the performance impact on the worker. OpenVMM
validates every configured denial before launching a traced worker and stops
with an error if tracing support for a configured name is missing.

## Generate a profile

Run the standalone profile-builder binary against the traces collected in the
previous step:

```shell
target/debug/sandbox_profiler \
    <TRACE_DIR> <WORKER> \
    [--output-dir <OUTPUT_DIR>]
```

`<TRACE_DIR>` is the directory created in the trace-collection step. The
profile builder searches this directory and its subdirectories for matching
trace files.

`<WORKER>` is the worker name from
`worker-<worker-name>.<pid>.jsonl`.

`--output-dir <OUTPUT_DIR>` is optional. Without it, the profile builder writes
the generated profile to `<TRACE_DIR>/<WORKER>_worker.rs` and a detailed report
to `<TRACE_DIR>/<WORKER>_worker.log`. With an output directory, both files are
written there. The Rust file starts with a single generated-profile comment
followed by the policy code. The log contains the trace count, observed filesystem
and network accesses, observed syscalls, and observed policy denials.

The profile builder uses the platform denylist exposed by the `sandbox`
crate.

The generated profile is a starting point and must be reviewed before it is
integrated into the worker.

#### Filesystem policy

The profile builder uses successful file accesses in the trace to determine which
directories the worker needs to read or modify. A nonnegative syscall result is
required to generate a filesystem grant. Failed accesses and accesses without a
recorded result remain in the observations. A later
successful access to the same path can still generate a grant using that call's
requested permissions.

Filesystem observations use `file_path, access mode, retval`, for example
`/usr/lib/libc.so.6, RO, SUCCESS` or `/denied/state, RW, EACCES`.
Successful results appear as `SUCCESS`. Error names come from the trace's errno
when available, otherwise from the negative syscall result. Unmapped error
numbers appear as `ERRNO_<number>`; missing outcomes appear as `UNKNOWN`.

For empty-path descriptor operations, the tracer preserves the original
`path: ""` and records `path_target` at syscall entry from `/proc/<tid>/fd/<dirfd>`,
or `/proc/<tid>/cwd` for `AT_FDCWD`. This applies to `newfstatat`, `statx`, and
`faccessat2` with `AT_EMPTY_PATH`, and to `readlinkat` with an empty pathname.
The filesystem observation uses that recorded target. Non-path descriptor
descriptions, such as `anon_inode:[eventpoll]`, and deleted-file annotations are
preserved. When the target is unavailable or absent in an older trace, the
observation uses an explicit description such as
`<empty pathname; statx; dirfd: 8>, RO, SUCCESS`. These descriptor-based
observations do not produce additional pathname grants.

Read access under `/sys` produces `.read(...)` entries, which allow reads and
directory traversal but not execution. Other read access conservatively produces `.read_exec(...)`
entries because the trace does not capture executable mappings of shared
libraries. Review these grants and use `.read(...)` for data that does not
need execution. Write access produces non-executable `.read_write(...)` entries.
`/proc` and `/tmp` are provided by the sandbox. Accesses remain in the
observations without additional directory entries. Root-wide grants are also
excluded.

For relative filesystem paths, the tracer records `path_base` at syscall entry:
the calling thread's current directory for `AT_FDCWD`, or the directory referenced
by the supplied file descriptor. `renameat2` records a separate `path2_base` for
its destination. The original pathname is preserved, and the profile builder
combines it with the recorded base to produce an absolute lookup path, including
for failed lookups whose targets do not exist. The result names the lookup
location, preserving symlinks in the pathname. An unavailable base is recorded as
`null` and the observation retains the original relative pathname instead of
guessing an absolute path. Older traces without these fields retain
file-descriptor tracking as a fallback, but cannot resolve relative `AT_FDCWD`
paths.

#### Network policy

The profile builder generates the narrowest network policy supported by the
sandbox that covers the successful IP activity in the trace. It generates
`Network::None` when no IP communication is observed, `Network::Loopback` when
all observed endpoints are loopback addresses, and `Network::Unrestricted`
when an external endpoint is observed or the destination cannot be determined.
Because unrestricted networking retains the caller's network namespace, review
that result before integrating the generated profile.

#### System call policy

The profile builder reads the platform system call denylist from the
configuration file selected by the `sandbox` crate. It removes entries
observed in the worker trace and writes the remaining denials to the generated
profile. It validates the configured names before reading the trace files and
stops with an error if tracing support for a configured name is missing.

The sandbox also applies its built-in mandatory syscall restrictions whenever
system call filtering is enabled. They are defined in
`support/sandbox/src/unix/seccomp.rs` and are maintained by the sandbox
implementation rather than duplicated here.
