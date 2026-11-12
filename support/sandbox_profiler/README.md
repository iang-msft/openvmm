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
    [--profile-dir <PROFILE_DIR>]
```

`<TRACE_DIR>` is the directory created in the trace-collection step. The
profile builder searches this directory and its subdirectories for matching
trace files.

`<WORKER>` is the worker name from
`worker-<worker-name>.<pid>.jsonl`.

`--profile-dir <PROFILE_DIR>` is optional. Without it, the profile builder writes
the generated profile to `<TRACE_DIR>/<WORKER>_worker.rs` and a detailed report
to `<TRACE_DIR>/<WORKER>_worker.log`. With a profile directory, both files are
written there. The Rust file starts with a generated-profile comment, creates a
named deny-all builder, and adds permissions in commented sections. Each nonempty
filesystem permission category has one pathname array and one loop that grants
access only when the resolved path exists on the worker. Syscall and network
configuration follow these loops, and the function returns the builder.
The log contains the trace count, observed filesystem
and network accesses, observed syscalls, and observed policy denials.

The profile builder uses the platform denylist exposed by the `sandbox`
crate.

The generated profile is a starting point and must be reviewed before it is
integrated into the worker.

#### Filesystem policy

For absolute accesses, the profile builder grants exact observed pathnames using
the operation's requested permissions, including failed accesses and accesses
without a recorded result. CWD-anchored accesses instead share one read/execute directory
grant, as described below.
For example, accessing `/etc/hosts` grants `/etc/hosts`, never its parent `/etc`.
Files, directories, symlinks, and unknown object types retain their observed paths,
without consulting the profiler host's filesystem. An independently observed
directory can still receive a directory grant; normalization removes descendants
already covered by that observed ancestor, without inventing ancestor grants.

Syscall results and errno remain in the trace and observation log. Successful opens
alone update descriptor tracking. A nonexistent pathname is still emitted as a
candidate entry in its permission array. The generated loop checks `Path::exists()`
when constructing the profile and skips missing sources, matching the built-in
worker profiles. Failed probes remain in the trace and report, and existing paths
are still granted regardless of the traced result. Entries are not widened to existing parents,
and exact file grants do not authorize creating, renaming, or deleting parent
directory entries.

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

Read access to a successfully inspected regular file produces `.read_exec(...)`
when its captured mode has any owner, group, or other execute bit (`mode & 0o111`).
Otherwise it produces `.read(...)`. If several successful snapshots disagree,
any snapshot with execute bits keeps execution available, independent of event order.
The observation log still describes the syscall's requested RO/RW access.
Read access under `/sys` always produces `.read(...)`, which allows reads and
directory traversal but not execution. Directories, other object types, failed
accesses, and older traces without usable mode metadata retain the conservative
`.read_exec(...)` fallback outside restricted ancestors.
An observed read-only directory above a known non-executable file uses `.read(...)`;
explicit executable file descendants retain separate `.read_exec(...)` grants.
Write access produces non-executable `.read_write(...)` entries regardless of mode.
This is a mode-bit heuristic, not evidence of executable mappings: shared libraries
without execute bits can still need executable mappings, so review their grants.
The existing broad CWD grant is unchanged and can cover non-executable files.
`/proc` and `/tmp` are provided by the sandbox. Accesses remain in the
observations without additional pathname grants. Root-wide grants are also
excluded.

After a successful `openat`, the tracer records an `opened_file` object with the
opened object's `file_type`, full numeric `mode` (including file type and permission
bits), `executable` (whether any `0o111` bit is set), descriptor target `path`, and, for character/block
devices, `device_major` and `device_minor`. It snapshots the returned descriptor
at syscall exit using an `O_PATH` reference, without opening the device for I/O.
Classification is best-effort: another thread can close or reuse a shared
descriptor before the snapshot. Inspection failures record `file_type: "unknown"`.
The original pathname and entry-time lookup base remain unchanged.

Confirmed character/block devices produce exact `.device(...)` grants
instead of ordinary filesystem grants, including metadata-only queries and
`O_PATH` opens. Classification uses captured metadata, including through symlinks.
Unknown paths beneath `/dev`, including failed lookups such as `/dev/sev`,
also produce device grants. Known regular files, directories, symlinks, FIFOs,
and sockets retain ordinary grants even beneath `/dev`. Classification never
inspects the profiler host's filesystem.

Successful `statx` and `newfstatat` calls also record
`path_metadata`, decoded from the returned stat buffer, with the object's type,
mode, execute-bit indicator, and device major/minor numbers. This preserves symlink-following semantics and
avoids inspecting the pathname again on the tracer or profiler host. An unavailable
stat buffer or a `statx` result without `STATX_TYPE` records an unknown type.
When `STATX_MODE` is absent, `mode` and `executable` are null rather than guessed.
Other threads can still modify a shared result buffer before it is read.

Other successful pathname operations record best-effort `path_metadata` using
an `O_PATH` snapshot through the tracee's root, CWD, or directory descriptor.
Readlink, unlink, rename, and `faccessat2(AT_SYMLINK_NOFOLLOW)` inspect the link
itself rather than its target. Unlink and rename snapshot before the syscall
can remove a source; other operations snapshot at exit. Rename also records
`path2_metadata` for its destination at entry. These snapshots are emitted only
when the syscall succeeds; lookup failures record an unknown type.
Concurrent pathname replacement, descriptor reuse, and namespace or symlink
differences can affect these best-effort snapshots.

Device grants remain separate during grant normalization. Independently observed
directory accesses are preserved; read-only ancestors of write or device grants use
`.read(...)` so their mount restrictions compose with the device exception.
Review these ancestors if executable files are also needed beneath them.
The current `.device(...)` API permits read/write/ioctl access even if the
observed open was read-only. Filesystem logs retain `file_path, access mode, retval`.
Device paths anchored to the worker's CWD retain exact `.device(...)` exceptions
resolved against the runtime CWD, alongside the ordinary CWD grant.

The tracer records the worker's startup `cwd` in `trace_started`, before releasing
the child. Each decoded pathname retains the original `path`, a `path_origin`
(`absolute`, `cwd_relative`, `dirfd_relative`, or `empty`), and the entry-time lookup
root in `path_base`. For `AT_FDCWD` this root is the calling thread's CWD; otherwise
it is the directory-FD target. `renameat2` records independent `path2_origin` and
`path2_base` fields for the destination. Results and errno are preserved.

When any access uses the startup-CWD anchor, the generated profile puts the
runtime CWD first in the read/execute array, followed by absolute candidates:

```rust
let cwd = std::env::current_dir().unwrap_or_default();
for path in [
    cwd.to_str().unwrap_or_default(), // Allow read/execute access to the worker's working directory.
    "/usr/lib/libc.so.6",
] {
    let path = std::path::Path::new(path);
    if path.exists() {
        profile = profile.read_exec(path);
    }
}
```

Individual ordinary CWD-anchored candidates, including failed library probes, are
replaced by the shared directory entry. This intentionally permits read/execute access throughout
the worker's current directory instead of restricting access to observed entries.
This grant does not add write or device-I/O permissions.
Exact paths, lookup origins, roots, and results remain in the trace, and resolved
paths and results remain in the observation log. The captured container directory
is not embedded in generated grants.
Directory-FD accesses inherit a CWD-relative anchor from successfully opened
relative directories, including through duplicated descriptors. Other directory-FD
roots remain absolute instead of being mistaken for the CWD. Absolute pathname
accesses remain absolute.
The shared CWD grant does not authorize paths outside that directory. No
profiler-host filesystem lookup is used.

All generated functions return `Builder`, matching the built-in profiles.
Construct them inside worker initialization, before sandbox application or CWD
changes: `let profile = vm_worker().build();`. A failed runtime CWD lookup or
non-UTF-8 CWD produces an empty string, which the existence check skips; absolute
candidates are still processed by the same loop.
No fallback directory is granted. These remain candidate profiles.

Absolute grants are minimized without inventing parents or comparing them with
captured CWD-relative locations. The report's CWD policy contains one read/execute `"."`
grant and any exact relative device exceptions when CWD-anchored accesses were observed. A changed CWD
underneath the startup directory shares this directory grant. An unavailable
startup anchor or a CWD-relative lookup outside it is reported as an error instead
of emitting an incorrect portable grant. Unresolvable lookup roots remain
observations. Older traces can use their first recorded CWD-relative lookup root
as an anchor; regenerate traces when startup CWD equivalence is uncertain.

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
