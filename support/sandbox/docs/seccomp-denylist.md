# seccomp denylist — why each syscall is blocked

The sandbox uses a **denylist** (default-allow) seccomp model rather than an
allowlist: a worker's full set of *needed* syscalls cannot be reliably
enumerated, so instead of allowlisting what a worker may call, the filter blocks
a curated set of syscalls a sandboxed worker never legitimately needs —
namespace-escape vectors and historical kernel-CVE fodder. Everything else is
allowed; each blocked syscall triggers the configured deny action (`EPERM` in
debug builds, `KILL_PROCESS` in release).

The baseline set lives in `mandatory_deny_syscall_nrs()` in
[`src/unix/seccomp.rs`](../src/unix/seccomp.rs); the argument-level guards are
built by the `*_deny_rules()` helpers in the same module. The list mirrors what
Docker's default seccomp profile, Kubernetes' `RuntimeDefault`, systemd's
`@system-service`, Chromium's `syscall_sets.cc`, Firejail's `@default`, and
Bubblewrap block by default.

## Namespace nesting

| Syscall | Why it's dangerous |
|---|---|
| `unshare` | Creates fresh namespaces for the caller. Unsharing a new **user** namespace hands the process full capabilities inside it, which it can then use to manipulate mounts/networking and break out. |
| `setns` | Joins an existing namespace via an fd — lets a process re-enter the host's mount/net/pid namespaces, directly escaping confinement. |

## Mount manipulation

| Syscall | Why it's dangerous |
|---|---|
| `mount` | Remount/bind host filesystems into the sandbox or strip protection flags, defeating the `pivot_root` boundary. |
| `umount2` | Detach overlay/protective mounts to expose the underlying host FS (including the moved-away old root). |
| `pivot_root` | Re-point the root filesystem, undoing the sandbox's root confinement. |
| `chroot` | Classic chroot-escape (chroot into a subdir, then `..` out). |
| `move_mount` | New-API mount relocation — same escape surface as `mount`. |
| `fsopen` / `fsconfig` / `fsmount` / `fspick` | New (fsopen-family) mount API to build/attach filesystem contexts; equivalent power to `mount`, so a `mount`-only denial would be trivially bypassed. |
| `open_tree` | Clones a mount tree into an fd — building block for detaching/re-attaching mounts. |
| `mount_setattr` | Clears per-mount `ro`/`nosuid`/`nodev` attributes the sandbox set, weakening its mounts. |

## Kernel-bug surface / privileged features

| Syscall | Why it's dangerous |
|---|---|
| `bpf` | Loads eBPF programs/maps — a large, historically CVE-rich privilege-escalation and info-leak surface. |
| `keyctl` / `add_key` / `request_key` | Kernel keyring management; repeated UAF/refcount CVEs (e.g. CVE-2016-0728) yielding root. |
| `perf_event_open` | Complex privileged interface (CVE-2013-2094) and a side-channel/info-leak vector. |
| `userfaultfd` | Userspace page-fault handling — a powerful exploit primitive (race-window widening, heap grooming); CVE-2021-3347. |
| `io_uring_setup` / `io_uring_enter` / `io_uring_register` | Young, fast-moving async-I/O subsystem with a heavy CVE stream; also performs file/network ops via SQEs, **bypassing syscall-level filters**. |

## Module loading

| Syscall | Why it's dangerous |
|---|---|
| `init_module` / `finit_module` | Load kernel modules = arbitrary kernel-code execution = total compromise. |
| `delete_module` | Unload modules — can remove security modules or trigger unload races. |

## System control

| Syscall | Why it's dangerous |
|---|---|
| `reboot` | Reboot/halt the host — whole-machine DoS. |
| `kexec_load` / `kexec_file_load` | Load a replacement kernel to boot into — full host takeover. |
| `swapon` / `swapoff` | Enable/disable swap — DoS and memory-backing manipulation. |
| `sysfs` | Obsolete FS-type enumeration syscall; legacy, buggy, no legitimate use. |
| `syslog` | Read/control the kernel ring buffer — leaks kernel pointers that defeat KASLR. |
| `iopl` / `ioperm` | Direct x86 I/O-port access / raised I/O privilege — bypasses the kernel to touch hardware. |
| `vhangup` | Virtually hangs up the controlling terminal — tty disruption/hijack. |
| `personality` | Can disable ASLR (`ADDR_NO_RANDOMIZE`, `READ_IMPLIES_EXEC`), weakening exploit mitigations. |
| `acct` | Turns on process accounting to an arbitrary path — arbitrary-file-write and DoS primitive. |

## UTS / hostname

| Syscall | Why it's dangerous |
|---|---|
| `sethostname` / `setdomainname` | Mutate the (host, if un-isolated) UTS namespace — integrity/DoS. |

## Privileged filesystem control

| Syscall | Why it's dangerous |
|---|---|
| `fanotify_init` | System-wide file-access monitoring/permission gating — observe or block other processes' file access. |
| `quotactl` | Disk-quota administration — privileged FS surface and DoS. |

## Capability manipulation

| Syscall | Why it's dangerous |
|---|---|
| `capset` | Sets process capabilities — an attempt to re-grant authority, which must never be reachable inside a deny-all sandbox. |

## Cross-process

| Syscall | Why it's dangerous |
|---|---|
| `ptrace` | Trace/control other processes — read/write their memory & registers to inject code or steal secrets; also historic privesc CVEs. |
| `process_vm_readv` / `process_vm_writev` | Read/write another process's address space directly — secret theft or code injection without `ptrace`. |
| `pidfd_getfd` | Steal an fd from another process via its pidfd — obtain sockets/files the sandbox was never granted. |

## Handle bypass

| Syscall | Why it's dangerous |
|---|---|
| `name_to_handle_at` / `open_by_handle_at` | Open files by opaque FS handle instead of path — bypasses path-based access control and the mount-namespace view to reach files outside the sandbox. |

## Clock manipulation

| Syscall | Why it's dangerous |
|---|---|
| `clock_settime` / `settimeofday` / `adjtimex` / `clock_adjtime` | Set/adjust the **host** clock — breaks TLS/cert validity, log integrity, and time-based security; DoS. |

## NUMA memory policy

| Syscall | Why it's dangerous |
|---|---|
| `set_mempolicy` / `mbind` / `migrate_pages` / `move_pages` | Obscure privileged memory-placement surface with info-leak/side-channel history; no worker need. |

## Debug

| Syscall | Why it's dangerous |
|---|---|
| `kcmp` | Compares two processes' kernel resources — an info-leak that can defeat ASLR by revealing shared resources. |

## Historical / defense-in-depth

| Syscall | Why it's dangerous |
|---|---|
| `vmsplice` | Splices user pages into a pipe — CVE-2008-0600 (local root) and a modern exploitation primitive. |
| `ioprio_set` | Sets I/O priority — I/O-starvation DoS. |
| `modify_ldt` *(x86)* | Modifies the LDT — classic x86 privesc surface (CVE-2015-5157, CVE-2017-17053). |

## Argument-level guards

These syscalls stay **allowed**; only the dangerous argument case is blocked, so
legitimate use keeps working.

| Case | Why it's dangerous |
|---|---|
| `ioctl(TIOCSTI)` | Injects characters into the controlling tty's input queue — "types" commands into a parent shell sharing the tty (CVE-2017-5226). |
| `ioctl(TIOCLINUX)` | Console manipulation (selection/paste buffer) that can likewise spoof/inject terminal input. |
| `clone(CLONE_NEW*)` | `clone` with any new-namespace bit = the `unshare` escape via the thread path; blocked per-bit so plain `pthread_create` (no NEW bits) still works. |
| `clone3(...)` | Flags live behind a pointer seccomp can't inspect, so it could smuggle `CLONE_NEW*`; forced to `ENOSYS` so libc falls back to the arg-filtered `clone`. |
| `prctl(PR_SET_MM)` | Rewrites the process's own memory-map descriptors — forges `/proc/self/maps` and confuses ASLR-based tooling. |
| `socket(AF_PACKET)` | Raw L2 packet sockets — direct network access and a historically exploited path (CVE-2017-7308); no worker need. |
