# Proposal: Connection-Authorization Policy for Mesh

> **Status:** *Draft for team review.*
> **Audience:** OpenVMM / OpenHCL maintainers, mesh maintainers, security reviewers.
> **Scope:** A small, localized addition to the mesh transport layer that lets
> the leader (control) process authorize node-to-node connection establishment.
> **The mechanism is Unix-only**; Windows/ALPC uses a different, non-leader-brokered
> model that needs a separate design (see
> [Transport & product coverage](#transport--product-coverage)). The Unix mechanism
> fully covers OpenHCL and Linux OpenVMM-host.
> **Relationship to other work:** This is a building block that the broader
> worker-sandboxing direction depends on. It is independently scoped and useful,
> and it does **not** depend on any of the (still-proposal-only) sandbox redesign
> being implemented first.

---

## Table of contents

1. [Summary](#summary)
2. [Motivation](#motivation)
3. [Goals & non-goals](#goals--non-goals)
4. [Background: how mesh connections work today](#background-how-mesh-connections-work-today)
5. [Proposed change](#proposed-change)
6. [What this does *not* cover](#what-this-does-not-cover)
7. [Impact analysis](#impact-analysis)
8. [Rollout & migration plan](#rollout--migration-plan)
9. [Testing strategy](#testing-strategy)
10. [Relationship to the broader sandbox effort](#relationship-to-the-broader-sandbox-effort)
11. [Open questions](#open-questions)
12. [Appendix: file-by-file change summary](#appendix-file-by-file-change-summary)

---

## Summary

Today, mesh node-to-node connections are **mechanically brokered** by the leader
(control) process but are **not policy-checked**: when any follower needs to
talk to another node, the leader unconditionally mints an `AF_UNIX` socket pair
and hands one end to each side. There is no hook for the control process to say
"worker A may not open a direct channel to worker B."

This proposal adds an opt-in **`ConnectionPolicy`** to the mesh leader. When a
follower requests a connection to another node, the leader consults the policy
and either creates the socket pair (allow) or returns a failed connection
(deny). The default policy is **allow-all**, preserving today's behavior exactly,
so the change is zero-impact until a consumer opts in.

The enforcement point is a single, already-existing chokepoint
(`run_leader`'s `LeaderRequest::Connect` arm in
`support/mesh/mesh_remote/src/unix_node.rs`), the requester identity is
**unspoofable** (it is the leader-assigned channel the request arrived on, not a
payload field), and the "deny" outcome **reuses an existing wire state**
(`FollowerRequest::Connect(.., None)`). The change is therefore small and
self-contained.

Importantly, a worker-to-worker connection is **not trivially reachable even
today**: to request a connection, a follower must already know the target's
`NodeId` — a random, unguessable 128-bit value (`NodeId::new()`) that can only be
*learned* from mesh wire data (port addresses, `ChangePeer` events), never
guessed. In a clean star, where the control process never routes worker-to-worker
ports, a worker would not learn a peer's `NodeId` at all. The policy therefore
does not patch an open door — it **strengthens the security stance via defense in
depth**: it converts an *emergent, unenforced* property ("peer `NodeId`s happen
not to leak across workers") into an *explicit, enforced* one ("the leader refuses
worker-to-worker connections regardless of which `NodeId`s a possibly-compromised
worker has obtained").

---

## Motivation

Mesh is a **cooperative abstraction, not an enforcement boundary.** Two facts
drive this proposal:

1. **Endpoint passing is unrestricted by design.** Any process — including a
   worker — can create channel pairs locally and pass endpoints over any channel
   it already holds. It is therefore possible for a channel endpoint to "bounce"
   from one worker to another. The convention that "the control process creates
   channels and hands endpoints to workers at spawn" is exactly that — a
   convention, **not a technical requirement**.

2. **The leader brokers sockets without policy.** When two nodes that are not yet
   connected need to exchange bytes, the leader creates the socket pair
   unconditionally for any known follower pair. There is no place for the control
   process to express "these two workers must not be directly connected."

For a capability-style worker-isolation model to hold against a **compromised
worker**, we want the property "a worker can only communicate with the trusted
broker (control process)" to be **enforced**, not merely conventional. With that
property enforced:

- A worker cannot hand a (legitimately granted) capability channel to a peer
  worker, because there is no worker-to-worker edge over which to pass it.
- The only delegation target available to a worker is the control process
  itself, which already holds full authority — making such delegation a no-op.

This does **not** attempt to prevent a worker from *proxying* the results of its
own authority (that is impossible whenever two parties can communicate). It
constrains **who a worker can communicate with in the first place**, which is the
part we *can* enforce.

### Acknowledging the existing implicit barrier

It is worth being precise about what is — and is not — possible today, so the
policy is understood as a *strengthening* rather than a fix for an open hole.
Establishing a worker-to-worker channel already has a non-trivial precondition:
the requesting worker must name the target's `NodeId`, a random 128-bit value
(`NodeId::new()`, `support/mesh/mesh_node/src/common.rs:101-110`) that **cannot be
guessed** and can only be *learned* from mesh wire data the worker has
legitimately handled (a port `Address`, a `ChangePeer` event). In the typical
star — where the control process never routes worker-to-worker ports — a worker
never learns a peer's `NodeId`, so a direct worker-to-worker connection is already
unlikely in practice.

The value of this policy is therefore **defense in depth**, not closing an
otherwise-open door. Without it, the "workers only talk to the control process"
property rests on an *emergent, unenforced* assumption — "peer `NodeId`s never
leak across workers" — that a compromised worker (or a future code path that
inadvertently exposes a `NodeId`) cannot be relied upon to respect. The policy
replaces that assumption with an *explicit, enforced* guarantee: **the leader
refuses worker-to-worker connections regardless of which `NodeId`s a worker has
obtained.** Combined with the unspoofable requester identity, this makes the
boundary hold even when a `NodeId` has leaked.

---

## Goals & non-goals

### Goals

- **G1.** Give the control (leader) process an **opt-in** mechanism to authorize
  or deny node-to-node connection establishment within a `mesh_process` star.
- **G2.** Support, at minimum, a **"star-only"** policy: non-leader nodes may
  connect only to the leader, never to each other.
- **G3.** Support a richer **allowlist ("bless specific pairs")** policy keyed on
  worker identity/role.
- **G4.** **Zero behavioral change** unless a policy is configured (default =
  allow-all).
- **G5.** Provide an **audit-only mode** that logs would-be denials without
  enforcing, to validate a policy against real workloads before turning on
  enforcement.
- **G6.** Keep the change **small, localized, and observable** (rate-limited
  tracing on denials).

### Non-goals

- **N1.** This is **not** a substitute for an OS sandbox. Mesh authorization only
  governs connections established *through mesh*; a worker with ambient OS
  authority can still bypass mesh with raw syscalls (`socket`/`connect`/`open`).
  Making mesh brokering a real boundary requires the OS sandbox to remove that
  ambient authority. See
  [Relationship to the broader sandbox effort](#relationship-to-the-broader-sandbox-effort).
- **N2.** This proposal does **not** change endpoint-passing semantics, the
  encoding layer, or the `Port`/`PortId` model.
- **N3.** It does **not** attempt to gate the external-listener join path,
  `PointToPointMesh`, or per-message authorization. (See
  [What this does *not* cover](#what-this-does-not-cover).)
- **N4.** It does not try to prevent a compromised worker from *proxying* its own
  granted authority to a party it is already allowed to talk to.

---

## Background: how mesh connections work today

This section establishes the exact mechanism the proposal hooks into. All line
references are to the current tree.

### Leader-brokered star topology

`mesh_process` creates a **star**: the control process is the **leader**, and each
spawned worker is a **follower** with a single connection to the leader.
`UnixNode::new(driver)` constructs the node-as-leader and spawns the `run_leader`
task (`support/mesh/mesh_remote/src/unix_node.rs:770`, `:786-792`).
`Mesh::new` calls `UnixNode::new` (`support/mesh/mesh_process/src/lib.rs:455`).

### All inter-node sockets are minted in one place

`run_leader` (`unix_node.rs:220`) is the single chokepoint for inter-node socket
creation. It handles:

- **`LeaderRequest::Invite`** (`unix_node.rs:275-328`) — the parent↔child
  bootstrap performed at spawn.
- **`LeaderRequest::Connect(target_id)`** (`unix_node.rs:248-273`) — a follower
  needing to reach another node. **This is the worker↔worker (and worker↔leader)
  path this proposal gates.**
- **Leadership handoff** (`unix_node.rs:344-380`) — connecting every follower to a
  new leader when leadership is transferred.

When a follower's `LocalNode` needs to route a port event to a node it has no
connection to, its `Connector::connect` sends `LeaderRequest::Connect(node_id)`
to the leader (`unix_node.rs:1019-1037`); it does **not** connect peer-to-peer.

### The requester identity is unspoofable

In the `Connect` arm, the requester is `remote_id = receivers[index].0`
(`unix_node.rs:245`) — i.e., **which leader-channel the request physically
arrived on**, assigned by the leader at invite time. It is **not** a field the
worker controls, so a compromised worker cannot impersonate another worker's
`from` identity. The `target_id` is worker-supplied, which is fine: the policy
authorizes whether `from` may reach `target`.

### "Deny" is already a representable wire state

`FollowerRequest::Connect(NodeId, Option<Socket>)` (`unix_node.rs:155-163`) already
carries an `Option<Socket>`. The follower's handler treats `None` as a failed
connection and logs it (`unix_node.rs:200-210`). Today this only happens on
socket-creation failure; the proposal reuses it as the "policy denied" outcome,
so **no new protocol message is required**.

### NodeIds are random per spawn

`NodeId` is a random UUID minted at invite (`NodeId::new()`,
`support/mesh/mesh_node/src/common.rs:101-110`, used at `unix_node.rs:282`).
Worker *names* (`node_name`) live one layer up in `mesh_process`
(`lib.rs:850`, `:911`), and `invite()` returns the new worker's `NodeId`. This is
why a human-meaningful (role-based) policy needs a `NodeId → role` map maintained
in `mesh_process` (see Tier 2 below).

---

## Proposed change

### New policy abstraction (`mesh_remote`)

```rust
/// The decision returned by a connection policy.
pub enum ConnectDecision {
    /// Permit the connection (create the socket pair).
    Allow,
    /// Refuse the connection (return a failed connection to the requester).
    Deny,
    /// Permit the connection, but record that policy *would* have denied it.
    /// Used to validate a policy against real workloads before enforcing.
    AuditWouldDeny,
}

/// Authorizes leader-brokered node-to-node connection establishment.
pub trait ConnectionPolicy: Send + Sync {
    /// `from` is the (unspoofable) requesting node; `to` is the target node.
    fn authorize(&self, from: NodeId, to: NodeId) -> ConnectDecision;
}

/// Default policy: preserves today's behavior exactly.
pub struct AllowAll;
impl ConnectionPolicy for AllowAll {
    fn authorize(&self, _from: NodeId, _to: NodeId) -> ConnectDecision {
        ConnectDecision::Allow
    }
}
```

### Tier 1 — star-only (no name resolution needed)

The simplest useful policy enforces the star directly. `run_leader` already holds
the leader's own id (`local_node.id()`), so the predicate needs no external
mapping:

```rust
// Allow iff at least one endpoint is the leader (control) node.
fn authorize(&self, from: NodeId, to: NodeId) -> ConnectDecision {
    if from == self.leader_id || to == self.leader_id {
        ConnectDecision::Allow
    } else {
        ConnectDecision::Deny // worker <-> worker
    }
}
```

This delivers the headline property — "workers can only talk to the control
process" — with a single configuration toggle and zero new bookkeeping.

### Tier 2 — bless specific pairs (allowlist)

For cases where two specific workers *should* talk directly, add a default-deny
allowlist expressed in **worker-role** terms (since NodeIds are random):

```
allowed_pairs = [ ("*", "control"), ("storage-worker", "net-worker") ]
```

`mesh_process` maintains a `NodeId → role` map (populated in `spawn_process`
using the `NodeId` returned by `invite()`), and the policy closure resolves
`from`/`to` to roles before checking membership.

### Where it plugs in

The gate is added to the **existing** `Connect` arm (`unix_node.rs:248-273`),
immediately before `new_socket_pair()`:

```rust
LeaderRequest::Connect(target_id) => {
    let remote = senders.get(&remote_id).expect("sender must exist");
    let mut fd = None;
    if let Some(target) = senders.get(&target_id) {
        let decision = policy.authorize(remote_id, target_id); // <-- new
        let create = match decision {
            ConnectDecision::Allow => true,
            ConnectDecision::AuditWouldDeny => {
                tracelimit::warn_ratelimited!(
                    ?remote_id, ?target_id,
                    "node-to-node connection WOULD be denied (audit mode)");
                true
            }
            ConnectDecision::Deny => {
                tracelimit::warn_ratelimited!(
                    ?remote_id, ?target_id,
                    "denied node-to-node connection by policy");
                false
            }
        };
        if create {
            match new_socket_pair() {
                Ok((left, right)) => {
                    target.send(FollowerRequest::Connect(remote_id, Some(left)));
                    fd = Some(right);
                }
                Err(err) => { /* existing error handling */ }
            }
        }
    }
    remote.send(FollowerRequest::Connect(target_id, fd)); // fd = None when denied
}
```

### Plumbing

`Mesh::new(mesh_name)` gains an optional policy (e.g.
`Mesh::new_with_policy(mesh_name, policy)`, keeping `Mesh::new` as a thin
wrapper that passes `AllowAll`). It threads through
`UnixNode::new(driver, policy)` and into the `run_leader` task. The policy is an
`Arc<dyn ConnectionPolicy>`, constructed by `mesh_process` (which has the
semantic knowledge of worker roles) and consumed by `mesh_remote` (which only
needs to call `authorize`).

### Observability

- Denials and audit-mode would-be-denials emit `tracelimit::warn_ratelimited!`
  with `from`/`to` node ids (rate-limited, since a misbehaving worker could
  trigger them repeatedly).
- A clean error should be propagated to the requester's stalled port rather than
  leaving it to hang silently (see [Open questions](#open-questions)).

---

## What this does *not* cover

The `Connect` hook is a complete chokepoint for **star-internal** node-to-node
connections, but the following paths are intentionally out of scope and must be
considered separately:

| Path | Why it is not covered | Mitigation |
|---|---|---|
| **`LeaderRequest::Invite`** (parent↔child bootstrap, `unix_node.rs:275-328`) | Different request type; only the leader/control invites. | Add a separate "who may be invited" hook only if needed. |
| **External join** via `UnixMeshListener` / `join_by_path` (`mesh_process/src/lib.rs:617`) | A process connecting to a filesystem listener socket bypasses the leader's `Connect` path. | Gated by filesystem permissions today; a separate concern. Audit whether any service uses listeners. |
| **Leadership handoff** (`unix_node.rs:344-380`) | Structural follower↔new-leader plumbing that must remain allowed. | Always allowed. **Verified not used in production** (only the `test_handoff_leader` unit test calls `offer_leadership`/`accept_leadership`), so the "policy travels with leadership" concern is moot today — see [Verification findings](#verification-findings). |
| **`PointToPointMesh`** | A wholly separate two-node transport, not leader-brokered. | Out of scope. |
| **Windows / ALPC transport** (`alpc_node.rs`) | **No leader-brokered chokepoint exists** — ALPC nodes connect peer-to-peer to each other's named ports; the only access control is a mesh-wide shared `MeshSecret`. | Needs a separate design (per-pair secrets or Ob-directory ACLs). The Unix hook does **not** apply. See [Transport & product coverage](#transport--product-coverage). |

### Connection-initiation paths: no coverage gap, but mind control-process-intended channels

It is worth being explicit about *who* initiates each connection, since the hook
gates only the follower-initiated `Connect` path. Every place the leader mints a
socket was traced (`new_socket_pair` / `start_connection` in `unix_node.rs`):

| Path | Initiated by | What it connects | Gated? |
|---|---|---|---|
| `Connect` arm (`:255`) | a **follower** (worker) | worker↔worker **or** worker↔leader | **Yes** — this is the hook. |
| `Invite` arm (`:277`, `:287`) | the **leader** | leader ↔ new node (spawn bootstrap) | No — leader-centric, always allowed. |
| Leadership handoff (`:351`) | the **leader** | follower ↔ new leader | No — leader-centric; unused in production. |

**The leader never *directly* creates a worker↔worker socket.** The only
connections it initiates on its own are **leader↔node** (Invite) and
**follower↔new-leader** (handoff) — both leader-centric and exactly the
connections a star-only policy must keep allowed. **All** worker↔worker sockets
are created exclusively through the follower-initiated `Connect` arm, so there is
**no coverage gap**: the hook sees every worker↔worker connection regardless of
how it came to be.

**However, the control process can *indirectly* cause a worker↔worker
connection** by routing or **bridging** endpoints (`Port::bridge`,
`local_node.rs:211`) so that two workers become peers — or by passing a
worker-A-peered port inside worker B's initial message. When that happens, A and B
become peers and the next send triggers a `Connect` *from one of them*. That
connection therefore still surfaces as a follower-initiated `Connect`, which means:

- there is no gap (the hook still sees it), **but**
- a **star-only policy would *deny* it**, even though the control process
  *intended* it.

By default this does not arise: `mesh_process::launch_host` peers each worker's
channels with the **control process** (the `user_port` bridges to a control-held
port, `unix_node.rs:984`), so workers peer with control, not each other.
Intentional cross-worker wiring only occurs if the *application* explicitly
bridges worker channels or passes cross-worker ports in initial messages — which
the current consensus is that OpenVMM/OpenHCL do not do. Any such intentional
channel must be **blessed via the Tier-2 allowlist**, and the `AuditWouldDeny`
rollout (see [Rollout & migration plan](#rollout--migration-plan)) is precisely
how these cases are discovered before enforcement is enabled.

---

## Impact analysis

### API impact

- **Additive only.** A new `ConnectionPolicy` trait + `ConnectDecision` enum +
  `AllowAll` default in `mesh_remote`; a new `UnixNode::new` parameter (or a
  `new_with_policy` variant); an optional policy on `Mesh::new`.
- Existing call sites that use `Mesh::new(name)` / `UnixNode::new(driver)`
  continue to compile and behave identically if `new` defaults to `AllowAll`
  (or via a thin wrapper).

### Behavioral impact

- **Default = allow-all ⇒ zero behavioral change.** Nothing is denied unless a
  consumer configures a restrictive policy.
- With a restrictive policy: a denied `Connect` results in a failed connection to
  the target node; the requester's attempt to route a port to that node fails.
  For the intended use (a worker reaching a forbidden peer), this is the desired
  outcome.

### Performance impact

- **Negligible.** One `authorize` call per *new* node-to-node connection — a rare,
  one-time event per node pair, off the hot data path. There is **no** per-message
  cost; once a connection exists, messages flow directly with no policy check.

### Security impact

- **What it closes:** the latent gap where the leader mints worker↔worker sockets
  with no policy check. With a star-only policy enforced, a worker cannot obtain a
  direct mesh channel to a peer worker — making the capability-delegation concern
  ("worker A hands its broker channel to worker B") structurally impossible within
  mesh, because there is no worker↔worker edge.
- **What it does *not* close:** a worker with ambient OS authority can still
  bypass mesh entirely (raw `socket`/`connect`). This hook is necessary but **not
  sufficient**; it only becomes a real boundary in combination with an OS sandbox
  (N1).
- **Defense in depth:** the unspoofable `from` identity means a compromised
  worker cannot impersonate another worker to obtain a connection it should not
  have.

### Compatibility / risk

- The restrictive policy is a behavioral tightening. Because worker↔worker
  connections are believed to be unused in practice today (but not *guaranteed*
  unused), the **audit-only mode** is the safety valve: deploy it first, confirm
  zero would-be-denials against real workloads, then enforce. See rollout below.

### Transport & product coverage

The mechanism is **Unix-only**, because only the Unix transport has a
leader-brokered connection chokepoint. This matters per product:

| Product | Transport | Covered by this hook? |
|---|---|---|
| **OpenHCL** (paravisor, Linux) | Unix domain sockets | **Yes** — fully covered. This is the primary security-sensitive target (worker isolation in VTL2). |
| **OpenVMM-host on Linux** | Unix domain sockets | **Yes** — covered. |
| **OpenVMM-host on Windows** | ALPC | **No** — different model; see below. |

**Why Windows/ALPC is not covered (verified).** The ALPC node
(`support/mesh/mesh_remote/src/alpc_node.rs`) has **no leader/broker**. Instead:

- Each node exposes a **named ALPC server port** in a shared anonymous Ob
  directory, at a path derived from its `NodeId` (`node_path`, `:482`).
- To reach node B, node A **connects directly** to B's named port
  (`connect_alpc`, `:686-728`) — there is no central broker in the path.
- The **only** authorization is a single mesh-wide shared 256-bit `MeshSecret`
  (`:529`); the accept decision is made by the **target** node's
  `ConnectionRequest` handler, whose sole check is `mesh_secret ==
  conn_data.mesh_secret` (`:1017`).

Consequently any ALPC node holding the shared secret can connect to any other
node whose `NodeId` it knows, and the natural "gate the accept" approach is the
**wrong trust placement** — the accept runs on the (potentially compromised)
target worker, which could simply accept anything. Enforcing an equivalent policy
on Windows therefore needs a separate, more involved design — e.g.,
**per-node/per-pair `MeshSecret`s** distributed selectively by the control
process, or **Ob-directory / ALPC-port ACLs** set by the (trusted) port creator.
This is out of scope for this proposal and is tracked as future work.

Given that the worker-isolation threat model (OpenHCL not trusting the VTL0 guest
or the host; Linux-only sandbox primitives like seccomp/namespaces/Landlock) is
Linux-centric, a Unix-only v1 covers the cases that matter most.

### Verification findings

Two questions from an earlier draft were investigated against the code and are
now resolved:

- **Leadership transfer is not used in production.** A repo-wide search found
  **no** callers of `offer_leadership` / `accept_leadership` outside the
  `test_handoff_leader` unit test (`unix_node.rs:1294-1320`). In OpenVMM/OpenHCL
  the control process that calls `Mesh::new` → `UnixNode::new` is the leader for
  the mesh's lifetime and never resigns.
- **A handed-off policy cannot survive a *compromised* successor — fail closed.**
  Technically a *declarative* policy could be shipped to a new leader by extending
  the `Followers` handoff payload (`unix_node.rs:376`) with serializable policy
  data plus the `NodeId → role` map (a *closure* policy is not serializable). But
  doing so is **not sufficient**, because the leader *is* the enforcement point:
  `run_leader` is where `authorize` runs and where sockets are minted, so a
  compromised new leader simply ignores any transferred policy, and can further
  **MITM all future brokered connections** (it creates both ends of every new
  socketpair), deny service, and control invitations. This matches mesh's own
  documented invariant on `LeadershipOffer` (`unix_node.rs:760-761`): *"One
  trusted process must be the leader at all times or the mesh will fail."* The
  enforcement root must be at least as trusted as everything it governs.
  - **Mitigation / recommendation:** leadership transfer is leader-initiated and
    capability-gated (a worker cannot seize it; the current leader must hand out a
    `LeadershipOffer`), so the only exposure is the trusted control process
    *choosing* to promote an untrusted node. Therefore, when a non-default policy
    is configured, **refuse/assert against leadership transfer (fail closed)**
    rather than attempting to make the policy survive the handoff. If transfer is
    ever required (HA/servicing), restrict it to another **equally-trusted**
    control process and ship the declarative policy + role map alongside
    `Followers`; "who may receive a `LeadershipOffer`" then becomes a
    maximally-trusted meta-policy decision.
- **ALPC has no equivalent chokepoint** (detailed above). The Unix-only scope is
  therefore a deliberate, verified limitation rather than an oversight.

---

## Rollout & migration plan

1. **Land the mechanism with `AllowAll` default.** No behavior change; all
   existing consumers unaffected.
2. **Add the star-only and allowlist policies** behind explicit configuration in
   `mesh_process`.
3. **Run in `AuditWouldDeny` mode** in OpenVMM and OpenHCL:
   - Boot, servicing, and the VMM test suite.
   - Confirm **zero** `"connection WOULD be denied"` events across representative
     workloads. Any hit reveals a legitimate worker↔worker connection that must be
     added to the allowlist (Tier 2) or the topology rethought.
4. **Flip to enforce** (`Deny`) once audit mode is clean.
5. **Document** the policy and its exceptions for mesh consumers.

This staged approach makes the tightening safe by construction: enforcement is
only enabled after empirical confirmation that no legitimate path is affected.

---

## Testing strategy

- **Unit tests in `mesh_remote`:** exercise `run_leader` with a custom
  `ConnectionPolicy` and assert that:
  - an allowed `Connect` yields a working bidirectional connection;
  - a denied `Connect` yields `FollowerRequest::Connect(target, None)` and no
    socket, and the requester observes a failed/clean error rather than a hang;
  - `AuditWouldDeny` still connects but emits the rate-limited trace.
  - leader↔follower and handoff connections remain unaffected by a star-only
    policy.
  Use `use test_with_tracing::test;` so trace assertions work.
- **`mesh_process` integration test:** spawn multiple workers under a star-only
  policy; assert worker↔leader works and a worker↔worker `Connect` is denied.
- **Audit-mode validation:** run the existing OpenHCL/OpenVMM VMM tests with the
  policy in `AuditWouldDeny` and assert no would-be-deny events are produced
  (proving no existing service is impacted).

---

## Relationship to the broader sandbox effort

This change is a **prerequisite enabler** for treating mesh resource-brokering as
a trust boundary, but it is **not** the boundary by itself. The complete picture
has two complementary halves:

- **Mesh connection authorization (this proposal):** the *positive/topology* half
  — the control process becomes the enforced sole communication hub, so a worker
  can only reach the trusted broker.
- **OS sandbox (separate, larger, not-yet-implemented work):** the
  *ambient-authority-removal* half — seccomp/namespaces/capability-drop/uid so a
  worker *cannot acquire resources except through mesh*.

Neither half alone is a security boundary:

- Mesh authorization without the OS sandbox → a compromised worker bypasses mesh
  via raw syscalls.
- OS sandbox without mesh discipline → a locked-down worker has no controlled way
  to receive the resources it legitimately needs.

Together they realize the intended model: **a worker can only obtain resources
the control process brokered to it, and can only communicate with the broker.**
This proposal is deliberately scoped to be independently reviewable and useful,
and it does not require the (proposal-only) sandbox redesign to land first.

For additional context on the worker model, capabilities are conveyed by
possession (object-capability semantics): a channel/handle *is* the authority, so
the design must (a) keep each granted capability **narrow** (a specific
read-only FD, not a broad "open-anything" broker) and (b) bind policy to the
**channel instance** (one receiver per worker) so that "B using A's channel gets
A's authority" — never an escalation. Items (a) and (b) are broker-design
concerns in the control process and are **out of scope** for this mesh change,
which provides only the topology-enforcement piece (the third leg).

---

## Open questions

1. **Requester-side failure semantics.** When a `Connect` is denied, the
   requester's port routing to the target currently stalls (its
   `pending_connections` entry never resolves). Should we propagate a clean
   `RecvError` to the affected port instead of relying on a silent failure?
   (Recommended.)
2. **Leadership transfer — RESOLVED (not used in production; fail closed when a
   policy is set).** No production callers of `offer_leadership` /
   `accept_leadership` exist (only `test_handoff_leader`,
   `unix_node.rs:1294-1320`). Because the leader *is* the enforcement point, a
   transferred policy cannot bind a **compromised** successor; the recommendation
   is to **refuse leadership transfer when a non-default policy is configured**
   (or restrict it to an equally-trusted control process). See
   [Verification findings](#verification-findings).
3. **Policy vocabulary.** Should the policy be expressed purely in `NodeId`
   terms (with `mesh_process` owning the closure and the `NodeId → role` map), or
   should invitations carry an explicit role label so the leader can pass roles
   to `authorize` directly? The former keeps `mesh_remote` simpler; the latter
   keeps the bless-list authoring fully role-based.
4. **Windows / ALPC parity — RESOLVED (no equivalent chokepoint; separate design
   needed).** Verified that `alpc_node.rs` has no leader/broker: nodes connect
   peer-to-peer to named ports, authorized only by a mesh-wide shared
   `MeshSecret`, with the accept decision on the (untrusted) target. This hook is
   Unix-only and covers OpenHCL + Linux OpenVMM-host; Windows OpenVMM-host needs a
   separate approach (per-pair secrets or Ob-port ACLs). See
   [Transport & product coverage](#transport--product-coverage).
5. **External listeners.** Do any in-tree services use `UnixMeshListener` /
   `join_by_path`? If so, they are not covered by this hook and need a separate
   decision.

---

## Appendix: file-by-file change summary

| File | Change |
|---|---|
| `support/mesh/mesh_remote/src/unix_node.rs` | Add `ConnectionPolicy` trait, `ConnectDecision` enum, `AllowAll`. Add a policy parameter to `UnixNode::new` and the `run_leader` task. Add the `authorize` call in the `LeaderRequest::Connect` arm (`:248-273`), reusing the `Connect(.., None)` deny path. Add rate-limited tracing. |
| `support/mesh/mesh_process/src/lib.rs` | Add an optional policy to `Mesh::new` (e.g. `new_with_policy`), thread it into `UnixNode::new`. For Tier 2, maintain a `NodeId → role` map populated in `spawn_process` from the `invite()`-returned `NodeId`, and build the policy closure. |
| (optional) `support/mesh/mesh_remote/src/alpc_node.rs` | Mirror the hook on Windows if ALPC has the same leader chokepoint (Open question 4). |
| Tests | Unit tests in `mesh_remote` for allow/deny/audit; `mesh_process` integration test for star-only enforcement; audit-mode validation across VMM tests. |

### Why the change is small

All star-internal node-to-node connection establishment funnels through a single
function (`run_leader`), the requester identity is already available and
unspoofable, and the "refuse" outcome is already a representable wire state
(`FollowerRequest::Connect(.., None)`). The proposal adds one decision point at
that chokepoint plus configuration plumbing — no new protocol messages, no hot-path
cost, and no behavioral change under the default `AllowAll` policy.
