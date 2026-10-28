# Alumina — Architecture

**Status:** design statement for the as-built implementation (foundation, boot,
wired single-owner serving runtime; provisional parser layer). This document is
**not** runtime proof — qualification is gated on the
Linux acceptance gates in [verification.md](verification.md). **Canonical source:** `docs/alumina-proxy.md` is
the sole governing specification (no accepted ADRs). Where this document
defines a boundary the spec leaves open, it is a **named design decision
(D1…Dn)**, never a policy change or security relaxation.

## 1. Governing invariants (invariant-led design)

The fixed-profile invariants are the spec's §Invariants (I: 3, II: 2, III: 3,
IV: 5); each names the design element that enforces it. Internal uses keep one
id per invariant (IV-1 is used at §3.5 and §4; III-3 at §3.7). A violation is a
tripwire signal, never a tolerated deviation — there is no tolerated rate of bad
behavior.

| Id | Invariant (spec name) | Enforced by |
|---|---|---|
| I-1 | The Destination-Binding Invariant | validated allowlist + mandatory SNI match (`src/config.rs`), address eligibility (`src/eligibility.rs`), current-cache peer selection with no addresses/cache refs stored in a tunnel (`src/worker.rs`; §5) |
| I-2 | The Authorization-Before-Forwarding Invariant | the two-barrier forwarding gate — A: no client bytes before full ClientHello validation; B: no upstream bytes before the gate opens (D2, `src/gate.rs`) |
| I-3 | The Fail-Closed Invariant | fail-closed defaults in config validation (`src/config.rs`), DNS negative/contradictory outcomes (`src/dns.rs`), non-global-unicast rejection (`src/eligibility.rs`) |
| II-1 | The Zero-Allocation Invariant | boot-preallocated storage (`src/inventory.rs`, §6) + allocator instrumentation (verification.md F3) |
| II-2 | The Resource-Bounds Invariant | fixed build-time limits: `CONNECT_LIMIT` (`src/connect.rs:8`), `MAX_CLIENT_HELLO` (`src/client_hello.rs:6`), log `QUEUE_SLOTS`/`SLOT_BYTES` (`src/log.rs:53-54`), `inventory.rs` constants |
| III-1 | The Ownership Invariant | one poll, one owner: `Serving::run_once` (`src/serving.rs:1257`) under `Runtime::turn` (`src/runtime.rs:252`); the slot table owns its lifecycle and counts (`src/worker.rs`) |
| III-2 | The Generation-Isolation Invariant | generation-tagged socket ids (`src/serving.rs:135-162`), cache-entry generations (`src/cache.rs`), per-tunnel window markers (`src/incident_report.rs:242-245`) |
| III-3 | The Bounded-Work Invariant | the per-visit I/O budget `VISIT_OPS`/`VISIT_BYTES` + timer recheck `TIMER_RECHECK_EVERY` (`src/serving.rs:105-111`); ≤ 8 DNS advances per turn (`src/runtime.rs:252-282`) |
| IV-1 | The State-Transition Invariant | `Stage`/`GatePhase` enums — illegal transitions unrepresentable, every I/O outcome has a permitted transition (`src/serving.rs:340-351`, `src/gate.rs`) |
| IV-2 | The Stream-Parsing Invariant | incremental CONNECT/ClientHello parsers with residual state and original-byte preservation (`src/connect.rs`, `src/client_hello.rs`) |
| IV-3 | The Non-Decrypting Invariant | no accept-side TLS termination on the tunnel path — transparent bit-pipe; the only TLS in-process is the resolver DoT client (`src/startup_dns.rs`, rustls bounded seam) |
| IV-4 | The Byte-Conservation Invariant | write-accounted gate + ordered per-direction forward with no duplication/replay (D5, `src/gate.rs`, `src/serving.rs`) |
| IV-5 | The Deadline Invariant | single monotonic earliest-deadline authority: `poll_timeout` folds every deadline; the sweep runs before dispatch (`src/serving.rs:3159-3223,3241-3269`) |

## 2. Module & ownership decomposition

Single binary crate, one worker thread, no async runtime (spec §Architecture →
I/O model); **all post-boot state is preallocated** (§6).

| Module | Owns (mutating authority) | Citations |
|---|---|---|
| `config` | Parsed config, startup validation; EX_CONFIG 78 | spec §Configuration & DNS; §Keyed configuration schema → Document bound |
| `resolver` | Validated TOML `resolver` array (1..=5 entries); per-entry dial port 53 (bare `IP`) / 853 (`IP#fqdn`, strict-pin); DNS TCP transport (1 conn/1 query, getrandom TIDs) | `:567-614,616-701` (amendment); spec §Configuration & DNS → Resolver selection / Transport |
| `dns` | Wire parsing + staging classification (bounded CNAME, negatives) | spec §Configuration & DNS → Wire parsing / DNS provenance |
| `eligibility` | Address eligibility (globally routable unicast only) | spec §Configuration & DNS → Addresses |
| `cache` | Per-name×type entries, generations, staging, refresh due table, retry/incident, reporting; **tunnels never hold cache refs** | spec §Architecture → Cache Publication; §Configuration & DNS → Cache lifetime |
| `worker` | 512-slot typed decision substrate: per-slot state machine, per-family counts; **owns no sockets** — a pure nonalloc decision core (`src/worker.rs:1-25`) | spec §Architecture → Single Owner |
| `serving` | The serving owner loop, slot lifecycle, and the per-slot traffic buffers (boot-preallocated `TrafficStorage`, `src/inventory.rs`) handed to serving slots; `Serving::run_once` | src/serving.rs:1257; spec §Architecture → I/O model; §Initial resource profile |
| `connect` | Incremental CONNECT (8 KiB) parser, residual state, original bytes | src/connect.rs:8; spec §Protocol contract → CONNECT request |
| `client_hello` | ClientHello (≤64 KiB) parser (two-barrier gate, D2), residual state, original bytes | src/client_hello.rs:6; spec §Protocol contract → TLS ClientHello profile |
| `runtime` | Shared-readiness `Runtime` owner loop: readiness demux, scheduling, timers, gate transitions; `Runtime::turn`; process exit | src/runtime.rs:252; spec §Architecture → Scheduling / → I/O model / → Runtime surface |
| `log` | 256×2 KiB preallocated queue; allocation-free encode; nonblocking sink; drop+count | src/log.rs:53-54; spec §Initial resource profile; §Lifecycle → Log delivery |
| `lifecycle` | SIGTERM + drain (`serving`), exit without deallocating (`runtime`), shutdown status (`log`) | spec §Lifecycle → Shutdown / → Closure |
| `enforcement` | rp2e tripwire/action/monitoring surface (per-control schema: `[any_illegal]` with the four controls `connect_parse`, `host_not_allowlisted`, `tls_profile`, `ech` + keyed `[allowed_fqdn."<fqdn>:<port>"]` tables with per-FQDN `early_data`/`ja4` controls), per-control Action (`notify`|`block`), bounded stdout monitoring, control state | §Tripwire actions, monitoring, and pacing, §Keyed configuration schema, §Per-control enforcement schema |

> **As-built realization.** `src/main.rs` is the single boot owner: preallocate
> serving workspaces → startup DNS window (`run_startup`) → on a Serve decision
> attach the listener and enter `Runtime::serve` (`src/runtime.rs`); one poll
> observes DNS freshness and traffic readiness, and the cooperative turn starts
> due DNS exchanges itself (`main.rs:83-95`; `starts_due_dns_if_idle`
> `runtime.rs:323-347`, called from `Runtime::turn` `runtime.rs:252-282`).
> Provisional parsers live in
> `src/{dns,connect,client_hello,startup_dns}.rs`; the rp2e tripwire/action/
> monitoring surface lives in `src/enforcement/{mod,action,monitor,policy,state}.rs`
> with the validated per-control schema — `[any_illegal]` (`connect_parse`,
> `host_not_allowlisted`, `tls_profile`, `ech`) plus keyed
> `[allowed_fqdn."<fqdn>:<port>"]` per-FQDN `early_data`/`ja4` controls
> (`alumina-cfgk`; 16 KiB document bound) enforced in
> `src/config.rs`. The serving owner is decomposed as `src/serving/{policy,reject,startup,tests}.rs`
> (fixed Refusal policy mapping, rejection effects, startup window, sibling
> test module) and the shared-readiness/runtime and startup-DNS test modules live
> at `src/runtime/tests.rs` and `src/startup_dns/tests.rs`. Buffer reuse is D5b.

## 3. The reactor pattern: one poll, one owner

Alumina is a **classical readiness reactor**: one thread blocks in a single
`mio::Poll` (epoll on Linux, kqueue under host tests), receives readiness edges
for every registered source, and runs a non-blocking handler per edge inside a
bounded turn. There is no async runtime, no future/executor machinery, no
thread pool, and no completion queue: a readiness edge is a hint that an
operation *may* proceed, never evidence that one completed (spec §Architecture
→ I/O model). The reactor is realized by `Serving::preallocate` /
`Serving::run_once` (`src/serving.rs:1019-1076,1257-1305`) under the owner turn
in `Runtime::turn` (`src/runtime.rs:239-282`), and is the only I/O admission
path in the process.

The same poll serves both owner phases: the startup DNS window attaches the
retained DNS transport to it **before** a listener exists
(`src/serving/startup.rs:42-47,178-183`), and a serving decision registers the
listener on the poll created once in `Serving::preallocate`
(`src/serving.rs:1023,1135-1142`), with the DNS transport attached to that same
registry (`src/serving.rs:1173-1177,1220-1240`). `Runtime::serve` is the
process-lifetime loop over it and never returns `Ok` (`src/runtime.rs:366-379`).

### 3.1 Event sources on the single poll

| Source | Token | Interest | Dispatch effect |
|---|---|---|---|
| Listener | `0` | readable | accept batch under the visit budget; a transient accept failure (e.g. `EMFILE`) pauses re-arm for 100 ms instead of hot-looping (`src/serving.rs:1773-1802`) |
| Client socket | `1..=512` | readable / writable | per-slot client arm |
| Upstream socket | `UPSTREAM_BASE + slot` | readable / writable | per-slot upstream arm |
| DNS refresh transport | `DNS_LOCAL` | phase-derived: writable while connecting or backpressured, readable while receiving, both while a write can proceed unwaited (`src/startup_dns.rs:1876-1887`) | raises the DNS freshness flag; the exchange itself advances cooperatively in the same turn |
| SIGTERM self-pipe | `SIGNAL_LOCAL` | readable | first observation fixes the shutdown grace |

Tokens are generation-tagged ids: the low 11 bits select the socket (client,
upstream, or a reserved source id) and the high bits carry the slot generation,
so an event for a slot that closed and was reused is dropped before any socket
is touched (`src/serving.rs:135-162`). The listener, DNS, and signal ids are
disjoint from every connection id, so no two registrations can collide.

### 3.2 The reactor loop

```text
  readiness sources                  one owner turn (single OS thread)
+-------------------------------+    +------------------------------------------------+
| listener              token 0 |--> | 1 resume_listener: re-arm after accept backoff |
| client sockets        1..=512 |    | 2 poll(<=1024 events, min(deadline, caller))   |
| upstream   UPSTREAM_BASE + n  |    | 3 SIGTERM pipe first -> Draining{deadline}     |
| dns refresh        DNS_LOCAL  |    | 4 expire_sweep when now >= next_expiry         |
| sigterm pipe    SIGNAL_LOCAL  |    | 5 pass 1: accept / dns flag / per-slot merge   |
+-------------------------------+    | 6 pass 2: one contiguous visit per slot        |
                                     | 7 dns turn (<=8 advances) / re-arm interest    |
                                     | 8 monitor+incident cadence / log drain         |
                                     +------------------------------------------------+
                                     then loop: the next wait is the nearest of
                                     setup / connect attempt / idle / FIN drain /
                                     grace / log drain / DNS exchange / refresh due
```

### 3.3 The turn, step by step

1. **Re-arm a paused listener** once its backoff has elapsed, so a transient
   accept failure is retried on a bounded cadence (`src/serving.rs:1433-1441`).
2. **One `poll` call.** The timeout is the earliest pending deadline clipped by
   the caller's timeout; `EINTR` is retried, and the event buffer is a ≤1024
   event snapshot preallocated before the startup window and reused every turn
   (`src/serving.rs:1257-1271`).
3. **SIGTERM before traffic.** A readable self-pipe is handled ahead of every
   connection event, so the first signal permanently stops admission, closes
   pending setups, cancels the DNS transport, and fixes the monotonic grace
   (`src/serving.rs:1272-1278,1540-1553`).
4. **Deadline sweep** when `now >= next_expiry`: setup, connect-attempt, relay
   idle, and FIN-drain expiry (`src/serving.rs:3241-3269`).
5. **Coalesce, pass 1**: the listener folds into an accept batch, the DNS token
   into a freshness flag, and every connection token into that slot's merged
   readiness in first-arrival order — skipping idle slots and stale generations,
   so interleaved client+upstream edges for one slot never waste a re-arm
   (`src/serving.rs:1337-1376`).
6. **Dispatch, pass 2**: each distinct slot is visited contiguously with both
   arms ordered by first arrival, under the complete-visit budget, with timers
   rejoining before the next visit once 256 work units have accrued
   (`src/serving.rs:1377-1428,1988-2007`).
7. **Cooperative DNS turn**, only when work is actually due (freshness edge, a
   step that can proceed without waiting, or the exchange deadline): probe
   sweep → corroboration → start one due refresh if the transport is idle →
   at most 8 exchange advances → re-align the DNS interest to the new phase
   (`src/runtime.rs:252-282,417-436`). Shutdown skips this entirely.
8. **Reporting and drain**: monitor and incident cadence checks, then one
   bounded log-sink drain (64 KiB or 16 operations), so a stalled sink cannot
   delay tunnels or deadlines (`src/runtime.rs:274-281`).

The loop exits only through `std::process::exit` — 0 on a clean drain, 70 when
shutdown has to force-close remaining sockets — which skips the owner's
destructors so the boot-owned heap is never freed before the OS reclaims it
(`src/runtime.rs:366-379`).

### 3.4 Timers: one earliest-deadline authority

There is no timer thread, no timerfd, and no timer heap. `poll_timeout` folds
every pending deadline into the single poll timeout: per-slot setup, connect
attempt (clipped to setup), relay idle, FIN drain, shutdown grace, the next log
drain, the outstanding DNS exchange deadline, and the next DNS refresh due time
(`src/serving.rs:3159-3223`). An already-passed deadline yields a zero timeout,
and the sweep runs before dispatch, so readiness can never be dispatched onto
state whose deadline has already expired. Long batches are additionally bounded
by the mid-batch timer recheck of §3.6.

### 3.5 Readiness is a hint, not an outcome

`WouldBlock` and spurious readiness are ordinary results, not errors, and each
consumes budget so a stalled arm cannot spin (`src/serving.rs:100-106`). Every
I/O outcome has an explicit permitted transition (IV-1); only successful writes
advance the forwarding gate and byte accounting (D3, D5). Work left unfinished
by budget exhaustion or re-queueing re-arms interest on the direction that
still has work rather than waiting for a fresh edge (D7,
`src/serving.rs:2017-2080`), and timer expiry never rewrites or splices a
response that has begun (D1).

### 3.6 Fair rotation and the per-visit budget

Fair round-robin with a **64 KiB-or-16-op per-visit budget** (D6); timer recheck
every ≤256 ready-slot visits; unfinished work reschedules without a new
readiness edge; ready queue duplicate-free by construction (D7) — the
application-owned queue of spec §Architecture → Scheduling; deadlines checked
against monotonic clock before any completion transition (spec §Invariants → IV
… The Deadline Invariant).

### 3.7 Why this shape

- **Fixed profile.** All post-boot storage is preallocated (§6); there is no
  per-connection task, boxed future, or wake queue to allocate, so steady-state
  turns stay allocation-free.
- **No synchronization surface.** One owner means no locks, no cross-thread
  handoff, and no scheduling nondeterminism on the relay path.
- **Bounded turn latency.** The visit budget, the 8-step DNS bound, the 64-byte
  signal-drain cap, and whole-record log drops keep any single turn finite, so a
  chatty peer cannot starve deadlines (III-3).
- **Accepted cost.** No CPU parallelism: one blocking handler would stall every
  source, so all socket operations are non-blocking and `WouldBlock` is a normal
  outcome. A completion/proactor model is rejected on purpose — the gate and
  byte-accounting invariants need the exact write-returned-N observation that
  readiness supplies and completion queues hide (D3, D5).

## 4. Tunnel state machine and legal transitions

Tunnel state is a Rust enum; **illegal transitions are unrepresentable**, not
merely rejected (IV-1). The protocol phases below are the `Stage` variants
themselves (`src/serving.rs:340-351`); the former `GATE_OPENING` and `DRAINING`
names are not top-level stages — `GATE_OPENING` is the gate-opening
write-accounting transition inside `upstream_write` (`src/gate.rs:217-238`), and
`DRAINING` is the relay-phase `SideEof` sub-state (`src/serving.rs:358-372`).

```
Stage::ReadingConnect (connection accepted; reading CONNECT headers)
        → (400/403 before 200 begins: Stage::Refusing) → Stage::Closing
                 ↓ AUTHORIZED (allowlisted, 443)
Stage::RunningDecision (allowlist decision + per-attempt DNS peer selection)
Stage::Dialing (≤4×2 s connect attempts clipped to the 10 s setup; 502/504 → Stage::Refusing)
                 ↓ `200` written
Stage::SendingConnected (successful CONNECT completed)
Stage::ValidatingHello (≤64 KiB ClientHello; barriers A/B)
                 ↓ gate opens: `GateOpened` in `upstream_write` (`src/gate.rs:217-238`) —
                   the write-accounting transition after the end of the validated
                   ClientHello (H), never a separate top-level stage
Stage::WritingHello (partial upstream write of the validated ClientHello)
Stage::Relay (bytes flow)
                 ↓ first orderly EOF → the `SideEof` relay sub-state (`src/serving.rs:358-372`)
Stage::Closing (drain half-closes, then close)
(after 200 begins: any error closes with no injected response and no TLS alert)
```

Stage-variant mapping (`src/serving.rs:340-351`):

| Variant | Role in the as-built flow |
|---|---|
| `Idle` | empty slot; no live state |
| `ReadingConnect` | connection accepted; reading CONNECT headers |
| `RunningDecision` | allowlist decision + per-attempt DNS peer selection |
| `Dialing` | upstream connect attempts (≤4×2 s clipped to the 10 s setup deadline; 502/504) |
| `SendingConnected` | `200` written |
| `ValidatingHello` | ≤64 KiB ClientHello validation (barriers A/B, D2) |
| `WritingHello` | partial upstream write of the validated ClientHello; the `GateOpened` write-accounting transition (`src/gate.rs:217-238`) |
| `Relay` | bytes flow; first orderly EOF enters the `SideEof` sub-state (DRAINING) |
| `Refusing` | refusal response written before 200 begins (400/403/502/503/504) |
| `Closing` | close after drain |

Named decisions:

- **D1 response-begin.** `ResponseBegin` ≠ `ResponseComplete`; before 200
  begins failures may send HTTP error, once begun they close with no injected
  response/alert; only a *completed* 200 permits ClientHello inspection.
- **D2 two barriers.** A: no client bytes before full validation (SNI
  normalized-equal to approved hostname). B: no upstream bytes before the gate
  opens (spec §Invariants → I … The Authorization-Before-Forwarding Invariant).
- **D3 gate-opening.** The gate opens **in the same worker transition whose
  successful local-write accounting reaches the end of the validated
  ClientHello (H), before any subsequent upstream read** (spec §Protocol
  contract; `src/gate.rs:217-238`); a crossing
  write forwards trailing `X` from the open point; local-write success ≠ remote
  receipt; arrival ordering never inferred after open.
- **D4 early-activity.** While B is closed the worker may do upstream I/O;
  actual data/EOF/reset terminates setup (metadata-only warn); WouldBlock/
  readiness is not activity.
- **D5 accounting.** Forwarded bytes advance only on successful writes; partial
  writes preserve order (spec §Architecture → I/O model; §Invariants → IV …
  The Byte-Conservation Invariant). **D5a** exactly two per-family
  counters (A/AAAA) per connecting tunnel, never addresses/refs (spec
  §Configuration & DNS → Bounds and retries).
  **D5b** two 128 KiB buffers reused across CONNECT/ClientHello/relay without
  discarding coalesced bytes; relay buffers never enlarge setup limits.

Lifetimes (spec §Lifecycle; §Invariants → IV … The Deadline Invariant): setup
deadline starts at accept, never reset; connect
deadlines clipped to it; idle starts at gate open, reset only on successful
writes; first EOF starts the never-reset 5 s drain; SIGTERM stops accepting +
8 s grace (never extended); resources released exactly once; exit without
deallocating.

## 5. Generations, lifetimes, and anti-alias (T7/T1-merged domains)

Four domains must **not** be merged (spec §Invariants → III. Execution &
Concurrency Invariants, Generation-Isolation; §Architecture → Single Owner):

| Domain | Owner | Invalidation rule | Reuse proof status |
|---|---|---|---|
| G1 Tunnel-slot generation | `worker` (slot substrate) | Connection-scoped state; reuse must never make stale work valid | **design artifact**; nonreuse proof open gate |
| G2 Cache-entry generation | `cache` | Advances on replacement/eviction; rejects obsolete | per-op tag; part of cache slice |
| G3 DNS non-connection lifetime | `cache` | Refresh results not connection generations; no cache refs | structural |
| G4 Reporting window id | `incident_report` | Ids not reusable while a live tunnel retains one; counters saturate (per-tunnel `slot_markers`, `src/incident_report.rs:242-245`; surfaced as `IncidentReport` at `src/serve.rs:75`) | **design artifact**; proof open gate |

A wide integer is not a nonreuse proof; width/exhaustion are recorded artifacts
with construction-and-reuse proof as a future gate.

## 6. Fixed storage and the zero-allocation model

- **T1 boot boundary:** boot init = privilege + config + resolver reads +
  storage/facility init; startup DNS is post-boot and allocation/deallocation-
  free (spec §Architecture → Boot-Time Storage; §Initial resource profile).
- **T3 memory reading:** 128 MiB is **tunnel traffic storage only**; the ban on
  heap alloc/dealloc during serving/refresh does not imply constant total
  memory — process/kernel memory reported separately (spec §Initial resource
  profile; §Architecture → Boot-Time Storage).

| Allocation | Size | Citations |
|---|---|---|
| Tunnel traffic buffers | 512 × 2 × 128 KiB = 128 MiB | spec §Initial resource profile; §Architecture → I/O model |
| Retained serving workspace (per-slot CONNECT head + 2×64 KiB ClientHello inspector + JA4 retention) | 512 × ~152.5 KiB ≈ 76 MiB (design estimate) | spec §JA4 client-fingerprint tripwire → Fixed storage; §Memory accounting — retained serving workspace |
| Config document buffer | 16385 B (16 KiB bound + 1 oversize-probe byte) | spec §Keyed configuration schema → Document bound; §Configuration & DNS |
| CONNECT / TLS pre-auth | ≤8 KiB / ≤64 KiB | spec §Initial resource profile |
| DNS message/records staging | 16 KiB / 128 RRs | spec §Initial resource profile |
| Cache entries | ≤32 names × 2 types, 16 A + 16 AAAA per name | spec §Initial resource profile; §Architecture → Cache Publication |
| Reporting storage | 32/64/512 markers | spec §Initial resource profile |
| Log queue | 256 × 2 KiB | spec §Initial resource profile |
| Ready/timer tables | Fixed slot counts (dup-free) | spec §Architecture → Scheduling |
| Stacks | Bounded worst-case (no recursion); numeric a **design artifact** | spec §Initial resource profile; §Verification |
| mio Poll/Events | Preallocated at boot; op matrix pinned | spec §Architecture → I/O model |

**Outside the 128 MiB budget** (separately accounted): the retained serving
workspace (512 × ~152.5 KiB ≈ 76 MiB, design estimate — JA4 ClientHello
retention reconciled at spec §JA4 client-fingerprint tripwire → Fixed storage), DNS storage, metadata, stacks, executable,
kernel socket buffers (T3). **Do not read the printed inventory 68 MiB as the
reconciled 76 MiB:** the code inventory/print path still reports the
pre-reconciliation figure — `SERVING_WORKSPACE_BYTES = 512 slots × 136 KiB`
(`CONNECT_LIMIT` head + two 64 KiB inspector buffers; `src/inventory.rs:22,25`,
test-pinned at `src/inventory.rs:250`; printed at `src/main.rs:32-37`) ≈ 68 MiB —
while the ~16.5 KiB/slot JA4 ClientHello retention (~8.2 MiB, spec §JA4
client-fingerprint tripwire → Fixed storage) is a spec figure the inventory does
not yet account for; no code allocation exists for it yet.
**Dependency seam (T2/G4):** `mio`+epoll mandated (spec §Architecture → I/O
model); pin version,
enumerate operations, gate each on source review + allocator instrumentation
(verification.md F3) — mio steady-state alloc-freedom is not assumed.

## 7. Startup, logging, shutdown

**Startup** (spec §Configuration & DNS; §Initial resource profile): privilege →
config+resolver → storage → 90 s startup
DNS window (exchanges clipped) → listener open; open early only when all names
usable; at deadline serve if unresolved ≤ allowance else EX_TEMPFAIL 75; no
readiness endpoint; one first-failure warn, suppressed per-type first warnings,
one `startup_name` record per unresolved name plus one final summary. **Logging**
(spec §Lifecycle → Log delivery): allocation-free records ≤2
KiB escaped (the maximum encoded record, including the terminating-newline
framing, fits a 2 KiB slot — `src/log.rs:3-6,53-54`), whole-record drop+count
(never truncate), nonblocking drain under
per-turn budget with partial-write preservation; a stalled sink must not delay
rejection/tunnel I/O/DNS/deadlines; one warn per rejection and per
early-activity close; stdout only. **Shutdown** (spec §Lifecycle → Shutdown;
§Architecture → Runtime surface): SIGTERM only →
stop accepting, 8 s grace, drain, exit without deallocating; `panic="abort"`
is fail-stop, not proof of panic freedom. The convention is enforced by the
deny, not counted by hand: **`unwrap()` is excluded from production paths,
and `expect()` is permitted only where the site carries a stated invariant
argument that makes the call infallible, enforced by lint denial with a
per-site expectation**, each such site carrying that reason string, e.g.
`ClientHello::ja4` (the parser bounds ciphers to `MAX_CIPHERS` and extensions
to `MAX_EXTENSIONS`, so its capacity checks cannot fire),
`FixedHostname::as_str` (construction normalizes to ASCII, so the stored bytes
are always valid UTF-8), and `BindingList::from_slice` (the candidate count is
bounded by `MAX_ADDRESSES`). The control is `#![deny(clippy::unwrap_used,
clippy::expect_used)]` on the production crate roots (`src/lib.rs`,
`src/main.rs`): `cargo clippy --lib -- -D clippy::expect_used -D
clippy::unwrap_used` exiting 0 is the citation of compliance; a test-only
carve-out (`#![cfg_attr(test, allow(...))]`) keeps unit-test targets
compiling. The warning count is deliberately not the control (it already
rotted once, from 30 to 40); the deny is. The dev-only
`src/bin/parser_bench.rs` is its own crate root with no deny
and still reports 14 `expect()`-use warnings under `cargo clippy --bin
parser_bench -- -W clippy::expect_used -W clippy::unwrap_used`. This scopes
`expect()`/`unwrap()` only; it is not a panic-freedom claim — `panic="abort"`
is fail-stop and other panic sources remain. Known residual: an item-level
`#[expect]` has the scope of the whole item, wider than the single site it
justifies (`#[expect]` has no stable statement/expression placement on this
toolchain — E0658), so the control guarantees a disappearing `expect()` is
reported (`unfulfilled_lint_expectations`) and no unjustified item slips in,
but not that a second `expect()` added inside an already-excepted function is
individually argued.

## 8. Deployment and trust boundary

Alumina is responsible for the egress it provides (spec §Deployment boundary;
§Threat model); VPC isolation is deployment-scoped. Runtime prerequisites (spec
§Architecture → Runtime prerequisites; §Deployment boundary): minimal
`FROM scratch`
container holding only `/alumina` (statically linked musl binary) and
`/config.toml` (validated allowlist + resolver set); non-root (`65534:65534`),
empty caps
(`--cap-drop ALL`), `no_new_privs` (`--security-opt no-new-privileges`),
read-only rootfs (`--read-only`), no writable/secret volumes, and a dedicated
appliance identity holding no application secrets or credentials. Confinement
default-denies workload egress except to Alumina's private VPC endpoint
(`tcp:5353`) + explicitly required non-HTTPS platform dependencies across all
routes/families (spec §Deployment boundary), including removing default
Private Google Access
(`199.36.153.8/30:443`) bypasses when unused; exactly one listening socket;
config read once; a validated `resolver` array with per-entry dial port 53
(bare `IP`) / 853 (DoT `IP#fqdn` / strict-pin forms) supplied
(`:567-614,616-701`); no NAT64/DNS64 in the egress path (spec §Deployment
boundary; §Configuration & DNS → Addresses).

- **Separate VPC appliance vs same-pod sidecar:** Because serverless
  multi-container sidecar sandboxes share a single network namespace
  (`CLONE_NEWNET`), VPC firewall identity, and pod restart lifecycle without
  per-UID `CAP_NET_ADMIN` packet filtering, a same-pod sidecar cannot prevent an
  RCE-compromised workload container from bypassing `HTTPS_PROXY` via direct
  `connect(2)` syscalls or resetting in-memory `Block Domain` / `Block All`
  latches by crashing the pod. Positive locking under RCE requires hosting
  Alumina on a separate network-tagged VPC appliance (e.g. a locked-down
  Container-Optimized OS instance with `--network host` at a static internal
  VPC IP; see [README.md](../README.md#reference-vpc-appliance-deployment-pattern)).

## 9. Explicit non-goals

UDP/QUIC, HTTP/2 CONNECT, plain HTTP forwarding, transparent interception,
TLS<1.3, ECH, HTTPS/SVCB substitution, DNS over HTTPS, recursion/follow-up
queries, multi-worker data paths, control plane / readiness / metrics surface,
DNS64/NAT64 compatibility, upstream auth or cert verification, automatic
fallback (spec §Overview; §Protocol contract; §Configuration & DNS; §Architecture
→ Runtime surface; §Deployment boundary).

Cross-map: [verification.md](verification.md) and
[qa-package/README.md](qa-package/README.md) for gate execution and the open
qualification gates.
