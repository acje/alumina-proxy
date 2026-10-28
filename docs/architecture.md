# Alumina — Architecture

**Status:** current-state design statement for the as-built implementation
(boot ownership, one poll / one worker, the two-barrier forwarding gate, the
single retained DNS transport, and the boot-fixed storage catalog). This
document is **not** runtime proof — qualification is gated on the
Linux acceptance gates in [verification.md](verification.md) and
[qa-package/README.md](qa-package/README.md)
(byte-canonical: `docs/alumina-proxy.md`, sha256
`e39dd75d33635d582e981bfcb4f91fa92e3f23f2bf9a408c3d7dcd5079cd4401` — never edited;
this document only restates or cites it). Where this document defines a
boundary the spec leaves open, it is a **named design decision (D1…D7)**, never
a policy change or security relaxation. Storage figures are labelled
`as-built | measured | lower bound | design estimate | open proof` (§7);
design estimates are descriptive and carry no runtime or performance claim.

## 1. Governing invariants (invariant-led design)

The fixed-profile invariants are the spec's §Invariants (I: 3, II: 2, III: 3,
IV: 5); each name is the design element that enforces it. Internal uses keep
one id per invariant (IV-1 is used at §4 and §4.4; III-3 at §3.6 and §5). A
violation is a tripwire signal, never a tolerated deviation — there is no
tolerated rate of bad behavior.

| Id | Invariant (spec name) | Enforced by |
|---|---|---|
| I-1 | The Destination-Binding Invariant | validated allowlist + mandatory SNI match (`src/config.rs`), address eligibility (`src/eligibility.rs`), current-cache peer selection with no addresses/cache refs stored in a tunnel (`src/worker.rs`; §5) |
| I-2 | The Authorization-Before-Forwarding Invariant | the two-barrier forwarding gate — A: no client bytes before full ClientHello validation; B: no upstream bytes before the gate opens (D2, `src/gate.rs`) |
| I-3 | The Fail-Closed Invariant | fail-closed defaults in config validation (`src/config.rs`), DNS negative/contradictory outcomes (`src/dns.rs`), non-global-unicast rejection (`src/eligibility.rs`) |
| II-1 | The Zero-Allocation Invariant | boot-preallocated storage (`src/inventory.rs`, §7) + allocator instrumentation (verification.md F3) |
| II-2 | The Resource-Bounds Invariant | fixed build-time limits: `CONNECT_LIMIT` (`src/connect.rs:8`), `MAX_CLIENT_HELLO` (`src/client_hello.rs:6`), log `QUEUE_SLOTS`/`SLOT_BYTES` (`src/log.rs:53-54`), `inventory.rs` constants |
| III-1 | The Ownership Invariant | one poll, one owner: `Serving::run_once` (`src/serving.rs:1261`) under `Runtime::turn` (`src/runtime.rs`); the slot table owns its lifecycle and counts (`src/worker.rs`) |
| III-2 | The Generation-Isolation Invariant | generation-tagged socket ids (`src/serving.rs:135-158`), cache-entry generations (`src/cache.rs`), per-tunnel window markers (`src/incident_report.rs:243-244`) |
| III-3 | The Bounded-Work Invariant | the per-visit I/O budget `VISIT_OPS`/`VISIT_BYTES` + timer recheck `TIMER_RECHECK_EVERY` (`src/serving.rs:105-123`); ≤ 8 DNS advances per turn (`src/runtime.rs:24`) |
| IV-1 | The State-Transition Invariant | `Stage`/`GatePhase` enums — illegal transitions unrepresentable, every I/O outcome has a permitted transition (`src/serving.rs:340-351`, `src/gate.rs`) |
| IV-2 | The Stream-Parsing Invariant | incremental CONNECT/ClientHello parsers with residual state and original-byte preservation (`src/connect.rs`, `src/client_hello.rs`) |
| IV-3 | The Non-Decrypting Invariant | no accept-side TLS termination on the tunnel path — transparent bit-pipe; the only TLS in-process is the resolver DoT client (`src/startup_dns.rs`, rustls bounded seam) |
| IV-4 | The Byte-Conservation Invariant | write-accounted gate + ordered per-direction forward with no duplication/replay (D5, `src/gate.rs`, `src/serving.rs`) |
| IV-5 | The Deadline Invariant | single monotonic earliest-deadline authority: `poll_timeout` folds every deadline; the sweep runs before dispatch (`src/serving.rs:3163-3276`) |

## 2. Module & ownership decomposition

Single binary crate, one worker thread, no async runtime (spec §Architecture →
I/O model); **all post-boot state is preallocated** (§7).

| Module | Owns (mutating authority) | Citations |
|---|---|---|
| `config` | Parsed config, startup validation; EX_CONFIG 78 | spec §Configuration & DNS; §Keyed configuration schema → Document bound |
| `resolver` | Validated TOML `resolver` array (1..=5 entries); per-entry dial port 53 (bare `IP`) / 853 (`IP#fqdn`, strict-pin); DNS TCP transport (1 conn/1 query, getrandom TIDs) | spec §Configuration & DNS → Resolver selection / Transport |
| `dns` | Wire parsing + staging classification (ResponseWorkspace owners table, bounded CNAME, negatives, bailiwick rooting) | `src/dns.rs:12-27,778-830,843-918`; spec §Configuration & DNS → Wire parsing / DNS provenance |
| `eligibility` | Address eligibility (globally routable unicast only) | spec §Configuration & DNS → Addresses |
| `cache` | Per-name×type entries, generations, staging, refresh due table, retry/incident, reporting; **tunnels never hold cache refs** | spec §Architecture → Cache Publication; §Configuration & DNS → Cache lifetime |
| `worker` | 512-slot typed decision substrate: per-slot state machine, per-family counters, precise deadlines; **owns no sockets** — a pure nonalloc decision core | `src/worker.rs:1-25`, `src/worker.rs:371-378`; spec §Architecture → Single Owner |
| `serving` | The serving owner loop, slot lifecycle, and the per-slot traffic buffers and serving workspace; `Serving::run_once` | `src/serving.rs:1261`; `src/inventory.rs`; spec §Architecture → I/O model; §Initial resource profile |
| `connect` | Incremental CONNECT (8 KiB) parser, residual state, original bytes | `src/connect.rs:8`, `src/connect.rs:188-194`; spec §Protocol contract → CONNECT request |
| `client_hello` | ClientHello (≤64 KiB) parser + inspector (two-barrier gate, D2), residual state, original bytes | `src/client_hello.rs:6,18`, `src/client_hello.rs:411-419`; spec §Protocol contract → TLS ClientHello profile |
| `runtime` | Shared-readiness `Runtime` owner loop: readiness demux, scheduling, timers, gate transitions; `Runtime::turn`; process exit | spec §Architecture → Scheduling / → I/O model / → Runtime surface |
| `startup_dns` | Boot-owned reusable DNS transport and the retained serving transport owner (startup window, failover/failback, probe sweep, corroboration, `ActiveExchange` step machine) | `src/startup_dns.rs:215-241,1147-1260,2815-2949`; spec §Configuration & DNS → Startup window |
| `log` | 256×2 KiB preallocated queue; allocation-free encode; nonblocking sink; drop+count | `src/log.rs:53-54`; spec §Initial resource profile; §Lifecycle → Log delivery |
| `lifecycle` | SIGTERM + drain (`serving`), exit without deallocating (`runtime`), shutdown status (`log`) | spec §Lifecycle → Shutdown / → Closure; `src/serving.rs:1544-1560` (on_sigterm), `src/runtime.rs:366-379` (serve loop exits via `process::exit`), `src/log.rs:1952-1959` (shutdown_final record) |
| `enforcement` | Tripwire/action/monitoring surface: per-control schema `[any_illegal]` (four controls) + keyed `[allowed_fqdn."<fqdn>:<port>"]` per-FQDN `early_data`/`ja4` controls, per-control Action (`notify`\|`block`), bounded stdout monitoring, control state | `src/enforcement/action.rs:11-15,161-232`, `src/enforcement/policy.rs:8-18,89-146`, `src/enforcement/monitor.rs:11-115`; spec §Tripwire actions, monitoring, and pacing |
| `incident_report` | 32-name incident windows, per-tunnel slot markers; summary/eligible-loss emission | `src/incident_report.rs:15,243-244`; `src/serve.rs:431-566` |

> **As-built realization.** `src/main.rs` is the single boot owner, walking an
> ownership transfer that never splits across owners: run boot →
> `ServeStorage::boot` over `TrafficStorage::allocate` → `Preallocated::preallocate`
> (serving workspaces + SIGTERM self-pipe armed) → startup DNS window
> (`run_startup`, 90 s, before a listener exists) → on a `Serve` decision
> `attach` the listener and shared DNS and enter `Runtime::serve`. The boot
> transfer is drawn in Fig. 1. One poll observes DNS freshness and traffic
> readiness and the cooperative turn starts due DNS exchanges itself
> (`starts_due_dns_if_idle` under `Runtime::turn`). The serving owner is
> decomposed as `src/serving.rs` plus the submodule set
> `src/serving/{policy,reject,startup,tests}.rs` (Refusal policy mapping,
> rejection effects, startup window, sibling test module); shared-readiness /
> runtime and startup-DNS test modules live at `src/runtime/tests.rs` and
> `src/startup_dns/tests.rs`. The rp2e tripwire/action/monitoring surface lives
> in `src/enforcement/{mod,action,monitor,policy,state}.rs` with the validated
> per-control schema enforced in `src/config.rs`. Buffer reuse is D5b.

```
Fig. 1 — Boot ownership transfer (one owner at a time; transfer by value)

 main        ServeStorage::boot      Preallocated::preallocate     run_startup
 ────        ──────────────────      ──────────────────────────    ──────────
 config ──▶  (validated allowlist        TrafficStorage (128 MiB      StartupDns
 resolver ─▶  + resolver set)           512 x 2 x 128 KiB)           (query/recv/
              ──▶ Worker (512 slots,     Serving (parser+inspector   workspace +
                  clock authority)        workspaces per slot,        bailiwick)
              ──▶ IncidentReport         SIGTERM self-pipe)
              ──▶ LogStore (256 x 2 KiB)
                                              │
                                              ▼
                              resolve_window (90 s, DNS before listener)
                                              │ Serve decision
                                              ▼
   attach (listener + shared DNS) ──▶ Runtime::serve  (never returns Ok;
                                        exits 0 / 70 via process::exit)
```

## 3. The reactor pattern: one poll, one owner

Alumina is a **classical readiness reactor**: one thread blocks in a single
`mio::Poll` (epoll on Linux, kqueue under host tests), receives readiness edges
for every registered source, and runs a non-blocking handler per edge inside a
bounded turn. There is no async runtime, no future/executor machinery, no
thread pool, and no completion queue: a readiness edge is a hint that an
operation *may* proceed, never evidence that one completed (spec §Architecture
→ I/O model). The reactor is realized by `Serving::preallocate` /
`Serving::run_once` (`src/serving.rs:1023,1261-1305`) under the owner turn in
`Runtime::turn`, and is the only I/O admission path in the process.

The same poll serves both owner phases: the startup DNS window attaches the
retained DNS transport to it **before** a listener exists, and a serving
decision registers the listener on the poll created once in
`Serving::preallocate`, with the DNS transport attached to that same registry.
`Runtime::serve` is the process-lifetime loop over it and never returns `Ok`.

### 3.1 Event sources on the single poll

| Source | Token | Interest | Dispatch effect |
|---|---|---|---|
| Listener | `0` | readable | accept batch under the visit budget (`accept_all`); a transient accept failure (e.g. `EMFILE`) pauses re-arm for 100 ms instead of hot-looping (`src/serving.rs:1777-1806`) |
| Client socket | `1..=512` | readable / writable | per-slot client arm (client_readable / client_writable) |
| Upstream socket | `UPSTREAM_BASE + slot` | readable / writable | per-slot upstream arm (upstream_readable / upstream_writable / dial) |
| DNS refresh transport | `DNS_LOCAL` | phase-derived: writable while connecting or backpressured, readable while receiving, both while a write can proceed unwaited | raises the DNS freshness flag; the exchange itself advances cooperatively in the same turn (≤8 steps, `src/runtime.rs:24`) |
| SIGTERM self-pipe | `SIGNAL_LOCAL` | readable | first observation fixes the shutdown grace (on_sigterm) |

Tokens are generation-tagged ids: the low 11 bits select the socket (client,
upstream, or a reserved source id) and the high bits carry the slot generation,
so an event for a slot that closed and was reused is dropped before any socket
is touched (`src/serving.rs:135-158`). The listener, DNS, and signal ids are
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
   accept failure is retried on a bounded cadence.
2. **One `poll` call.** The timeout is the earliest pending deadline clipped by
   the caller's timeout; `EINTR` is retried, and the event buffer is a ≤1024
   event snapshot preallocated before the startup window and reused every turn
   (`src/serving.rs:1261-1271`).
3. **SIGTERM before traffic.** A readable self-pipe is handled ahead of every
   connection event, so the first signal permanently stops admission, closes
   pending setups, cancels the DNS transport, and fixes the monotonic grace
   (`src/serving.rs:1544-1560,1649-1700`).
4. **Deadline sweep** when `now >= next_expiry`: setup, connect-attempt, relay
   idle, and FIN-drain expiry (`src/serving.rs:3245-3276`).
5. **Coalesce, pass 1**: the listener folds into an accept batch, the DNS token
   into a freshness flag, and every connection token into that slot's merged
   readiness in first-arrival order — skipping idle slots and stale generations,
   so interleaved client+upstream edges for one slot never waste a re-arm
   (`src/serving.rs:1337-1376`).
6. **Dispatch, pass 2**: each distinct slot is visited contiguously with both
   arms ordered by first arrival, under the complete-visit budget, with timers
   rejoining before the next visit once 256 work units have accrued
   (`src/serving.rs:1341-1428,1988-2007`).
7. **Cooperative DNS turn**, only when work is actually due (freshness edge, a
   step that can proceed without waiting, or the exchange deadline): probe
   sweep → corroboration → start one due refresh if the transport is idle →
   at most 8 exchange advances → re-align the DNS interest to the new phase
   (§5). Shutdown skips this entirely.
8. **Reporting and drain**: monitor and incident cadence checks
   (`report_monitor_if_due`, `report_incident_if_due`), then one bounded
   log-sink drain (64 KiB or 16 operations), so a stalled sink cannot delay
   tunnels or deadlines (`src/log.rs:66-67`, `src/serve.rs:386,431`).

The loop exits only through `std::process::exit` — 0 on a clean drain, 70 when
shutdown has to force-close remaining sockets — which skips the owner's
destructors so the boot-owned heap is never freed before the OS reclaims it.

### 3.4 Timers: one earliest-deadline authority

There is no timer thread, no timerfd, and no timer heap. `poll_timeout` folds
every pending deadline into the single poll timeout: per-slot setup, connect
attempt (clipped to setup), relay idle, FIN drain, shutdown grace, the next log
drain, the outstanding DNS exchange deadline, and the next DNS refresh due
(`src/serving.rs:3163-3223`). The deadline-presence bitmap
(`DeadlineSlots [u64;8]`, one bit per slot, `src/serving.rs:852-863`) gates the
fold so it iterates only deadline-bearing slots, and `next_expiry` backstops a
stale clear within the bounded recheck window. An already-passed deadline
yields a zero timeout, and the sweep runs before dispatch, so readiness can
never be dispatched onto state whose deadline has already expired. Long batches
are additionally bounded by the mid-batch timer recheck of §3.6.

### 3.5 Readiness is a hint, not an outcome

`WouldBlock` and spurious readiness are ordinary results, not errors, and each
consumes budget so a stalled arm cannot spin (`src/serving.rs:105-123`). Every
I/O outcome has an explicit permitted transition (IV-1); only successful writes
advance the forwarding gate and byte accounting (D3, D5). Work left unfinished
by budget exhaustion or re-queueing re-arms interest on the direction that
still has work rather than waiting for a fresh edge (D7), and timer expiry
never rewrites or splices a response that has begun (D1).

### 3.6 Fair rotation and the per-visit budget

Fair round-robin with a **64 KiB-or-16-op per-visit budget** (D6); timer recheck
every ≤256 ready-slot visits; unfinished work reschedules without a new
readiness edge; ready queue duplicate-free by construction (D7). Two-pass
coalescing builds a `CoalescedBatch` (first-arrival chain per slot, generation
drop mid-batch) so a slot is visited at most once even with interleaved arms.
Deadlines are checked against the monotonic clock before any completion
transition.

### 3.7 Why this shape

- **Fixed profile.** All post-boot storage is preallocated (§7); there is no
  per-connection task, boxed future, or wake queue to allocate, so steady-state
  turns stay allocation-free.
- **No synchronization surface.** One owner means no locks, no cross-thread
  handoff, and no scheduling nondeterminism on the relay path.
- **Bounded turn latency.** The visit budget, the 8-step DNS bound, the
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
write-accounting transition inside `upstream_write` (`src/gate.rs:217-244`), and
`DRAINING` is the relay-phase `SideEof` sub-state (`src/serving.rs:359-372`).

### 4.1 Protocol stages and legal transitions

```
Stage::ReadingConnect (connection accepted; reading CONNECT headers)
        → (400/403 before 200 begins: Stage::Refusing) → Stage::Closing
                 ↓ AUTHORIZED (allowlisted, 443)
Stage::RunningDecision (allowlist decision + per-attempt DNS peer selection)
Stage::Dialing (≤4×2 s connect attempts clipped to the 10 s setup; 502/504 → Stage::Refusing)
                 ↓ `200` written
Stage::SendingConnected (successful CONNECT completed)
Stage::ValidatingHello (≤64 KiB ClientHello; barriers A/B)
                 ↓ gate opens: `GateOpened` in `upstream_write` (`src/gate.rs:217-244`) —
                   the write-accounting transition after the end of the validated
                   ClientHello (H), never a separate top-level stage
Stage::WritingHello (partial upstream write of the validated ClientHello)
Stage::Relay (bytes flow)
                 ↓ first orderly EOF → the `SideEof` relay sub-state (`src/serving.rs:359-372`)
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
| `WritingHello` | partial upstream write of the validated ClientHello; the `GateOpened` write-accounting transition (`src/gate.rs:217-244`) |
| `Relay` | bytes flow; first orderly EOF enters the `SideEof` sub-state (DRAINING) |
| `Refusing` | refusal response written before 200 begins (400/403/502/503/504) |
| `Closing` | close after drain |

### 4.2 Named decisions (D1…D7)

- **D1 response-begin.** `ResponseBegin` ≠ `ResponseComplete`; before 200
  begins failures may send HTTP error, once begun they close with no injected
  response/alert; only a *completed* 200 permits ClientHello inspection.
- **D2 two barriers.** A: no client bytes before full validation (SNI
  normalized-equal to approved hostname). B: no upstream bytes before the gate
  opens (spec §Invariants → I … The Authorization-Before-Forwarding Invariant).
- **D3 gate-opening.** The gate opens **in the same worker transition whose
  successful local-write accounting reaches the end of the validated
  ClientHello (H), before any subsequent upstream read** (spec §Protocol
  contract; `src/gate.rs:217-244`); a crossing
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
- **D6 visit budget.** Fair round-robin with a shared 16-op / 64 KiB per-visit
  budget; timer recheck every ≤256 ready-slot visits (spec §Architecture →
  Scheduling; §Verification).
- **D7 reschedule.** Work left unfinished by budget exhaustion re-arms interest
  on the direction that still has work instead of waiting for a fresh readiness
  edge; the ready queue is duplicate-free by construction.

### 4.3 Lifetimes and deadlines

Lifetimes (spec §Lifecycle; §Invariants → IV … The Deadline Invariant): setup
deadline starts at accept, never reset; connect
deadlines clipped to it; relay idle deadline (300 s, `IDLE_SECS`,
`src/serving.rs:84`) starts at gate open, reset only on successful tunnel-byte
writes; first EOF starts the never-reset 5 s drain; SIGTERM stops accepting +
8 s grace (never extended); resources released exactly once; exit without
deallocating.

### 4.4 The byte-flow trace across the two barriers

The gate (`src/gate.rs`) is the authority over byte flow; the buffers live in
the boot-owned per-slot serving workspace (`SlotWorkspace`, `src/serving.rs:621-697`),
which `Serving::preallocate` splits out of `TrafficStorage` at boot
(`src/serving.rs:1023-1035`). A single slot has two retained buffers — the up
relay buffer (`buf`, with `buf_len`/`fwd` cursors and `parse_rel`/`insp_rel`
consumed-cursors) and the down relay buffer (`down`, with `down_off`/`down_len`)
— plus the gate's accounting offsets. All cursors are
explicit; ordered progress is the monotonic gate ledger.

**Client → upstream (Barrier A).**

```
client ─buffer&parse/&validate─▶ up buffer (buf, parse_rel / insp_rel)
        │
        ├─ ConnectParser.feed (head [u8;8KiB]; first CRLFCRLF ⇒ head_len;        [ReadingConnect]
        │    bytes past head_len stay in buf — early ClientHello, not forwarded)
        ├─ gate.on_connect_head(head_len): hello_start = head_len
        ├─ run_decision → decide(current cache, slot ledger) ⇒ 403/502/504/200   [RunningDecision]
        ├─ dial(peer) → connect_deadline clipped to setup; on connect:           [Dialing]
        │    BODY_200 via flush_down → gate.on_response_ok()                     [SendingConnected]
        ├─ ChInspector.feed(buf[insp_rel..]) ⇒ Inspect::Complete{consumed}       [ValidatingHello]
        │    → client_hello::validate → ValidatedHello(H) witness                (gate.rs:196-201)
        │    → gate.on_hello_validated(H); hello_consumed; stage = WritingHello
        └─ flush_client_upstream: drain_to_upstream writes;                      [WritingHello→Relay]
             gate.upstream_write(n) accumulates upstream_committed (gate.rs:217-244)
             once committed ≥ hello_len ⇒ GateOpened{crossing, relay_from_open}
             relay_from_open = trailing coalesced bytes X past H in the SAME
             successful write (D3); finish_setup ⇒ TunnelIndex; idle_deadline arms
```

Key properties along this path:

- Fragmented CONNECT framing and pipelined `ClientHello` survive TCP read
  boundaries: the parser is incremental with residual state and the inspector
  accepts bytes beyond `head_len` that are simply not forwarded before the gate
  passes (`buffer_and_parse`, `src/serving.rs:2212-2249`).
- A partial successful write advances exactly its own bytes; `WouldBlock` and
  readiness record no bytes (D4/D5); the only transition that can open the gate
  is the write-accounting transition (D3).
- The gate carries a `ValidatedHello` **capability** (mintable only from a
  `HelloAccepted` validator witness, `src/gate.rs:120-142`), so a caller can
  never invent a hello boundary.
- Backpressure: when `fwd < buf_len` the client-readable flush is retried under
  the visit budget and the direction is re-armed, so a stalled upstream never
  stops reading (backpressure/reschedule, D7).

**Upstream → client (Barrier B).**

```
client ◀─ flush_down (down_off/down_len; BODY_200 once, then relay bytes)
        ▲
        ├─ while gate closed: upstream_readable → observe_upstream_read
        │    actual data/EOF/reset ⇒ Activity ⇒ EarlyUpstream(activity)         (gate.rs:249-256, D4)
        │    ⇒ project_tripwire + early_activity log + close_slot (no forwarding)
        └─ once gate open: upstream_readable → relay_upstream_to_client
             up.read(into down[...down_len+room])  (bounded by read_room/visit)
             flush_down: client.write(down[down_off..]) — only Stage::Relay writes
               count as tunnel bytes into the incident window
               (note_incident_tunnel_bytes, src/serving.rs:1942-1953)
```

- Reads go direct-into-slab bounded by the live visit budget: each single read
  is the coarse `READ_CHUNK` 32 KiB (`src/serving.rs:123`) straight into the
  retained 128 KiB directional slab — no stack bounce buffer — still bounded by
  the shared visit budget; in relay each read is paired with the draining flush
  in the same visit, leaving ≥ half the remaining budget for the flush
  (`read_room`, `src/serving.rs:1970-1990`).
- Ordered EOF: each direction records `SideEof::Eof` independently, arms the
  once-started 5 s drain, and `finish_drain` sends a write half-close on a side
  only once that side's accepted bytes have fully drained
  (`src/serving.rs:3077-3137`); `maybe_close_drained` closes the slot exactly
  once when both directions are drained. A reset or deadline closes the slot
  with no half-close ceremony; resources are released exactly once
  (`close_slot`, `src/serving/reject.rs:79`).

### 4.5 The ownership/slot-table layer

The fixed tunnel budget is `MAX_TUNNELS = 512`, with at most
`MAX_PENDING_SETUPS = 128` in-setup; the `Worker` owns the
`[SlotState; 512]` table plus a `free_heap [u16; 512]` min-heap and cached
`occupied`/`pending` counters kept in lockstep with every transition
(`src/worker.rs:371-378,388-463,569-614`). A setup is `SlotState::InSetup`
with its absolute `setup_deadline` and `AttemptLedger` (two per-family counts +
previous-family input for alternation) (`src/worker.rs:159-202,344-354`);
established work is `SlotState::Established`. Handles are linear and typed:
`SlotIndex` for in-setup, `TunnelIndex` after graduation, consumed on release,
so a stale handle can never free a reused slot (9mq9 H1r). `Worker::decide`
reads the deadline and ledger **from the granted slot** and cache seconds from
the single clock authority — never a caller-supplied value (`src/worker.rs:507-525`).

## 5. DNS flow and cache publication

One boot-owned transport, one owner: the `StartupDns` value retains the poll
registration, the fixed `query_buf [u8;512]` / `recv_buf [u8;DNS_MSG_LIMIT+2]`,
the reusable `ResponseWorkspace`, and the `BailiwickZones` set for the process
lifetime (`src/startup_dns.rs:1147-1260`). The transport is a TCP connection for
a bare-IP resolver, or a rustls TLS 1.3 client over its own TCP socket for a
`DoT` resolver (TLS setup allocations confined to that per-connect seam,
`src/startup_dns.rs:1088-1120`); it is relocated only by the state machine
(failover/failback/probe sweep), never by both at once.

```
Fig. 2 — One DNS answer from receipt through later peer selection

transport (recv_buf) ─▶ ResponseWorkspace (owners[128], MAX_TOTAL_RR;   src/dns.rs
                          16 KiB msg bound, MAX_CNAME_LINKS=8, extreme-   :12-27,778-830
                          TTL flag) + BailiwickZones (per-entry zones)    :843-918
  └─ staging classification (negatives, bailiwick checks, generation)
  └─ validated outcome vs captured generation ⇒ publish cache/schedule      cache.rs
  └─ schedule refresh-due/incident update; DNS anomaly facts (bv/rpm/xttl/  schedule.rs
      cc) folded into monitor; resolver relocation facts (dp/pr/ep)         monitor.rs
  └─ later CONNECT: Worker::decide reads current cache via WorkView ⇒
      Peer{addr, family, connect_deadline} (worker.rs:507-525) —            worker.rs
      the tunnel stores only two family counters, never addresses/refs
```

**Startup window** (`resolve_window`, `src/startup_dns.rs:2815-2949`): 90 s
fixed (`STARTUP_WINDOW_SECS`, `src/startup_dns.rs:49`), each exchange deadline
5 s (`EXCHANGE_DEADLINE_SECS`, `src/startup_dns.rs:48`); the schedule's
`select_due` drives per-(name,family) exchanges over the single retained
transport; every configured resolver is exercised via failover, and the
outcome is a `StartupReport` (exchanges/failed/not_attempted/resolved_names +
per-name `NameOutcome`). On return, `startup_decision` applies the canonical
readiness rule — every name usable ⇒ `Full`; unresolved ≤ configured allowance
⇒ `Degraded`; else EX_TEMPFAIL exit 75 (`src/serve.rs:970-988`).

**Cooperative serving turn** — the shared owner advances the retained
transport, never blocking (III-3): per turn, in order,
`step_sweep` (post-window probe of unexercised resolvers, pure sensor;
`src/serve.rs:803-818`) → `step_corroboration` (cross-resolver check on
sustained negatives; `src/serve.rs:832-846`) → `starts_due_dns_if_idle` (start
one due refresh when the transport is idle) → `cooperative_dns_turn` (at most
`DNS_ADVANCE_BOUND = 8` exchange advances, `src/runtime.rs:24`) →
`sync_dns_shared` (re-arm interest to the phase-derived arm) → monitor/incident
cadence → drain_sink.

**One outstanding exchange** is `ActiveExchange` (`src/startup_dns.rs:215-241`):
ordinal/family/absolute `deadline`/`step`/`qlen`/transaction id/`serving` flag/
`probe` flag/`generation` captured at start. The step machine advances at most
one stage per cooperative turn — `Connecting → TlsHandshake → SendReady →
AwaitWritable → Receiving` (`src/startup_dns.rs:247-267`) — with a query write
only after a verifiably connected socket, no kernel send-buffer assumption, and
a response assembled to the exchange deadline; a counted per-exchange failure
advances the schedule backoff exactly once (`TurnResult`, `src/startup_dns.rs:272-283`).
`start_dns_exchange` captures the current cache generation; apply compares the
staged result against that captured generation so an obsolete result cannot
overwrite newer cache state (`src/serve.rs:764-791`; `src/startup_dns.rs:236-240`).
Peer selection for a later CONNECT then reads the *current* cache, so a cache
replacement between attempts takes effect at the next attempt (I-1, §5).

## 6. Generations, lifetimes, and anti-alias

Four domains must **not** be merged (spec §Invariants → III. Execution &
Concurrency Invariants, Generation-Isolation; §Architecture → Single Owner):

| Domain | Owner | Invalidation rule | Reuse proof status |
|---|---|---|---|
| G1 Tunnel-slot generation | `worker` (slot substrate) | Connection-scoped state; reuse must never make stale work valid | **design artifact**; nonreuse proof **open** gate |
| G2 Cache-entry generation | `cache` | Advances on replacement/eviction; rejects obsolete | per-op tag; part of cache slice |
| G3 DNS non-connection lifetime | `cache` | Refresh results not connection generations; no cache refs | structural |
| G4 Reporting window id | `incident_report` | Ids not reusable while a live tunnel retains one; counters saturate (per-tunnel `slot_markers`, `src/incident_report.rs:243-244`, surfaced as `IncidentReport` at `src/serve.rs:75`) | **design artifact**; proof **open** gate |

A wide integer is not a nonreuse proof; width/exhaustion are recorded artifacts
with construction-and-reuse proof as a future gate.

## 7. Fixed storage and the zero-allocation model

- **T1 boot boundary:** boot init = privilege + config + resolver reads +
  storage/facility init; startup DNS is post-boot and allocation/deallocation-
  free (spec §Architecture → Boot-Time Storage; §Initial resource profile).
- **T3 memory reading:** 128 MiB is **tunnel traffic storage only**; the ban on
  heap alloc/dealloc during serving/refresh does not imply constant total
  memory — process/kernel memory is reported separately (spec §Initial resource
  profile; §Architecture → Boot-Time Storage). No RSS figure is asserted here.

### 7.1 The large fixed-structures catalog

Status is one of `as-built` (exact capacity stated in the source and the
structure exists), `measured` (compiler-derived `size_of` figure from A1 —
also as-built), `lower bound` (retained named bytes excluding other per-slot
fields), `design estimate` (spec prose figure, not code-derived), or
`open proof` (future qualification gate). Status describes a *present*
structure or a documented estimate; it is not a runtime or performance claim.

| Structure | Owner | Container / cardinality | Key fields | Role / path | Status | Source |
|---|---|---|---|---|---|---|
| TrafficStorage | `main` boot → `Serving` | 512 `SlotTraffic` pairs × 2 × 128 KiB = `TRAFFIC_STORAGE_BYTES` 128 MiB | `up`/`down` boxed byte pairs | relay byte store; hot per tunnel; transferred in whole (no duplicate blob) | as-built | `src/inventory.rs:10-13` |
| ServeStorage (composition owner) | `main` boot → `Serving` | 1; owns config + cache + worker + schedules + log + incident report + enforcement + StartupDns | work_view pair (config/cache), clock authority | the single construction site of every decision-relevant owner pair; hot for decide/accept/release | as-built | `src/serve.rs:62-81` |
| SlotWorkspace (per slot) | `serving` | 512; holds parser, inspector, gate, cursors + the two transferred 128 KiB buffers | `handle`, `tunnel`, `slot_gen`, `buf`/`buf_len`/`fwd`, `parse_rel`/`insp_rel`, `down`/`down_off`/`down_len`, `directional` SideEof, deadlines | per-slot state machine / relay; hot | as-built | `src/serving.rs:621-697` |
| ConnectParser | per slot in workspace | head `[u8; CONNECT_LIMIT]` (8 KiB) + cursors; `size_of = 8,488` | `head`, `head_len`, `scan_cursor`, `result` | CONNECT head parse; warm (setup only), reused across connections | measured | `src/connect.rs:188-194`; `src/inventory.rs:257-294` |
| ChInspector | per slot in workspace | `buf`+`scratch` `[u8; 64 KiB]×2` + `Option<ClientHello>` retained; `size_of = 148,368` | `buf`, `scan_pos`, `flat`, `scratch`, `hello: Option<ClientHello>`, `consumed` | ClientHello frame+parse, JA4 retention inline; warm (setup), reused | measured | `src/client_hello.rs:411-419`; `src/inventory.rs:257-294` |
| ClientHello (retained inline in inspector) | `client_hello` | ciphers `[u16;8192]`, extensions `[u16;64]`, `alpn [u8;255]`, `sigalgs [u16;64]`, versions/sni; `size_of = 17,264` | fixed-capacity arrays + lens | JA4 fingerprint source; retained across the connection lifetime of the slot | measured | `src/client_hello.rs:61-77`; `src/inventory.rs:257-294` |
| Retained serving workspace (total) | `serving` | `SLOT_WORKSPACE_BYTES = 156,856`; `SERVING_WORKSPACE_BYTES = 512 × 156,856 = 80,310,272` (≈ 76.6 MiB) | parser + inspector incl. retained hello | preallocated at boot, reused across connections; outside the 128 MiB traffic budget | measured | `src/inventory.rs:30,36,257-294` |
| Spec 136 KiB table row | spec table | 512 × 136 KiB = **68 MiB** | — | *historical* pre-reconciliation row at spec §Memory accounting → Retained serving workspace — superseded by the reconciliation estimate (512 × ~152.5 KiB ≈ 76 MiB, `docs/alumina-proxy.md:718`) | design estimate | `docs/alumina-proxy.md:434` |
| Spec reconciled estimate | spec prose | 512 × ~152.5 KiB ≈ **76 MiB** | — | reconciliation of +~16.5 KiB/slot JA4 retention over the 68 MiB row | design estimate | `docs/alumina-proxy.md:206,232,718` |
| Config document buffer | `main` / `config` | `CONFIG_DOC_LIMIT + 1` = 16,385 B | oversize-probe tail byte | config read once at boot; cold | as-built | `src/inventory.rs:17`; `src/config.rs:15` |
| LogStore queue | `log` | 256 slots × 2 KiB = `LOG_QUEUE_BYTES` 512 KiB | slot ring, head, partial-write cursor | allocation-free encode, whole-record drop+count; cold (emergency signal) | as-built | `src/log.rs:53-54`; `src/inventory.rs:46-49` |
| DNS named buffers | `startup_dns` | `query_buf [u8; QUERY_BUF_LEN=512]` + `recv_buf [u8; RECV_BUF_LEN=DNS_MSG_LIMIT+2]` + `workspace: ResponseWorkspace` = `DNS_NAMED_BUFFER_BYTES` | retained `StartupDns` fields; `ActiveExchange` step machine (ordinal/family/deadline/step/qlen/tid/serving/probe/generation) advances over the same transport | retained transport: query/response buffers + reusable response workspace all owned by the `StartupDns` value for the process lifetime; cold except per-exchange turn | lower bound | `src/startup_dns.rs:50-51,1147-1160`; `src/inventory.rs:43-44`; `src/dns.rs:12`; `src/startup_dns.rs:215-241` |
| ResponseWorkspace | `dns` | `owners [Owner; MAX_TOTAL_RR]` (128) + soa/extreme-ttl | per-owner name/cname/addrs `[;MAX_ADDRESSES]` | response parse/staging, reused; warm per exchange | as-built | `src/dns.rs:778-830` |
| BailiwickZones | `startup_dns`/`dns` | `zones[ALLOWLIST_MAX]` + `suffixes[ALLOWLIST_MAX]` + `suffix_owner[ALLOWLIST_MAX]` | DnsName slots, per-entry owners | CNAME rooting gate; cold, built once | as-built | `src/dns.rs:843-918` |
| Worker slot table | `worker` | `slots [SlotState; 512]` + `free_heap [u16; 512]` | InSetup deadline/ledger, Established | decision substrate; hot on accept/decide/release; owns no sockets | as-built | `src/worker.rs:371-378,388-407` |
| DeadlineSlots bitmap | `serving` | `[u64; DEADLINE_SLOT_WORDS=8]` = 64 B | one bit per slot | C50 O(1) fold gate for poll_timeout; hot | as-built | `src/serving.rs:852-863` |
| Poll events snapshot | `serving` | `POLL_EVENTS_CAP=1024` preallocated, reused | readiness/token list | reactor turn pass 1; hot | as-built | `src/serving.rs:105-123,1261-1271` |
| Ready/coalescing tables | `serving` | `CoalescedBatch` first-arrival chain, ready visit state | merged arms, batch generations | pass 1/pass 2; hot | as-built | `src/serving.rs:1341-1428` |
| Monitor facts/actions | `enforcement` | FactCounters (any_illegal/kinds, per-ordinal early_data+ja4, dns_anomaly kinds), ActionCounters (per-scope/per-ordinal), ja4_value `[[u8;36];32]`, ja4_seed/peer, 64-entry capture ring | saturating counters, JA4 value table, `[Option<ConsumedCapture>;64]` | fact fold → tripwire effect → monitor record; the always-emitted summary counters are authoritative; per-domain / per-capture detail batches are best-effort (dropped whole on overflow, never summed); warm | as-built | `src/enforcement/monitor.rs:11-115`; `src/log.rs:55-67` |
| JA4 baseline table | `serving` | `[ [Ja4BaselineEntry;16]; 32 ]` = 512 × 36 B = 18,432 B | per-ordinal set of ≤16 distinct 36-byte JA4 strings (no per-IP element) | first-seen set baseline, never updated after seeding; warm | as-built | `src/serving.rs:584-619`; spec §JA4 client-fingerprint tripwire (docs/alumina-proxy.md:353) |
| Enforcement control table | `enforcement`/`config` | `[Control;4]` + two `[PerFqdnControl;32]` + `count` | any_illegal + early_data/ja4 per FQDN | uniform decide(); warm per violation | as-built | `src/enforcement/action.rs:161-232` |
| Enforcement latch/gate state | `enforcement` | `Enforcement { control, block_all, blocked, monitor, bad_handshake_gate, illegal_fqdn_gate, early_data_gate, ja4_gate }` plus one `FirstSlot` latch per serving slot | all-scope `block_all` latch; per-domain `blocked` bitset; four per-class `WindowedCounter` gates built from the `GateSet` threshold + window (boot defaults `ALL_SCOPE_GATE_DEFAULT_THRESHOLD = 1` and `ALL_SCOPE_GATE_DEFAULT_WINDOW_SECS = 900`, `src/enforcement/state.rs:12,17` — operator configuration; the gate mechanism itself is a fixed constant) | an `AnyIllegal` cause or all-scope early_data/ja4 folds into its class gate; while the (threshold, window) cap is uncrossed the all-scope `Block` is demoted to `BaselineOnly`, and the first crossing lifts it and latches `block_all`; the per-connection `FirstSlot` latch (Armed→Spent once, re-armed on slot reset) applies the first-`AnyIllegal` action at most once per connection | as-built | `src/enforcement/state.rs:216-225,262-334`; `src/enforcement/action.rs:137-153,161-232`; `src/serving.rs:640,780` |
| IncidentReport | `incident_report` | `name_reports [NameReport;32]` + `slot_markers [Option<(u64,u64)>;512]` | per-name windows, per-tunnel markers | per-window incident bytes/attribution; warm | as-built | `src/incident_report.rs:243-244`; `src/serve.rs:75` |
| Cache entries | `cache` | ≤32 names × 2 families × 16 addresses | per-family bindings, generations, freshness/retirement deadlines | current-cache CONNECT authorization + refresh; hot | as-built | `src/cache.rs` |
| Schedules | `schedule` | per-(name,family) refresh-due table + retry/incident transitions | due timestamps, backoff stages, incident N/M/window | drives startup window and serving refresh; warm | as-built | `src/schedule.rs` |
| Stacks | process | bounded worst-case (no recursion) | numeric | design artifact | design estimate | spec §Initial resource profile; §Verification |

### 7.2 Reconciliation with the spec and A1

The spec's retained-serving-workspace numbers are prose **design estimates**;
the as-built inventory and print path report the type-derived figures:

- The spec's §Memory accounting → Retained serving workspace table row gives
  512 × 136 KiB = **68 MiB** (`docs/alumina-proxy.md:434`), reconciled by the
  spec itself to 512 × ~152.5 KiB ≈ **76 MiB** design estimate when the
  ~16.5 KiB/slot JA4 ClientHello retention was added
  (`docs/alumina-proxy.md:206,232,718`). The spec notes both figures are
  estimates, exact sizes fixed at implementation; the 68 MiB number survives
  only as that historical table row.
- A1 measured the retained **types** via `size_of`: `ConnectParser` = 8,488,
  `ChInspector` = 148,368 (incl. the retained `ClientHello` at 17,264 — the
  spec's hand sum `[u16;8192]+[u8;255]+[u16;64]+[u16;64] = 16,895`
  (`docs/alumina-proxy.md:714`) is the estimate; the measured struct adds
  framing/lens and is 17,264), hence
  `SLOT_WORKSPACE_BYTES = 156,856` and
  `SERVING_WORKSPACE_BYTES = 80,310,272` (≈ 76.6 MiB) — near the spec
  reconciliation, and this is the **as-built** figure, pinned by tests
  (`src/inventory.rs:257-294`) and reported at boot by the inventory/print path
  (`BootInventory::phase1`, `src/inventory.rs:166,169`; printed at
  `src/main.rs:34-40`).
- The **JA4 ClientHello retention is implemented** — it is the retained
  `Option<ClientHello>` (17,264 B) inside each `ChInspector`, already counted in
  the `156,856`-byte slot figure. The older "512 × 136 KiB ≈ 68 MiB" inventory
  math describes the pre-retention profile and survives only as the spec's
  historical table row (`docs/alumina-proxy.md:434`); it is **not** what the
  binary prints — the A1 boundary fixture run reports
  `inventory named fixed buffers (lower bound): 214665002 (traffic 134217728 +
  serving workspace 80310272 + dns named buffers 137002)`, i.e. the
  `report.inventory.serving_workspace_bytes()` = 80,310,272 type-derived figure
  (`src/main.rs:34-40`).
- The lower bound of §7.1 deliberately excludes the per-slot gate, capture,
  cursors, and approved hostname (they are small by design but not the type
  surface A1 measured); those fields live in `SlotWorkspace` and are enumerated
  there (`src/serving.rs:621-697`).

**Dependency seam (T2/G4):** `mio`+epoll mandated (spec §Architecture → I/O
model); pin version, enumerate operations, gate each on source review +
allocator instrumentation (verification.md F3) — mio steady-state alloc-freedom
is not assumed.

## 8. Startup, logging, shutdown

**Startup** (spec §Configuration & DNS; §Initial resource profile): privilege →
config+resolver → storage → 90 s startup
DNS window (exchanges clipped) → listener open; open early only when all names
usable; at deadline serve if unresolved ≤ allowance else EX_TEMPFAIL 75; no
readiness endpoint; one first-failure warn, suppressed per-type first warnings,
one `startup_name` record per unresolved name plus one final summary.
**Logging** (spec §Lifecycle → Log delivery): allocation-free records ≤2
KiB escaped (the maximum encoded record, including the terminating-newline
framing, fits a 2 KiB slot — `src/log.rs:53-54`), whole-record drop+count
(never truncate), nonblocking drain under
per-turn budget with partial-write preservation; a stalled sink must not delay
rejection/tunnel I/O/DNS/deadlines; one warn per rejection and per
early-activity close; stdout only. **Shutdown** (spec §Lifecycle → Shutdown;
§Architecture → Runtime surface): SIGTERM only →
stop accepting, 8 s grace, drain, exit without deallocating; `panic="abort"`
is fail-stop, not proof of panic freedom. The `expect()`/`unwrap()` discipline
(`#![deny(clippy::unwrap_used, clippy::expect_used)]` on the production crate
roots `src/lib.rs:1`, `src/main.rs:1`) is the control: `cargo clippy --lib -- -D
clippy::expect_used -D clippy::unwrap_used` exiting 0 is the citation of
compliance (the warning count is deliberately not the control). The dev-only
`src/bin/parser_bench.rs` is its own crate root with no deny, so it is outside
that check by construction. An item-level `#[expect]` has item scope (no stable
statement placement on this toolchain), so a disappearing `expect()` is
reported while a second one inside an already-excepted item is not individually
argued. `panic="abort"` remains fail-stop; no panic-freedom claim is made.

## 9. Deployment and trust boundary

Alumina is responsible for the egress it provides (spec §Deployment boundary;
§Threat model); VPC isolation is deployment-scoped. Runtime prerequisites (spec
§Architecture → Runtime prerequisites; §Deployment boundary): minimal
`FROM scratch`
container holding only `/alumina` (statically linked musl binary) and
`/config.toml` (validated allowlist + resolver set); non-root (`65534:65534`),
empty capabilities
(`--cap-drop ALL`), `no_new_privs` (`--security-opt no-new-privileges`),
read-only rootfs (`--read-only`), no writable/secret volumes, and a dedicated
appliance identity holding no application secrets or credentials. Confinement
default-denies workload egress except to Alumina's private VPC endpoint
(`tcp:5353`) + explicitly required non-HTTPS platform dependencies across all
routes/families (spec §Deployment boundary), including removing default
Private Google Access
(`199.36.153.8/30:443`) bypasses when unused; exactly one listening socket;
config read once; a validated `resolver` array with per-entry dial port 53
(bare `IP`) / 853 (DoT `IP#fqdn` / strict-pin forms) supplied;
no NAT64/DNS64 in the egress path (spec §Deployment
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

## 10. Explicit non-goals

UDP/QUIC, HTTP/2 CONNECT, plain HTTP forwarding, transparent interception,
TLS<1.3, ECH, HTTPS/SVCB substitution, DNS over HTTPS, recursion/follow-up
queries, multi-worker data paths, control plane / readiness / metrics surface,
DNS64/NAT64 compatibility, upstream auth or cert verification, automatic
fallback (spec §Overview; §Protocol contract; §Configuration & DNS; §Architecture
→ Runtime surface; §Deployment boundary).

Cross-map: [verification.md](verification.md) and
[qa-package/README.md](qa-package/README.md) for gate execution and the open
qualification gates.

## 11. Current-state requirements map

This section is the **traceability control** for the live canonical rule set
(`docs/alumina-proxy.md`, sha256 `e39dd75d…`), not a re-narration of the §1
invariant-enforcement map, the §4 byte-flow trace, the §5 DNS flow, or the §7
fixed-storage catalog — those own the mechanism detail and are linked by
prose reference above. Each row resolves one live requirement to: its current
canonical clause (§name + `docs/alumina-proxy.md:LINE` in the repo's existing
citation style), the later amendment that supersedes earlier wording where
applicable, the implementation owner (`module + symbol`, symbol preferred over
line-only, `src/…:LINE` anchors verified against the gate's range check), the
fixed constant/data owner, the focused gate plus exact verification selector
([verification.md](verification.md) command set), and an honest status:

- `implemented` — mechanism in-tree bounded by focused tests that are part of a
  green (past-candidate) selector; a citation alone never upgrades a row.
- `proof-open` — mechanism implemented but the formal qualification/proof gate
  (fuzz loop, non-reuse proof, performance measurement, release gate) is open;
  a live owner bead is named in the row, never orphan prose.
- `deployment-owned` — the live rule is enforced by deployment/operator
  verification (confinement, image, VPC topology, initial deployment), not by
  any proxy-internal property.
- `deferred` — spec-deferred (reserved-but-inert); selecting it is invalid
  configuration.
- `Unknown` — genuinely unresolvable against the complete canonical file; each
  such row names a decision bead. (This revision records none; every live rule
  resolved.)

Every `src/…` or `.md` `file:line` citation — the forms the docs-gate head
regex matches (`scripts/docs_check/check.mjs:92`) — is mechanically
range-checked; the `docs:NNN` clause shorthand and bare `:NNN` continuations
are not independently range-checked. Semantic truth is review-owned, never
inferred from the citation's existence. Rows state the **current** rule:
where later text replaced earlier wording (expect()/clippy control, per-ordinal
JA4 baseline and storage, 2-KiB log geometry, 5/900 refresh band, 5-second
exchange deadline), the row says so instead of copying the earlier text.

### 11.1 Security & resource invariants

| Id — invariant | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| I-1 Destination-Binding | §Invariants → I (docs:251); §Configuration & DNS → Cache lifetime / Bounds and retries (docs:117-125) | allowlist stays the keyed per-FQDN surface; stale-serving window governs stale admission | `src/worker.rs Worker::decide`, `src/cache.rs servable` (151), `src/eligibility.rs is_eligible` (13) | `ALLOWLIST_MAX` `src/config.rs:17`; cache `Entry` | lib cache/eligibility rows of `mid full`; `boundary phase1` | implemented |
| I-2 Authorization-Before-Forwarding | §Protocol contract (docs:70-74); §Invariants → I (docs:252) | two-barrier D2 (§4.2) | `src/gate.rs TunnelGate` (93), `src/client_hello.rs validate` (1108) | — | gate/serving lib rows in `mid full`; `e2e relay` | implemented |
| I-3 Fail-Closed | §Invariants → I (docs:253); §Configuration & DNS (docs:101) | — | `src/config.rs` validation, `src/cache.rs` eviction, `src/startup_dns.rs` fail-closed DoT | — | `mid boot`; `mid full` | implemented |
| II-1 Zero-Allocation | §Invariants → II (docs:257); §Initial resource profile (docs:197) | first-party scope + rustls bounded seam (docs:623-625) supersede the dependency-inclusive reading | `src/alloc.rs` witness, `src/inventory.rs` preallocation, `src/startup_dns.rs build_tls_connection` (1101) seam | §7 catalog | `mid full` (alloc-witness lib + gate-only), `mid foundations` | implemented (candidate-bound via alloc-witness) |
| II-2 Resource-Bounds | §Invariants → II (docs:258); §Initial resource profile table (docs:199-230) | profile rows folded in place by SP-007 (docs:1090-1096: 5/900 and 30/900) | `src/worker.rs` / `src/serving.rs` / `src/log.rs` / `src/config.rs` caps | per-row constants (§11.3-11.6) | `mid boot` (storage inventory); `mid full` | implemented |
| III-1 Ownership | §Invariants → III (docs:262); §Architecture → Single Owner (docs:187) | — | `src/runtime.rs Runtime::turn`, `src/serving.rs run_once` (1261) | — | `mid full` (runtime/serving lib) | implemented |
| III-2 Generation-Isolation | §Invariants → III (docs:263); §Architecture → Cache Publication (docs:188) | G1/G4 non-reuse proof open; width/exhaustion are recorded artifacts (docs/architecture.md:491-492), B4 owns status | `src/serving.rs` generation-tagged tokens, `src/cache.rs Generation::checked_next` (59), `src/incident_report.rs slot_markers` | `Generation` token | `mid full` (G1 tunnel-slot + G4 reporting-window non-reuse rows) | proof-open (B3/B4: alumina-cdwui.6/.7; exhaustion: alumina-v52be; B1/B2 delivered 2e061e3) |
| III-3 Bounded-Work | §Invariants → III (docs:264); §Architecture → Scheduling (docs:189) | — | `src/serving.rs` `VISIT_OPS`/`VISIT_BYTES` (105-106), `TIMER_RECHECK_EVERY` (111) | 16 op / 64 KiB / 256 visits | `mid full` (serving lib) | implemented |
| IV-1 State-Transition | §Invariants → IV (docs:268); §Architecture → I/O model (docs:190) | — | `src/serving.rs Stage`, `src/gate.rs GatePhase` | — | `mid full` (serving/gate lib) | implemented |
| IV-2 Stream-Parsing | §Invariants → IV (docs:269); §Protocol contract (docs:74) | — | `src/connect.rs ConnectParser` (src:8), `src/client_hello.rs ChInspector` (6) | `CONNECT_LIMIT` 8 KiB, `MAX_CLIENT_HELLO` 64 KiB | `mid boot` (strict parser); `mid full` | implemented |
| IV-3 Non-Decrypting | §Invariants → IV (docs:270) | — | transparent bit-pipe; rustls only on the resolver DoT seam | — | `e2e relay`; `mid full` | implemented |
| IV-4 Byte-Conservation | §Invariants → IV (docs:271); §Architecture → I/O model (docs:190) | write-advance-only accounting (D5, D5b buffer reuse) | `src/gate.rs upstream_write` (217), `src/serving.rs` relay paths | — | `mid full`; `e2e relay` | implemented |
| IV-5 Deadline | §Invariants → IV (docs:272); §Lifecycle (docs:240-243); §Initial resource profile (docs:230) | single earliest-deadline authority folds every deadline | `src/serving.rs DeadlineSlots` (863), `expire_sweep` (3245), `src/worker.rs` `SETUP_DEADLINE_SECS` (51) / `CONNECT_DEADLINE_SECS` (55) | 10/2/300/5/8 s | `mid full`; `e2e shutdown` | implemented |

### 11.2 CONNECT & ClientHello contract

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| CONNECT head incremental 8 KiB; exact accept/reject discriminants | §CONNECT request (docs:76-83); Vec 36 (docs:455-457) | Vec 36 replaces the coarse `NotHttp` catch-all with exact discriminants (docs:457) | `src/connect.rs ConnectParser`, `ConnectError` (47), `ConnectHeadReason` (116) | `CONNECT_LIMIT` (8 KiB, `src/connect.rs:8`) | `mid boot`; `mid full` | implemented |
| CONNECT CRLF-only; bare-CR and bare-LF rejection | L3 (docs:361-363); P-A6b fold (docs:1384-1392) | L3 tightens the bare-LF rejection to a strict CRLF-only rule (docs:363) | `src/connect.rs bare_carriage_return` / `bare_line_feed` | — | `mid full` (`rejects_bare_*` tests, `src/connect.rs:832-847`) | implemented |
| CONNECT Content-Length canonical digits | §CONNECT Content-Length canonical digits (docs:419-421) | literal `0` only; leading-zero spelling rejected | `src/connect.rs` head validation | — | `mid full` | implemented |
| CONNECT header-line count bound | Vec 35 (docs:462-466) | — | `src/connect.rs` `MAX_HEADER_LINES` (13), `TooManyHeaderLines` | 16 header lines | `mid full` | implemented |
| ClientHello TLS 1.3-only profile; framing and identity | §TLS ClientHello profile (docs:85-90); L8 (docs:369-371), L9 (docs:373-375), L10 (docs:377-379), L11 caps (docs:381-393) | L8 rejects non-`host_name`; L9 pins the 4-byte min payload; L10 SNI trailing-dot normalization; L11 promotes caps into the profile | `src/client_hello.rs validate` (1108), `parse_server_names` (771), caps (6,18,21,24) | `MAX_VERSIONS` 32, `MAX_EXTENSIONS` 64 | `mid boot`; `mid full` | implemented |
| ClientHello handshake-message 16 KiB bound | Vec 34 (docs:451-453) | content-level classification bound, not a buffer change | `src/client_hello.rs MAX_HANDSHAKE_LEN` (18), `HandshakeTooLarge` | 16 KiB | `mid full` | implemented |
| Sigalg bound 64; `count:02` saturates | SP-006/RT-001 (docs:1066-1088); P-A6b (docs:1401-1410) | RT-001 removes the silent-truncation path for the JA4 hash input | `src/client_hello.rs MAX_SIGALGS` (40), `parse_sig_algs`, `count_token` (966) | 64 sigalgs | `mid full` (`sigalgs_over_max_*` tests, `src/client_hello.rs:2222-2243`) | implemented |
| ECH rejection incl. `0xffce` / `encrypted_server_name` | §TLS ClientHello profile → ECH (docs:89); §Reject unknown ECH codepoint (docs:1527-1535) | `0xffce` treated as ECH-present, consistent with `0xfe0d`; never stripped | `src/client_hello.rs has_ech`, `ChError::EchPresent` | — | `mid full` (`rejects_esni_codepoint`, `src/client_hello.rs:1476`) | implemented |
| Forwarding gate opens only on the write-accounting transition (D3) | §Protocol contract (docs:72); D3 (§4.2) | gate opens in the same worker transition accounting the successful end-of-ClientHello write; `ValidatedHello` capability | `src/gate.rs TunnelGate` (93), `ValidatedHello` (120), `upstream_write` (217) | — | `mid full` (gate lib); `e2e relay` | implemented |
| Response corpus 400/403/502/503/504; oracle acknowledgement | §CONNECT request → Errors (docs:83); SP-008 (docs:1098-1106) | threat-model acknowledgement only; no body/behavior change (docs:1105-1106) | `src/serving/policy.rs Refusal` (8-39) for 400/403/502/504; `src/serving.rs BODY_503` (202, written at 1815) for the capacity class; emitted via `src/serving/reject.rs` | — | `mid full`; `e2e relay` | implemented |

### 11.3 Configuration & resolver rules

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| 16 KiB config document bound | §Configuration & DNS (docs:94); §Keyed configuration schema → Document bound (docs:831-840) | 4096 → 16384 (docs:833); oversize rejected without truncation | `src/config.rs load_config_document` (704-713), `parse_config_document` (732-736), `CONFIG_DOC_LIMIT` (15) | 16 KiB + oversize-probe tail | `mid boot`; parser-real fit tests (`compact_32_*`, `src/config.rs:1986-2042`) | implemented |
| Keyed allowlist 1..=32; mandatory `early_data` + `ja4`; optional `cname_bailiwick` | §Keyed allowlist tables (docs:739-789); SP-014 (docs:1325-1330) | positional `[actions]` removed (docs:741); SP-014 adds optional `cname_bailiwick`; its (docs:1329-1330) sentence omits `ja4` — the §Keyed allowlist tables text (docs:788-789) governs (mandatory) | `src/config.rs parse_allowed_fqdn_table` (998), `Fqdn` (22) | `ALLOWLIST_MIN`/`MAX` (`src/config.rs:16-17`) | `mid boot`; `mid full` | implemented |
| Per-control schema T2/T3/T6; unified `decide()` | §Per-control enforcement schema (docs:893-971); §Configuration surface (docs:315-336) | per-control `scope` uniformly `connection\|fqdn\|all` (`domain` in spec, spelled `fqdn` in config, `parse_per_fqdn_scope` src/config.rs:942-952) supersedes SP-002's early-data `domain\|all` refusal (docs:1016-1026); F-02 close (docs:1369-1379) makes `early_data` block scope legal as `connection` only — `fqdn`/`all` rejected exit 78 (`src/config.rs parse_per_fqdn_control` guard at `:1114`, `ConfigError::EarlyDataBlockScopeInvalid` `src/config.rs:534`); guard landed `206e021`, silently deleted `0ea2f48`, restored `7fb619d` (P1: alumina-a7nlq) — the enforcement consequence is that Domain/All are unreachable from valid config, so early data cannot select a per-domain or process-wide latch | `src/enforcement/action.rs Control` (35), `ControlTable` (168), `FirstSlot` (137); `src/enforcement/policy.rs decide` (113) | — | `mid full` (`rejects_early_data_block_fqdn_scope` + `rejects_early_data_block_all_scope`, `src/config.rs:1844-1883`) | implemented |
| Four per-class gate sections; operator-configurable bar | §Keyed configuration schema (docs:806-819, 754-768); SP-001 (docs:978-999, 1442-1472) | fixed-constants claim superseded by operator-configurable per-class gates (docs:991-999); defaults threshold 1 / window 900 | `src/config.rs parse_gate_section` (958); `src/enforcement/state.rs WindowedCounter` (127), `Enforcement::decide` (262) | `ALL_SCOPE_GATE_DEFAULT_THRESHOLD`/`_WINDOW_SECS` (`src/enforcement/state.rs:12,17`) | `mid full` (`single_any_illegal_*`, `src/enforcement/state.rs:1071-1138`) | implemented |
| `startup_unresolved_allowance` required; `0..=names-1` | §Configuration & DNS → Startup readiness (docs:108); §Keyed configuration schema (docs:96) | affects startup availability only, never destination authorization | `src/config.rs from_table` (`require_integer` 757; `AllowanceOutOfRange` 782-788); consumed by `src/serve.rs startup_decision` (970) | bound `allowance < names` (`AllowanceOutOfRange`) | `mid boot` (startup readiness); `mid full` | implemented |
| Resolver array 1..=5 mandatory; homogeneous-trust | §Resolver set (docs:502-527); SP-003 (docs:1028-1038, 1474-1478) | mixed DoT/plain arrays rejected at startup exit 78 — no cross-entry downgrade | `src/config.rs build_resolver_set` (810); `src/resolver.rs ResolverSet` (400) | `MAX_RESOLVERS` 5 (`src/resolver.rs:17`) | `mid boot` (`resolver_mixed_plain_and_dot_trust_rejected`, `src/config.rs:2711`) | implemented |
| `IP#fqdn` identity and strict SPKI pin grammar | V37 (docs:535-543); V5 pin grammar + verifier (docs:566-574) | per-entry dial port 53 (bare IP) / 853 (FQDN); pin composes as `#pin-sha256=` sub-suffix | `src/resolver.rs select` (327), `Fqdn` (44), `SpiPin` (126), `Nameserver` (207) | pin digest inline `[u8; 32]` | `mid boot`; `mid full` (dot_tests) | implemented |
| DoT client negotiates TLS 1.3 only | F-11 (docs:1224-1226) | `tls12` feature removed — client contains no TLS 1.2 code (docs:1226) | `src/startup_dns.rs build_tls_connection` (1101) with `with_protocol_versions([TLS13])` | — | `mid full` (`pinned_dot_rejects_tls12_only_peer`, `src/startup_dns/dot_tests.rs`) | implemented |
| No OS resolver file; single config read | §Resolver selection (docs:105); amendment (docs:512-514) | `read_resolver_config_file` removed; image holds binary + config only | `src/boot.rs run_boot`, `src/config.rs` | — | `mid boot` | implemented |
| Unpinned DoT fails closed against an empty root store | V5 verifier caveat (docs:570-574) | deliberately not operationally useful until a trust-anchor intake lands (docs:574) | `src/startup_dns.rs AluminaServerCertVerifier` (817) | empty `RootCertStore` | `mid full` (unpinned reject in dot_tests) | deployment-owned (trust-anchor intake: alumina-esyx7) |

### 11.4 DNS provenance, lifetime, scheduling, incidents

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| Wire provenance; response binding; section counts | §Wire parsing (docs:112); §DNS response outcomes (docs:127-140) | — | `src/dns.rs ResponseWorkspace` (778) | `MAX_TOTAL_RR` 128 (`src/dns.rs:20`) | `mid full` (dns lib) | implemented |
| CNAME provenance ≤8 links; no loops/conflicts | §DNS provenance (docs:114); §DNS response outcomes (docs:135-138) | — | `src/dns.rs` chain walk | `MAX_CNAME_LINKS` 8 (`src/dns.rs:15`) | `mid full` (dns lib) | implemented |
| CNAME bailiwick: self-default zone + declared suffix union | SP-014 (docs:1304-1337); §DNS provenance sentence amended (docs:1337) | supersedes Vec 11/Vec 32 pinning and RT-005 parent-zone note (docs:1332-1337); operator chooses granularity | `src/dns.rs BailiwickZones` (843), `from_allowlist` (878), `covers_for` (941), `soa_covers` (1303); `src/config.rs` `cname_bailiwick` | suffix total ≤ `ALLOWLIST_MAX` | `mid full` (`from_allowlist_fails_stop_on_suffix_slot_overflow`, `src/dns.rs:1827`) | implemented |
| Address eligibility (globally routable unicast), boundary vectors | §Configuration & DNS → Addresses (docs:116); L6 (docs:365-367) | negative/contradictory path fail-closed; NAT64/6to4/Teredo rejected | `src/eligibility.rs ipv4_is_eligible` (65), `ipv6_is_eligible` (78), `is_eligible` (13), `src/cache.rs` eligibility gate | fixed build-time exclude table | `mid full` gate-only binary `tests/eligibility.rs` | implemented |
| Cache lifetime: TTL cap, TTL 0 → 1, freshness/retirement, dedup | §Cache lifetime (docs:117); §Stale retirement (docs:118); L12 (docs:395-397); L13 (docs:399-401) | L12 caps honored TTL at 86400 (authorization lifetime ≤ 345600); L13 dedups identical bindings | `src/cache.rs publish_positive` (373), `servable` (151), `StagedPositive` | `TTL_CAP` (`src/cache.rs:18`), `STALE_GRACE` (`src/cache.rs:10`) | `mid full` (cache TTL/dedup tests) | implemented |
| Stale-serving window independent; zero-TTL stale-allowed bit | §Stale retirement (docs:118); RT-006 (docs:1170-1176); F-10 (docs:1220-1222) | RT-006 separates serving window from retention; F-10 gates stale on the bit and schedules zero-TTL refresh at 1 s | `src/cache.rs STALE_SERVING_WINDOW` (15), `stale_allowed` (167), `servable` (151); `src/schedule.rs normal_refresh_interval` (56) | `STALE_SERVING_WINDOW` 3600 | `mid full` (`zero_ttl_entry_never_served_stale`, `src/cache.rs:736`; `normal_refresh_interval_honors_bounds`, `src/schedule.rs:1059`) | implemented |
| Refresh band 5/900 and negative 30/900 | §Refresh scheduling (docs:119); §Negative refresh (docs:120); Vec 14 (docs:472-474); SP-007 (docs:1090-1096) | Vec 14 widens the normal band and splits the negative floor; SP-007 folds the rows into the profile | `src/schedule.rs REFRESH_MIN` (6), `REFRESH_MAX` (9), `NEGATIVE_REFRESH_MIN` (12), `normal_refresh_interval` (56), `negative_refresh_interval` (68) | 5/900, 30/900 | `mid full` (schedule bounds tests) | implemented |
| Failure retry backoff 1,2,4,8,16,30 capped | §Refresh failures and recovery (docs:121); §Initial resource profile (docs:222) | retry state distinct per family; only the affected type resets | `src/schedule.rs` backoff, `src/cache.rs note_exchange_failure` (468) | capped backoff table | `mid full` | implemented |
| DNS incidents, summaries, reporting bounds | §DNS incident notifications (docs:122); §DNS incident summaries (docs:123); §DNS reporting bounds (docs:124); SP-004 (docs:1040-1051) | SP-004 adds the sustained-negative incident class (N/M windows) | `src/schedule.rs INCIDENT_N` (23), `INCIDENT_M` (27), `INCIDENT_WINDOW` (30); `src/incident_report.rs NameReport` (99), slot markers | 32 names / 512 window markers | `mid full` (`sustained_negative_streak_opens_incident_at_n_across_m_windows`, `src/schedule.rs:1331`) | implemented |
| DNS exchange deadline 5 s | §DNS exchange deadline (docs:655-659); citation refresh (docs:727-734) | 2 → 5 s; startup budget proof `5×3×5=75≤90` (docs:659) | `src/startup_dns.rs EXCHANGE_DEADLINE_SECS` (48) | 5 s | `mid full` | implemented |
| Startup window 90 s; allowance; EX_TEMPFAIL 75 | §Startup deadline (docs:107); §Startup readiness (docs:108); L6 (docs:365-367) | positive classification requires an eligible, non-retired binding (L6) | `src/startup_dns.rs STARTUP_WINDOW_SECS` (49); `src/serve.rs startup_decision` (970) | `STARTUP_WINDOW_SECS` 90 | `mid boot` (startup readiness); `fixtures boot` | implemented |
| Failover/failback, degradation, probe sweep, corroboration | §Multi-resolver failover and failback (docs:520-527); Vec 19 (docs:468-470); post-window probe sweep (docs:627-650); F-03/F-04/F-05 (docs:1194-1214); failback hysteresis (docs:591-596); bounded corroboration (docs:1573-1600) | F-04 relocates on the 3rd counted failure (docs:1200); F-05 settles failback on 3 consecutive successes (docs:1212); F-03 probe-isolation invariant; `cc=` conflict fact | `src/startup_dns.rs start_exchange` (2971), `maybe_begin_failback` (3184), `on_exchange_failed` (3523), `on_exchange_succeeded` (3601), `DEGRADED_AFTER` (656), `FAILBACK_SUCCESSES` (661), `FAILBACK_AFTER_SECS` (667); `src/serve.rs step_sweep` (803), `step_corroboration` (832) | degradation/failback constants; single 1-conn/1-query transport | `mid full` (`five_resolver_startup_budget_fits_the_window`, `src/startup_dns/tests.rs`) | implemented |
| Obsolete-result isolation; generation captured at exchange start | §Capture cache generation at exchange start (docs:1554-1570); §Cache Publication (docs:188) | apply refuses `StaleGeneration` for an in-flight start | `src/startup_dns.rs start_exchange` (2971), `ActiveExchange` (215); `src/cache.rs Generation::checked_next` (59) | `Generation` token | `mid full` (`stale_generation_is_refused_at_apply`, `src/startup_dns/tests.rs:1146`) | implemented |

### 11.5 Reactor & lifecycle

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| One poll, one owner, classical readiness reactor | §Architecture → I/O model (docs:190); → Single Owner (docs:187) | — | `src/serving.rs preallocate` (1023), `run_once` (1261) under `src/runtime.rs Runtime::turn` | — | `mid full`; `e2e relay` | implemented |
| Two-barrier forwarding gate | §Protocol contract (docs:70-74); D2 (§4.2) | — | `src/gate.rs TunnelGate` (93); `src/client_hello.rs validate` (1108) | — | `mid full`; `e2e relay` | implemented |
| Per-visit budget 16-op/64 KiB; 256-visit timer recheck | §Architecture → Scheduling (docs:189); D6 (§4.2) | — | `src/serving.rs VISIT_OPS` (105), `VISIT_BYTES` (106), `TIMER_RECHECK_EVERY` (111) | 16 op / 64 KiB / 256 visits | `mid full` (serving lib) | implemented |
| Single earliest-deadline authority | §Initial resource profile (docs:217-230); IV-5 (docs:272) | — | `src/serving.rs DeadlineSlots` (863), `poll_timeout`, `expire_sweep` (3245) | — | `mid full`; `e2e shutdown` | implemented |
| Lifetimes: setup/connect/idle/drain/grace | §Lifecycle (docs:240-243); §Initial resource profile (docs:230) | no extension by client/dial activity | `src/worker.rs SETUP_DEADLINE_SECS` (51), `CONNECT_DEADLINE_SECS` (55); `src/serving.rs IDLE_SECS` (84), `DRAIN_SECS` (88), `SHUTDOWN_GRACE` (93) | 10 / 2 / 300 / 5 / 8 s | `mid full`; `e2e shutdown` | implemented |
| Shutdown: SIGTERM only, no extension, exit without deallocating | §Lifecycle → Shutdown (docs:243); §Architecture → Runtime surface (docs:192) | subsequent signals cannot extend the grace | `src/serving.rs on_sigterm` (1544); `src/runtime.rs` `process::exit` | — | `e2e shutdown`; `mid full` | implemented |
| Boot storage order and ownership transfer | §Architecture → Boot-Time Storage (docs:186); §Initial resource profile (docs:232) | — | `src/main.rs` boot, `src/inventory.rs` catalog, `src/serving.rs preallocate` (1023) | `TRAFFIC_STORAGE_BYTES` (`src/inventory.rs:13`), `SLOT_WORKSPACE_BYTES` (30), `SERVING_WORKSPACE_BYTES` (36) | `mid boot` (storage inventory); `fixtures boot` | implemented |
| Boot prerequisite checks: root UID, empty caps, no_new_privs | §Architecture → Runtime prerequisites (docs:193) | preflight gate runs before config load in `run_boot` | `src/preflight.rs preflight::check` (96-111); `src/boot.rs run_boot` | — | `mid boot` (preflight unit: `preflight_rejects_each_unmet_prerequisite_independently`); `fixtures boot` (root/caps/no_new_privs rejected exit 78) | implemented |
| One-listener runtime surface; single config read | §Architecture → Runtime surface (docs:192); §Architecture → Boot-Time Storage (docs:186) | listener bound once at attach; config read exactly once in `run_boot` — source-surface properties, not preflight facts | `src/main.rs` run_startup/attach (89-106); `src/boot.rs run_boot` (single `load_config_document` read) | — | — (source-surface property; no selector asserts single-listener uniqueness) | implemented (surface property) |

### 11.6 Logging

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| 2-KiB log queue geometry (256 × 2 KiB) | §2 KiB log slot and monitor family split (docs:1257-1302) | live geometry **replaces** the 10-KiB slot (docs:1232-1255); F-12 `dx=` bitset supersedes per-ordinal `d<j>x` renders (docs:1228-1230) | `src/log.rs QUEUE_SLOTS` (53), `SLOT_BYTES` (54) | `LOG_QUEUE_BYTES` (`src/inventory.rs:49`) | `mid full` (`logging_worst_case_record_per_kind_fits_the_slot_with_margin`, `src/log.rs`) | implemented |
| Allocation-free bounded encode; whole-record drop+count | §Lifecycle → Log delivery (docs:245); L18 (docs:411-413) | L18 counts sink-stranded records as dropped (never silently lost) | `src/log.rs LogStore::drain_sink` (2049), `drop_one` — L18 drop accounting; bounded encode path | — | `mid full` gate-only `monitor_stdout`/`stdout_stall`; `mid foundations` | implemented |
| Reserved records / priority classes; drop newest-lowest | SP-010 (docs:1119-1129; register 1506-1511) | latch/event, `startup_final`, `resolver_probe` reserved; bounded, not lossless | `src/log.rs is_reserved` (294), `enqueue_reserved` (2210), `Kind::ResolverProbe` (257) | — | `mid full` (`logging_reserved_startup_final_displaces_newest_normal_when_full` + `logging_reserved_records_survive_normal_overflow`, `src/log.rs:3727-3769`) | implemented |
| Monitor family split: committed summary + best-effort detail | §Monitoring (docs:338-340); §2 KiB split (docs:1271-1288); P-F09 (docs:1603-1638) | summary reserved at every cadence; per-batch/per-detail `capture_drops` unit mixing is intentional | `src/log.rs encode_monitor_summary` (858), `DOMAIN_BATCH` (61), `CAPTURE_BATCH` (63) | fixed core: 13 globals / 10 scalars / 19 `c<i>` / 4 `unk<i>` / `dx=` | `mid full` (`logging_monitor_all_saturated_record_fits_the_2k_slot`, `src/log.rs:3343`) | implemented |
| Startup records split: `startup_name` + `startup_final` | §Startup-final record shape (docs:842-891) | per-name records never embedded in the summary; `names_dropped` ⊆ `dropped` | `src/log.rs` record path | worst-case headroom table (docs:870-885) | `mid full` | implemented |
| stdout-only sink; partial-write preservation; bounded drain | §Lifecycle → Log delivery (docs:245) | a stalled sink never delays rejection/tunnel I/O/DNS/deadlines | `src/log.rs LogStore::drain_sink` (2049); `src/serve.rs` drain caller | — | `mid full` (`stdout_stall`); `e2e shutdown` (stalled sink) | implemented |
| expect()/unwrap() lint discipline | §Architecture → Failure Handling (docs:191) | live control is the clippy `-D warnings` exit 0 (per §8), not the warning count; `#[expect]` has item scope | `src/lib.rs:1`, `src/main.rs:1` deny roots | — | clippy -D warnings (`mid clippy`, `boundary phase1`) | implemented (per-site infallibility proof open: alumina-kcd4c) |

### 11.7 Tripwires, JA4, monitor records

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| Unified `decide()`; first-AnyIllegal latch (T6 Option A) | §Per-control enforcement schema T6 (docs:947-971) | single connection-level latch; per-control action on first occurrence | `src/enforcement/policy.rs decide` (113); `src/enforcement/action.rs FirstSlot` (137) | — | `mid full` (enforcement lib) | implemented |
| Block Connection/Domain/All; 512-slot closure; sticky until restart | §Block and Notify semantics (docs:304-309); SP-001 (docs:978-999) | All-scope arms only after the configured (threshold,window) bar; no runtime unblock | `src/enforcement/state.rs Enforcement` (216), `WindowedCounter` (127); 512-slot walk `src/serving.rs Serving::stop_block_all` (2265) | gate defaults 1/900 | `mid full` (`*_latch_all`/`never_latches_all`, `src/enforcement/state.rs:1071-1138`) | implemented |
| JA4 fingerprint (canonical 36-char) with ALPN hex-fallback | §JA4 format clause (docs:668-693) | hex-fallback implemented per spec (user-confirmed 2026-10-22, docs:693); observe-only — no cipher/ALPN policy (docs:695-697) | `src/client_hello.rs ja4_fingerprint` (919), `ja4()` (150), `count_token` (966) | — | `mid full` (`ja4_v*_published_vector_byte_for_byte`, `src/client_hello.rs:1874-2096`) | implemented |
| JA4 baseline per-ordinal 16-entry set; overflow fires deviation | SP-005 (docs:1053-1064); F-08 (docs:1216-1218) | per-ordinal set (no per-IP element) **supersedes** the per-(ordinal,IP) 41-B design row (docs:711) and the control-storage table's IP-bearing shape; baseline never updated | `src/serving.rs Ja4BaselineTable` (584) (512 × 36 B as-built); `src/enforcement/monitor.rs note_fact_ja4_change` (272) | 512 entries; `d<j>x` loss flag → `dx=` bitset | `mid full` (`ja4_set_overflow_fires_decision_on_each_new_distinct_beyond_capacity`, `src/serving/tests.rs`) | implemented |
| Change value keyed per-ordinal + triggering peer | C1 (docs:720-725); SP-013 (docs:1145-1155); F-12 (docs:1228-1230) | value per-ordinal (`d<j>v`), peer `d<j>p` lossless hex (docs:1234-1243) | `src/enforcement/monitor.rs ja4_value` / `ja4_peer_ip`; `src/log.rs` `d<j>j/v/p` render | `[[u8; 36]; ALLOWLIST_MAX]` table | `mid full` (`logging_monitor_summary_exact_grammar_and_zero_suppression`, `src/log.rs:3211`) | implemented |
| Monitor fact surface: `rd=`/`ss=`/`dp=`/`pr=`/`bv=`/`rpm=`/`xttl=`/`cc=`/`dx=` | Vec 19 (docs:468-470); serving-stale (docs:584-589); DoT→plain (docs:611-616); SP-009 (docs:1108-1117); Vec 21 (docs:489-491); bounded corroboration (docs:1590-1600) | probe relocations counted disjoint from `dp=` (SP-009); edge-triggered `rd=`; `cc=` corroboration-conflict anomaly | `src/enforcement/monitor.rs FactCounters` (12), `DnsAnomalyKind` (55), `serving_stale` (112); `src/log.rs encode_monitor_summary` (858) | — | `mid full` (`monitor_stdout` gate-only binary; `logging_monitor_summary_exact_grammar_and_zero_suppression`, `src/log.rs:3211`) | implemented |
| Exit-gate philosophy: no tolerated rate; operator chooses action AND bar | §Design philosophy (docs:9-47); §Keyed configuration schema gates (docs:806-819) | tripwires react on the first deviation at the configured bar | `src/enforcement/*`, `src/config.rs` schema | — | `mid full` | implemented (design direction owner: alumina-ea9q2) |
| Tarpit (reserved action) | §Tarpit (deferred) (docs:311-313) | deferred: no real establishment-allowed predicate; selecting it is rejected exit 78; no storage preallocated (docs:356) | — (no runtime variant; parse-rejected) | — | config parse (exit 78) | deferred (owner: alumina-5edss) |

### 11.8 Deployment boundary

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| Egress responsibility; VPC isolation out of proxy scope | §Deployment boundary (docs:142-144) | isolation is deployment-scoped, not a proxy property | operator / deployment | — | §Verification → Deployment confinement (docs:284) | deployment-owned |
| Minimal container image (binary + config only) | §Typical deployment pattern (docs:161); amendment (docs:512-514) | image holds binary + validated allowlist + resolver set, nothing else | deployment image build | — | image inspection in deployment verification; `fixtures boot` | deployment-owned |
| Separate-VPC appliance vs same-pod sidecar (positive locking under RCE) | §Deployment boundary (docs:144, 159); §Typical deployment pattern (docs:146-163); architecture §9 bullet | same-pod sidecar cannot prevent bypass (`connect(2)`, latch crash) | deployment topology | — | deployment verification (README reference pattern) | deployment-owned |
| Egress path must not apply NAT64 / DNS64 | §Typical deployment pattern (docs:159); §Addresses (docs:116) | proxy rejects NAT64/6to4/Teredo candidates at eligibility (row 11.4.4); the deployed path must also not apply NAT64 | deployment (path) | — | deployment verification | deployment-owned |
| Initial test target (Cloud Run worker-pool, Direct VPC) | §Initial test target (docs:175-179); §Initial resource profile (docs:234) | provider-specific validation target; 1-10 Gbps headroom quantified (docs:234) | operator / deployment; P2 E-series (alumina-cdwui.14-18) | — | §Verification → Initial deployment (docs:285) | deployment-owned (measurement: alumina-cdwui.14-18) |
| Deployment confinement verification (no alternate egress) | §Verification → Deployment confinement (docs:284) | repeat when networking/client/deps change; not a proxy-internal property | operator / deployment | — | deployment verification (§Verification → Deployment confinement, docs:284) | deployment-owned (release queue: alumina-cdwui.20) |

### 11.9 Performance & qualification

| Requirement | Current clause (§spec:line) | Supersession / current-state | Owner (module + symbol) | Fixed data owner | Focused gate · selector | Status |
|---|---|---|---|---|---|---|
| 128 MiB tunnel-traffic storage; 1-10 Gbps aggregate target | §Initial resource profile (docs:195-234); §Verification → Performance (docs:287) | targets and deployment behaviors "unverified until measured" (docs:287); 128 MiB is not a throughput guarantee | `src/inventory.rs TRAFFIC_STORAGE_BYTES` (13) | 128 MiB | `mid union`/`mid full` (storage inventory); performance measurement in P2 E-series | proof-open (alumina-cdwui.14-18) |
| L17 four named parser fuzz targets before qualification | L17 (docs:407-409) | scaffold-only harnesses do not satisfy; a real fuzz loop is the qualifying gate | `src/fuzz.rs` corpus; `tests/foundations.rs` F5 checked-in corpus | — | `mid foundations` (F5); full loop Linux-gated | proof-open (alumina-md58x) |
| Zero-allocation candidate proof (alloc-witness) | II-1 (docs:257); §Verification → Resource profile (docs:281) | per-candidate witness, exact inputs | `src/alloc.rs` witness | §7 catalog | `mid full` (alloc-witness lib + gate-only); `boundary phase1` | implemented (candidate-bound) |
| Real-I/O relay and SIGTERM shutdown gates on the exact candidate | §Verification → TLS forwarding gate (docs:277); → Lifecycle deadlines (docs:278) | boundary itself never runs E2E; selectors are host-runnable | `scripts/e2e_relay.sh`, `scripts/e2e_shutdown.sh` + harnesses | — | `e2e relay`; `e2e shutdown` | proof-open per candidate (release gate: alumina-cdwui.20) |
| Release qualification state | §Verification requirements (docs:274-287); [verification.md](verification.md) BOUNDARY | FINAL-PHASE1-COMPLETION is BLOCKED by design until prereqs; later-slice + release gates remain open | `scripts/verify.sh` boundary coordinator | — | `boundary phase1` | proof-open (P1 integration: alumina-cdwui.20)
