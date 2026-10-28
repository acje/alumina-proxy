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
deadlines clipped to it; idle starts at gate open, reset only on successful
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

- Reads go direct-into-slab bounded by the live visit budget; in relay each
  read is paired with the draining flush in the same visit, leaving ≥ half the
  remaining budget for the flush (`read_room`, `src/serving.rs:1970-1990`).
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
| JA4 baseline table | `serving` | `[ [Ja4BaselineEntry;16]; 32 ]` = 512 × 36 B = 18,432 B | per-(ordinal,addr) JA4 strings | first-seen set baseline, never updated after seeding; warm | as-built | `src/serving.rs:584-619`; spec §JA4 client-fingerprint tripwire (docs/alumina-proxy.md:353) |
| Enforcement control table | `enforcement`/`config` | `[Control;4]` + two `[PerFqdnControl;32]` + `count` | any_illegal + early_data/ja4 per FQDN | uniform decide(); warm per violation | as-built | `src/enforcement/action.rs:161-232` |
| Enforcement latch/gate state | `enforcement` | `Enforcement { control, block_all, blocked, monitor, bad_handshake_gate, illegal_fqdn_gate, early_data_gate, ja4_gate }` plus one `FirstSlot` latch per serving slot | all-scope `block_all` latch; per-domain `blocked` bitset; four per-class `WindowedCounter` gates built from the `GateSet` threshold + window | an `AnyIllegal` cause or all-scope early_data/ja4 folds into its class gate; while the (threshold, window) cap is uncrossed the all-scope `Block` is demoted to `BaselineOnly`, and the first crossing lifts it and latches `block_all`; the per-connection `FirstSlot` latch (Armed→Spent once, re-armed on slot reset) applies the first-`AnyIllegal` action at most once per connection | as-built | `src/enforcement/state.rs:216-225,262-334`; `src/enforcement/action.rs:137-153,161-232`; `src/serving.rs:640,780` |
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
