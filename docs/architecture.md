# Alumina — Architecture

**Status:** design statement for the as-built implementation (foundation, boot,
wired single-owner serving runtime; provisional parser layer). This document is
**not** runtime proof — qualification is gated on the
Linux acceptance gates in [verification.md](verification.md). **Canonical source:** `docs/alumina-proxy.md` is
the sole governing specification (no accepted ADRs). Where this document
defines a boundary the spec leaves open, it is a **named design decision
(D1…Dn)**, never a policy change or security relaxation.

## 1. Governing invariants (invariant-led design)

The fixed-profile invariants I-1…IV-5 name the design element each enforces.

## 2. Module & ownership decomposition

Single binary crate, one worker thread, no async runtime (`:140,147`); **all
post-boot state is preallocated** (§6).

| Module | Owns (mutating authority) | Citations |
|---|---|---|
| `config` | Parsed config, startup validation; EX_CONFIG 78 | `:54,56,58,60` |
| `resolver` | Validated TOML `resolver` array (1..=5 entries); per-entry dial port 53 (bare `IP`) / 853 (`IP#fqdn`, strict-pin); DNS TCP transport (1 conn/1 query, getrandom TIDs) | `:567-614,616-701` (amendment), `:68` |
| `dns_parse` | Wire parsing + staging classification (bounded CNAME, negatives, eligibility) | `:69,71,73,86-97` |
| `cache` | Per-name×type entries, generations, staging, refresh due table, retry/incident, reporting; **tunnels never hold cache refs** | `:74-82,145` |
| `tunnel` | 512 slots; per-slot state machine; two 128 KiB buffers; per-family counts | `:82,145,160,183` |
| `parse` (CONNECT/CH) | Incremental CONNECT (8 KiB) + ClientHello (≤64 KiB) parsers, residual state, original bytes | `:34,41,47-50,163-164` |
| `worker` / `Runtime` | The single owner loop: readiness demux, scheduling, timers, gate transitions — realized as the shared-readiness `Runtime` | `:138,144,146,147,149` |
| `log` | 256×8 KiB preallocated queue; allocation-free encode; nonblocking sink; drop+count | `:149,178-179,193-194` |
| `lifecycle` | SIGTERM, shutdown grace, drain; exit without deallocating | `:149,150,181,192` |
| `enforcement` | rp2e tripwire/action/monitoring surface (per-control schema: `[any_illegal]` with the four controls `connect_parse`, `host_not_allowlisted`, `tls_profile`, `ech` + keyed `[allowed_fqdn."<fqdn>:<port>"]` tables with per-FQDN `early_data`/`ja4` controls), per-control Action (`notify`|`block`), bounded stdout monitoring, control state | §Tripwire actions, monitoring, and pacing, §Keyed configuration schema, §Per-control enforcement schema |

> **As-built realization.** `src/main.rs` is the single boot owner: preallocate
> serving workspaces → startup DNS window (`run_startup`) → on a Serve decision
> attach the listener and enter `Runtime::serve` (`src/runtime.rs`); one poll
> observes DNS freshness and traffic readiness, and the cooperative turn starts
> due DNS exchanges itself (`main.rs:80-91`; `starts_due_dns_if_idle`
> `runtime.rs:246-280`). Provisional parsers live in
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
listener on that same poll without creating a second one
(`src/serving.rs:1135-1142,1220-1240`). `Runtime::serve` is the process-lifetime
loop over it and never returns `Ok` (`src/runtime.rs:366-379`).

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
application-owned queue of `:146`; deadlines checked against monotonic clock
before any completion transition (`:146,147`).

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
merely rejected (IV-1).

```
ACCEPT → READ_CONNECT → (400/403 before 200 begins) → CLOSE
                 ↓ AUTHORIZED (allowlisted, 443)
        CONNECTING_UPSTREAM (revalidate per attempt, ≤4×2 s clipped to 10 s; 502/504)
                 ↓ SENT_200 (successful CONNECT completed)
        VALIDATING_CLIENTHELLO (≤64 KiB)
                 ↓ GATE_OPENING (write-accounting transition)
        RELAY_ACTIVE → DRAINING (first orderly EOF) → CLOSE
        (after 200 begins: any error closes, no injected response, no TLS alert)
```

Named decisions:

- **D1 response-begin.** `ResponseBegin` ≠ `ResponseComplete`; before 200
  begins failures may send HTTP error, once begun they close with no injected
  response/alert; only a *completed* 200 permits ClientHello inspection.
- **D2 two barriers.** A: no client bytes before full validation (SNI
  normalized-equal to approved hostname). B: no upstream bytes before the gate
  opens (`:201`).
- **D3 gate-opening.** The gate opens **in the same worker transition whose
  successful local-write accounting reaches the end of the validated
  ClientHello (H), before any subsequent upstream read** (`:32`); a crossing
  write forwards trailing `X` from the open point; local-write success ≠ remote
  receipt; arrival ordering never inferred after open.
- **D4 early-activity.** While B is closed the worker may do upstream I/O;
  actual data/EOF/reset terminates setup (metadata-only warn); WouldBlock/
  readiness is not activity.
- **D5 accounting.** Forwarded bytes advance only on successful writes; partial
  writes preserve order (`:32,80,146-147,220`). **D5a** exactly two per-family
  counters (A/AAAA) per connecting tunnel, never addresses/refs (`:82`).
  **D5b** two 128 KiB buffers reused across CONNECT/ClientHello/relay without
  discarding coalesced bytes; relay buffers never enlarge setup limits.

Lifetimes (`:189-192`): setup deadline starts at accept, never reset; connect
deadlines clipped to it; idle starts at gate open, reset only on successful
writes; first EOF starts the never-reset 5 s drain; SIGTERM stops accepting +
8 s grace (never extended); resources released exactly once; exit without
deallocating.

## 5. Generations, lifetimes, and anti-alias (T7/T1-merged domains)

Four domains must **not** be merged (`:212`):

| Domain | Owner | Invalidation rule | Reuse proof status |
|---|---|---|---|
| G1 Tunnel-slot generation | `tunnel` | Connection-scoped state; reuse must never make stale work valid | **design artifact**; nonreuse proof open gate |
| G2 Cache-entry generation | `cache` | Advances on replacement/eviction; rejects obsolete | per-op tag; part of cache slice |
| G3 DNS non-connection lifetime | `cache` | Refresh results not connection generations; no cache refs | structural |
| G4 Reporting window id | `cache` | Ids not reusable while a live tunnel retains one; counters saturate | **design artifact**; proof open gate |

A wide integer is not a nonreuse proof; width/exhaustion are recorded artifacts
with construction-and-reuse proof as a future gate.

## 6. Fixed storage and the zero-allocation model

- **T1 boot boundary:** boot init = privilege + config + resolver reads +
  storage/facility init; startup DNS is post-boot and allocation/deallocation-
  free (`:64,150,206,230`).
- **T3 memory reading:** 128 MiB is **tunnel traffic storage only**; the ban on
  heap alloc/dealloc during serving/refresh does not imply constant total
  memory — process/kernel memory reported separately (`:143,183,206`).

| Allocation | Size | Citations |
|---|---|---|
| Tunnel traffic buffers | 512 × 2 × 128 KiB = 128 MiB | `:160-162,183` |
| Retained serving workspace (per-slot CONNECT head + 2×64 KiB ClientHello inspector + JA4 retention) | 512 × ~152.5 KiB ≈ 76 MiB (design estimate) | `:162,186,929` |
| Config document buffer | 16385 B (16 KiB bound + 1 oversize-probe byte) | `:54,158` |
| CONNECT / TLS pre-auth | ≤8 KiB / ≤64 KiB | `:163-164` |
| DNS message/records staging | 16 KiB / 128 RRs | `:165` |
| Cache entries | ≤32 names × 2 types, 16 A + 16 AAAA per name | `:74,166` |
| Reporting storage | 32/64/512 markers | `:177` |
| Log queue | 256 × 8 KiB | `:178` |
| Ready/timer tables | Fixed slot counts (dup-free) | `:146` |
| Stacks | Bounded worst-case (no recursion); numeric a **design artifact** | `:143,165,183` |
| mio Poll/Events | Preallocated at boot; op matrix pinned | `:147,206,230` |

**Outside the 128 MiB budget** (separately accounted): the retained serving
workspace (512 × ~152.5 KiB ≈ 76 MiB, design estimate — JA4 ClientHello
retention reconciled at spec §JA4 client-fingerprint tripwire), DNS storage, metadata, stacks, executable,
kernel socket buffers (T3).
**Dependency seam (T2/G4):** `mio`+epoll mandated (`:147`); pin version,
enumerate operations, gate each on source review + allocator instrumentation
(verification.md F3) — mio steady-state alloc-freedom is not assumed.

## 7. Startup, logging, shutdown

**Startup** (`:64-67`): privilege → config+resolver → storage → 90 s startup
DNS window (exchanges clipped) → listener open; open early only when all names
usable; at deadline serve if unresolved ≤ allowance else EX_TEMPFAIL 75; no
readiness endpoint; one first-failure warn, suppressed per-type first warnings,
one `startup_name` record per unresolved name plus one final summary. **Logging**
(`:178-179,193-194`): allocation-free records ≤8
KiB escaped, whole-record drop+count (never truncate), nonblocking drain under
per-turn budget with partial-write preservation; a stalled sink must not delay
rejection/tunnel I/O/DNS/deadlines; one warn per rejection and per
early-activity close; stdout only. **Shutdown** (`:150,192`): SIGTERM only →
stop accepting, 8 s grace, drain, exit without deallocating; `panic="abort"`;
`unwrap()/expect()` excluded from production paths.

## 8. Deployment and trust boundary

Alumina is responsible for the egress it provides (`:99-101`); VPC isolation is
deployment-scoped. Runtime prerequisites (`:118,150`): minimal `FROM scratch`
container holding only `/alumina` (statically linked musl binary) and
`/config.toml` (validated allowlist + resolver set); non-root (`65534:65534`),
empty caps
(`--cap-drop ALL`), `no_new_privs` (`--security-opt no-new-privileges`),
read-only rootfs (`--read-only`), no writable/secret volumes, and a dedicated
appliance identity holding no application secrets or credentials. Confinement
default-denies workload egress except to Alumina's private VPC endpoint
(`tcp:5353`) + explicitly required non-HTTPS platform dependencies across all
routes/families (`:116`), including removing default Private Google Access
(`199.36.153.8/30:443`) bypasses when unused; exactly one listening socket;
config read once; a validated `resolver` array with per-entry dial port 53
(bare `IP`) / 853 (DoT `IP#fqdn` / strict-pin forms) supplied
(`:567-614,616-701`); no NAT64/DNS64 in the egress path (`:101,116`).

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
fallback (`:19,49,63,71,72,97,144,149`).

Cross-map: [verification.md](verification.md) and
[qa-package/README.md](qa-package/README.md) for gate execution and the open
qualification gates.
