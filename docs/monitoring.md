# Notify delivery: stdout collector reliability and drop-alerting runbook

Deployment-owned companion to the `notify` action. The proxy owns detection,
denial, action, and **bounded, best-effort emission** into its single stdout
sink — nothing more ([docs/alumina-proxy.md](alumina-proxy.md) §Log
delivery, §Monitoring). It **never guarantees delivery**. Everything that turns
that byte stream into an operator signal — the collector, its liveness, and
alerting on loss — is a deployment responsibility, in part because the proxy
cannot observe its own unread pipe (writes succeed into a buffer nobody reads).

## Who guarantees what (tested proxy behaviour vs deployment-owned assurance)

**Proxy-owned, tested** — rely on, do not re-verify:

- Nonblocking stdout: fd 1 is made nonblocking once
  ([src/log/sink.rs](../src/log/sink.rs):16-27), writes are `write_vectored` against a
  16-op / 64 KiB per-turn budget ([src/log/mod.rs](../src/log/mod.rs):66-67), and a
  stalled or full pipe can never stall serving ([src/log/sink.rs](../src/log/sink.rs):100-179).
  A `WouldBlock` retains the partial cursor and retries
  ([src/log/sink.rs](../src/log/sink.rs):100-179); byte conservation is exact.
- Bounded queue: 256 × 2 KiB (`src/log/mod.rs:53-54`); on overflow a whole record is
  dropped and counted (`dropped`), never truncated.
- The monitor family is split into a reserved `kind=monitor` summary whose
  fixed core is admitted even when the queue is full, and best-effort
  `monitor_domain` / `monitor_capture` detail batches
  ([docs/alumina-proxy.md](alumina-proxy.md):341-343).
- A failed sink latches permanently and the drain quiesces (`src/log/sink.rs:87-99,100-179`):
  no further records of any kind are emitted until the proxy restarts.
  Backpressure is never a failure: a `WouldBlock`/`Interrupted` write retains
  the cursor and retries on the bounded retry cadence, so a stalled/full pipe
  is lossy only (whole-record drop, count on overflow) — never a hard failure
  or a stall of serving (`src/log/sink.rs:136-144`). An **unrecoverable**
  write error (e.g. stdout pipe closed) latches the sink failed, stranding
  every remaining queued record once in the shared `dropped` tally
  (`src/log/sink.rs:145-153`); outside shutdown the serving owner exits
  `EX_IOERR` (74) at the next owner-turn boundary rather than continue without
  an external log-loss signal (`src/runtime/owner.rs:309-310`; §F-09
  `docs/alumina-proxy.md:1235`). During shutdown the drain carries no exit; the
  shutdown verdict alone terminates the process.

**Deployment-owned** — you must build and assure; no proxy test covers this:

- A **persistent reader** on proxy stdout. Write-succeeds ≠ received (the pipe
  buffers; nobody reading it is not visible to the proxy).
- **Collector liveness** and alerting on its death or a filled pipe (out-of-band;
  the proxy emits no "nobody is reading" record anywhere).
- **Backpressure**: read fast enough that the pipe never stays full long enough
  to overflow the 256 × 2 KiB queue into counted drops.
- **Gap detection and loss alerting** per the counters below, plus the honest
  acceptance that a dropped record and a dropped counter can themselves be lost.

## Capacity guidance (derived from recorded workload receipts, not an invented rate)

Two inputs: the fixed emission geometry (source fact) and the recorded workload
receipts ([docs/benchmarks/e2micro-suite.md](benchmarks/e2micro-suite.md) §2,
§9; `.ooda/benchmarks/85b7769-*.json`, 85b7769 baseline).

**Receipt provenance / host disclosure.** The M-04 receipts are **host
measurements**, not e2-micro: they were recorded on an arm64 Apple VM (8 CPU /
14 GiB, rootful podman, loopback alias) modelling e2-micro by workload
parameters only, with no cgroup CPU/mem cap
([docs/benchmarks/e2micro-suite.md](benchmarks/e2micro-suite.md):97-107).
Read the CPU/RSS numbers below as host-measured indications for a collector
budget, never as e2-micro certifications. The receipts measure **relay
throughput**, not notify stdout volume (the proxy emits essentially nothing on a
clean golden path).

**What the receipts record** (corrected M-04, §9): 1gbps steady alumina achieved
999.969 Mbps at 32 sustained conns with CPU mean/peak 0.409/0.440 cores and RSS
mean 211,188 KiB (`85b7769-bench-alumina-1gbps-timed-20261028T131504Z.json`);
storm150 (150 new conns/s) established 9000/9000 sessions with CPU mean/peak
0.028/0.119 cores and RSS mean 210,915 KiB
(`85b7769-bench-alumina-storm150-timed-20261028T131839Z.json`); storm50
established 3000/3000 at 0.011/0.077 cores RSS 210,832 KiB
(`85b7769-bench-alumina-storm50-timed-20261028T132204Z.json`).

**Guidance.** Size the collector with (1) a **buffer ≥ one full proxy queue
(512 KiB) plus pipe capacity** so it absorbs a short burst — a guarantee only
for bursts whose volume fits pipe + queue; a sustained stall past that combined
capacity still overflows into counted drops, so the buffer is **not** a loss
guarantee — and (2) a read rate that stays ahead of your connection-churn class:
the receipts bound the classes at 150 new conns/s (storm150) and 50/s (storm50).
Every notify-tripping connection emits at most bounded per-connection
warn/info records (≤ 2 KiB each, e.g. `reject` / `early_activity`) as **their
own records**, plus the event-driven monitor family as a separate aggregate: a
reserved `kind=monitor` summary (≤ 2048 B fixed core) and best-effort
`monitor_domain` / `monitor_capture` detail batches (≤ 2048 B each, up to 3+3
per dirty second, `src/log/mod.rs:60-63`); the summary emits at most once per dirty
whole-second (`src/enforcement/monitor.rs:351-353`). Budget collector CPU/RAM in
the same order of magnitude as the proxy's recorded footprint above and never
assume the proxy slows down for a slow reader.

## Alerting on proxy-observable loss (exact counters, units, observation point)

Alert thresholds are your configuration; the semantics below are fixed
constants. The monitor-summary counters (`report_drops`, `capture_drops`) are
saturating and expose an `o*` overflow flag (`oreport_drops`, `ocapture_drops`);
treat a nonzero overflow flag as "count is a floor, not a total". Generic
`dropped` is a plain saturating count with **no** overflow field in the emitted
records (`startup_final`/`shutdown_final` carry `dropped` only) — see the
exit-accounting note below.

| Signal | Where | Unit (exact) | Means |
| --- | --- | --- | --- |
| `dropped` | `startup_final` ([src/log/mod.rs](../src/log/mod.rs):836-860) and `shutdown_final` (:935-944) **only** — never in the monitor summary core (:945-980) | 1 per whole record lost, all classes | Whole-record loss over boot/full run. Long-run loss surfaces **only** at these two boundaries while serving (not refreshed in-band); serving-exit residue after the single bounded drain is **uncounted, unobservable** (exit-accounting note below) |
| `report_drops` / `oreport_drops` | every `kind=monitor` summary fixed-core wire grammar ([src/log/encoding.rs](../src/log/encoding.rs):572-581) | 1 per dropped `monitor_domain` **batch** at report time ([src/log/mod.rs](../src/log/mod.rs):953-962; `src/enforcement/monitor.rs:320`) — a batch is up to 11 domain blocks, never per block | Queue-full refusal of a domain detail batch |
| `capture_drops` / `ocapture_drops` | every `kind=monitor` summary fixed-core wire grammar ([src/log/encoding.rs](../src/log/encoding.rs):572-581) | **mixed, by design**: 1 per detail at capture time (later-relation suppression [reactor.rs](../src/runtime/reactor.rs):2414-2430; 64-detail window eviction [monitor.rs](../src/enforcement/monitor.rs):335) **and** 1 per dropped `monitor_capture` batch at report time ([src/log/mod.rs](../src/log/mod.rs):945-980) — a batch is up to 22 details | Capture-detail loss in mixed units; a nonzero value means detail loss, never treat "1" as "one detail" |
| `dx=` | `kind=monitor`, square brackets loss bitset, present only when nonzero ([src/log/encoding.rs](../src/log/encoding.rs):666-675) | 1 bit per allowlist ordinal, hex | That ordinal's JA4-change facts overflowed the bounded detail |

**Notification drop path (exit accounting — counted vs unobservable).** Queue
residue a drain cannot deliver is accounted differently per path, never as
`report_drops`/`capture_drops`. **Counted residue:** a sink failure drops and
counts every remaining queued record exactly once in the shared `dropped` tally
([src/log/sink.rs](../src/log/sink.rs):145-153, per-record via [src/log/queue.rs](../src/log/queue.rs):176-181), and a startup-termination exit
(`Exit75`/`Terminated`) additionally strands whatever its bounded startup drains
did not deliver, each counted once in the same tally
([src/runtime/storage.rs](../src/runtime/storage.rs):1249-1258, `strand_queued`'s only call site).
**Unobservable residue:** the serving exit
([src/runtime/owner.rs](../src/runtime/owner.rs):30-40, :332-343) reads `dropped`, enqueues
`shutdown_final` with that snapshot, performs exactly **one** bounded drain
(16 ops / 64 KiB, [src/log/mod.rs](../src/log/mod.rs):66-67), then `process::exit` — records
still queued at that moment are destroyed **uncounted**, and a stalled sink can
make that single drain deliver nothing at all, so even `shutdown_final` itself
is lost. Therefore any `dropped` value in `shutdown_final` is a **lower bound**,
never proof of a lossless exit window.

## Alerting on collector-observable absence + the honest limitation

- The monitor summary is **event-driven**: it is emitted only when the aggregate
  is dirty, at most once per whole second
  (`src/enforcement/monitor.rs:351-353`). On a silent golden path there are
  **no** periodic summaries at all — so "no summary for N s" is not an alarm by
  itself. Alert instead on **silence where emission was expected**: a stream that
  had been delivering `kind=monitor` lines (or an open DNS incident per the
  incident-summary window) going quiet for > N s is an **investigation signal,
  not a proof of failure or exit**: causes are a latched hard sink failure
  (outside shutdown the proxy exits `EX_IOERR` (74); nothing more is emitted;
  `src/log/sink.rs:135-153`; `src/runtime/owner.rs:309-310`; §F-09), a dead
  collector, or **live backpressure** — a live but stalled/slow collector
  leaves the pipe full while events continue (`WouldBlock`/`Interrupted`
  retains the cursor, never latches the sink; no exit, serving continues;
  `src/log/sink.rs:136-144`). Correlate process status and collector read
  progress out-of-band; a latched sink is cleared only by operator restart.
- **A dropped record and a dropped counter can themselves be lost.** The summary
  line that would carry `report_drops`/`capture_drops` is itself a record the
  sink can strand; generic `dropped` refreshes only at startup/shutdown; and a
  collector that dies with a full pipe loses what was written-but-unread (those
  bytes are gone, succeeded, never read). Therefore: counters are a **lower
  bound** on true loss. The conservative operator response to any fired tripwire
  is to treat it as confirmed and investigate; the conservative response to a
  suspiciously *silent* stream with a healthy workload is never to conclude "no
  loss" from counter == 0 — verify the reader is actually consuming.
- **Conservative responses, by signal:** `report_drops`/`capture_drops`/`dx`
  growth ⇒ detail is gone (summary aggregates remain authoritative) — do not try
  to reconstruct detail, do not scale the proxy. A **nonzero** generic `dropped`
  at `shutdown_final`, or a **missing** `shutdown_final` entirely (a latched or
  stalled sink can consume the single exit drain), ⇒ the run's stdout corpus is
  incomplete — rebuild context from the collector's persisted stream and patch
  alerting; never read `dropped=0` as proof of a lossless exit window. Silence
  after a latched sink ⇒ rotate: repair or replace the collector, then exercise
  the operator-controlled restart to clear the latch, expecting in-memory state
  reset (§ below).

## Restart semantics (state that is in-memory and does not survive)

- **Proxy restart** clears all in-memory enforcement state: the per-ordinal
  domain block-latch bitset
  ([src/enforcement/state.rs](../src/enforcement/state.rs):220-222,233-235,359) and the
  all-scope block latch (:277-278), plus the JA4 first-seen baselines
  ([src/runtime/reactor.rs](../src/runtime/reactor.rs):579-598, :1098, "reset on restart"). A previously
  blocked or baselined identity is treated as first-seen again, and the monitor
  aggregate (including the drop counters in the summary) starts at zero. Treat a
  proxy restart as a clean-slate for block and baseline state; a restarted proxy
  does not resume prior latches.
- **Collector restart does not replay proxy history.** Proxy stdout is one-way
  and drained; there is no replay buffer. Records the collector missed are gone
  — either dropped and counted (queue overflow / strand) or written to a pipe
  it never read. After a collector restart, the persisted stream simply resumes
  at the proxy's current emission; do not expect past records, and do not
  back-fill from the proxy.

## Failure drill (stall the collector) — status: proxy-owned portion executed on the exact candidate; deployment-owned collector-restore portion BLOCKED/Unknown

Execution is D4's scope (bead `alumina-cdwui.13`) on the exact candidate. The **proxy-owned**
portion — pipe stdout to a non-reading consumer, generate notify-path activity, observe the
whole-record drop counter (a documented lower bound) and continued denial while stalled — was
executed by the repository's gate harness (historical `stdout_stall` / `monitor_stdout`,
`mid full` via the then-existing `boundary phase1`, witness-off/on); result and raw exits:
bead `alumina-cdwui.13`. The former wrapper has since been removed. The
**deployment-owned** collector-stall-and-restore portion was **not executed**: no external
collector process, alerting stack, or liveness-probe infrastructure exists for this repository
(missing prerequisite), so it is recorded **BLOCKED/Unknown**, never PASS and never an external
alert-delivery claim. The historical wrapper did not execute E2E; nothing here is production
qualification. Prerequisites for an executor of the full drill:

1. A running proxy with at least one `notify` action reachable on a fixed golden
   path; a collector process that reads proxy stdout and appends to a durable
   stream it can search; ability to stop and start the collector **without**
   restarting the proxy (separate process/identity); a way to generate one
   controlled notify-tripping event (e.g. the TLS 1.3-only JA4-change procedure
   in [docs/qa-package/README.md](qa-package/README.md) §JA4
   change-signal verification).
2. **Stall** the collector (SIGSTOP or stop the service — not the proxy).
3. **Generate** one controlled notify event, then a second, a few seconds apart.
4. **Restore** the collector; let it drain and persist what remains queued in
   the pipe.
5. **Inspect drop/liveness signals** in the persisted stream: whether a
   `kind=monitor` summary appears and whether `report_drops`/`capture_drops`/`dx`
   are nonzero; whether records emitted during the stall are missing; and, on an
   operator-controlled proxy SIGTERM/start (restart is operator-controlled, a
   preserved constraint), whether `startup_final`/`shutdown_final` `dropped`
   stayed 0.

**Expected observations.** Two branches. (a) **No-loss branch (the honest default
for a small drill):** with a short stall and a handful of notify events, the
records are pipe-buffered — the write succeeds into the pipe, nothing is lost,
and the resumed collector delivers them late; `report_drops`/`capture_drops`/`dx`
and `startup_final`/`shutdown_final` `dropped` all stay 0. The pipe buffer and
the 256-slot in-memory queue absorb the burst. (b) **Loss branch (requires a
sustained burst, not a few events):** `report_drops`/`capture_drops` move only
if the in-memory queue is full **at report time** (a dropped `monitor_domain`
/`monitor_capture` batch, `src/log/mod.rs:945-980`), and generic `dropped` moves
only when the queue overflows — both need enough un-drained records to exhaust
the 256 × 2 KiB queue, i.e. well over a hundred retained records with the
collector stopped. With the small burst a small drill generates, do not expect
counters to move; forcing branch (b) deliberately is its own larger drill. The
proxy never stalls serving in either branch (nonblocking sink).

**Pass / Unknown criteria.** PASS if: the proxy never stalled serving; some
subset of the events survived (pipe-buffered) and were drained after restore;
and, **within the serving window only**, every counter that moved is exactly
explicable by the recorded geometry — or, on the no-loss branch, all event
records for the stall window are present and all counters stayed 0. Do **not**
require exact reconciliation across a proxy exit: residue between the single
exit drain and `process::exit` is uncounted and unobservable (exit-accounting
note above). **Unknown** (record as Unknown, never PASS) if: the collector or
proxy OOM/thrashed (environment), a latched sink silently quiesced (no in-band
evidence by design), or the stall duration versus pipe capacity was not
measured. No direct-egress fallback is required anywhere in this drill — the
proxy's stdout pipe is the only path exercised.
