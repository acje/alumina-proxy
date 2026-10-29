# Alumina — Independent As-Built Architecture Review

| Field | Value |
|---|---|
| Repository | `/Users/anders.jensen/code/alumina-proxy` (crate `alumina`) |
| Target revision | `3f587e947fa8f050954b2f1fa7ec6b47012ac769` (`main`) |
| Review date | 2026-10-29 |
| Method | Static read-only inspection of the tracked Rust sources at the target SHA. No builds, no test runs, no doc files used as evidence. |
| Evidence rule | Every architectural claim cites source `path:line` or a named symbol at the target SHA. `docs/` (including `docs/alumina-proxy.md`) is deliberately **not** used as evidence. `AGENTS.md` is used only as the review *criteria* it declares itself to be (fixed-profile constraints), never as a description of the code. |
| Code volume | 57,152 lines of Rust tracked at HEAD (`src/` + `tests/`); 950 `#[test]` occurrences. |
| Output scope | This directory only. No source, test, Cargo, script, or doc file was modified. |

Severity scale: **S1** = correctness/security risk reachable in the shipped configuration;
**S2** = contract or capacity mismatch that will mislead an operator or the next maintainer;
**S3** = maintainability/hygiene with bounded blast radius; **S4** = informational/positive.

---

## 1. Executive summary

Alumina is a single-process, single-threaded, `mio`-driven HTTPS `CONNECT` egress proxy whose
architecture is unusually explicit: ownership is a linear chain of consuming constructors, the
per-connection lifecycle is a closed enum state machine, and the two forwarding barriers are a
pure state machine separated from all I/O. The dominant architectural asset is that most
"cannot happen" statements are *types* rather than assertions (`Preallocated` cannot serve,
`SlotIndex`/`TunnelIndex` are consumed, `ValidatedHello` requires a `HelloAccepted` witness,
`DomainOrdinal` is a range-bounded index validated against the current table).

The dominant architectural cost is **memory**: the retained boot footprint is ≈ **205 MiB**, not
the 128 MiB traffic store that the inventory headline reports, because every one of the 512 slots
also retains a `ConnectParser` plus a `ChInspector` holding two 64 KiB buffers and a full inline
`ClientHello` (`156,856` bytes/slot, pinned by test). Per concurrent tunnel the retained cost is
≈ **409 KiB**.

Five findings deserve management attention:

1. **S2 — `[early_data]` gate is inert.** The All-scope gate for early-data can never arm under any
   configuration the parser accepts, yet it is parsed, validated, stored and wired. An operator
   tuning `[early_data] threshold/window` is tuning a no-op.
2. **S2 — "no post-boot heap alloc/dealloc" holds for the plain-DNS profile only.** The `DoT`
   connect path allocates by construction (`Arc`, `ClientConfig`, `String`, `ClientConnection`,
   `Box`), and the in-code witness comments say so explicitly.
3. **S2 — boot retained memory is ~1.6× the headline traffic store**, and the inventory is an
   explicit *lower bound* that excludes per-slot gate/capture/cursor state.
4. **S3 — two direct dependencies (`rustls-pki-types`, `rustls-webpki`) are declared but never
   referenced** by any Rust source.
5. **S3 — the serving/refresh exchange class is a positional 2-call protocol** (`start_exchange`
   then `mark_serving_started`) that a future caller can silently get wrong, and the runtime
   cancels any exchange that does not carry the flag.

---

## 2. System shape

```
main.rs
  └─ boot::run_boot ─────────────► preflight (/proc/self/status) → config (TOML) → TrafficStorage
       └─ ServeStorage::boot ────► Cache · Schedules · StartupDns · Worker · Enforcement · LogStore · IncidentReport
            └─ Preallocated::preallocate ─► Serving { 512 SlotWorkspace, Poll, SIGTERM self-pipe, events }
                 └─ run_startup ─► cooperative DNS window over the *serving* poll (+ SIGTERM)
                      ├─ StartupDecision::Exit75 ─► exit 75
                      ├─ StartupDecision::Terminated ─► exit 0
                      └─ Serve(_) ─► Preallocated::attach(listener) ─► Runtime::serve
                           └─ loop { Runtime::turn: one poll wait; dispatch batch; bounded DNS turn; drain logs }
                                └─ shutdown_exit ─► process::exit(0 | 70)
```

Everything is one OS thread. There are no worker threads, no async runtime, and no background
tasks: the only `std::thread` use outside tests is a sleep in a `#[cfg(test)]`-gated startup driver
(`src/startup_dns.rs:2683`, `:2929`). The `mio` `Poll` in `Serving` is the single readiness
authority for the listener, all tunnels, the DNS transport, the SIGTERM self-pipe and the log-sink
deadline (`src/serving.rs:67`, `:137`, `:144`, `:150`, `:917`).

| Subsystem | Primary type(s) | File | Lines (incl. tests) |
|---|---|---|---|
| Boot / preflight / inventory | `run_boot`, `KernelFacts`, `BootInventory` | `src/boot.rs`, `src/preflight.rs`, `src/inventory.rs` | 307 / 209 / 295 |
| Configuration | `Config`, `ControlTable`, `AllScopeGate`, `ResolverSet` | `src/config.rs`, `src/resolver.rs` | 3,001 / 801 |
| Serving storage + startup decision | `ServeStorage`, `StartupDecision` | `src/serve.rs` | 2,672 |
| Shared-readiness owner | `Preallocated`, `Runtime` | `src/runtime.rs` | 440 |
| Event loop / relay | `Serving`, `SlotWorkspace`, `Stage` | `src/serving.rs` (+ `policy`, `reject`, `startup`) | 3,374 |
| Two-barrier gate | `TunnelGate`, `ValidatedHello` | `src/gate.rs` | 524 |
| CONNECT parsing | `ConnectParser`, `ConnectRequest` | `src/connect.rs` | 1,115 |
| ClientHello inspection / JA4 | `ChInspector`, `ClientHello`, `validate` | `src/client_hello.rs` | 2,368 |
| Decision core | `Worker`, `SlotState`, `Deadline` | `src/worker.rs` | 1,911 |
| DNS cache / schedules | `Cache`, `Schedules`, `Entry` | `src/cache.rs`, `src/schedule.rs` | 1,420 / 1,457 |
| DNS wire + DoT transport | `parse_response`, `StartupDns` | `src/dns.rs`, `src/startup_dns.rs` | 3,703 / 3,835 |
| Enforcement | `Enforcement`, `decide`, `Monitor` | `src/enforcement/*` | ~2,100 |
| Observability | `LogStore`, `IncidentReport` | `src/log.rs`, `src/incident_report.rs` | 4,413 / 781 |
| Witness / harness | `Counting`, `fuzz`, `fault` | `src/alloc.rs`, `src/fuzz.rs`, `src/fault.rs` | 225 / 581 / 156 |

Twenty-one of twenty-seven modules are `pub` (`src/lib.rs:4-27`); `enforcement` and
`incident_report` are private. The library surface exists because the integration tests under
`tests/` consume it; the binary is the only production consumer.

---

## 3. Lifecycle and ownership (the strongest part of the design)

The boot chain is *consuming by construction*:

| Stage | Constructor | Consumes | Guarantee |
|---|---|---|---|
| Kernel facts | `preflight::read_kernel_facts` (`src/preflight.rs:123`) | — | non-root, empty Eff/Prm/Amb caps, `no_new_privs` (`:96-113`) |
| Config | `config::load_config_document` (`src/config.rs:706`) | file | ≤16 KiB, UTF-8, strict schema, unknown key = error (`:762-783`) |
| Traffic store | `inventory::TrafficStorage::allocate` (`src/inventory.rs:97`) | — | 512 × 2 × 128 KiB, fallible → typed `StorageUnavailable` |
| Serving storage | `ServeStorage::boot` (`src/serve.rs:168`) | `&Config` (cloned) | cache/schedules sized from the *same* allowlist (`src/cache.rs:306-308`) |
| Workspaces | `Serving::preallocate` (`src/serving.rs:1023`) | `ServeStorage` + `TrafficStorage` | buffers moved in by value, no second traffic blob |
| Pre-attach owner | `Preallocated` (`src/runtime.rs:40`) | — | **no `serve()`/`turn()` exists**; `attach` consumes `self` (`:153`), so double-attach is unrepresentable (with a `compile_fail` doctest at `:34-39`) |
| Serving owner | `Runtime::serve` (`src/runtime.rs:366`) | `Runtime` | returns `Infallible` only via `process::exit` |

Shutdown deliberately bypasses destructors: `Runtime::serve` emits the typed record, drains the
bounded log queue, then `std::process::exit(exit.code())` (`src/runtime.rs:374-377`), with
`Drained → 0`, `Forced → 70` (`src/serving.rs:183-199`). This is coherent with the "no post-boot
dealloc" profile: the retained heap is reclaimed by the kernel, never by `Drop`.

The one soft spot in this chain is the **clock mount**. `ServeStorage` holds `origin`/`now0` and
re-anchors both itself and the worker via `mount_clock` (`src/serve.rs:223-227`), called from
`settle_startup` (`:1060`). Nothing in the type system prevents a second mount or a mount with a
foreign origin; correctness rests on `settle_startup` being the only caller. There is a single
call site today (`src/serve.rs:1060`), so this is a documented seam rather than a defect.

---

## 4. Request data path

One `CONNECT` traverses nine explicit stages (`Stage`, `src/serving.rs:340-351`):

| # | Stage | Entry point | What is decided / enforced | Citation |
|---|---|---|---|---|
| 1 | Accept | `accept_all → admit` | 512-slot / 128-pending capacity → `503`; slot generation bumped | `src/serving.rs:1777`, `:1808` |
| 2 | `ReadingConnect` | `client_readable → buffer_and_parse` | incremental 8 KiB head parser, CRLF scan cursor, no O(N²) rescan | `src/connect.rs:228-270` |
| 3 | `RunningDecision` | `run_decision` | exact `<fqdn>:<port>` allowlist match; blocked-domain refusal; peer selection | `src/serving.rs:2360-2426`, `src/worker.rs:815-845` |
| 4 | `Dialing` | `dial` | eligible numeric destination only; 2 s per-attempt deadline clipped to the 10 s setup deadline; ≤4 attempts | `src/serving.rs:2495-2529`, `src/worker.rs:210-253`, `:833` |
| 5 | `SendingConnected` | `upstream_writable` | fixed `200 Connection established` body | `src/serving.rs:201`, `:2531-2557` |
| 6 | `ValidatingHello` | `buffer_and_validate → hello_complete` | TLS 1.3-only profile, exactly one SNI equal to the approved host, ECH rejected | `src/client_hello.rs:1108-1121`, `:708-723`, `:771-813` |
| 7 | `WritingHello` | `flush_client_upstream` | barrier A releases exactly the validated hello; the crossing write opens the gate atomically | `src/gate.rs:217-244` |
| 8 | `Relay` | `client_readable`/`upstream_writable`/`relay_upstream_to_client` | byte-conserving double buffering, half-close after drain, idle/drain deadlines | `src/serving.rs:2872-2926`, `:2976-3026`, `:3077-3150` |
| 9 | `Closing` | `close_slot` | exactly-once release, capture consumed into the monitor | `src/serving/reject.rs:79-99` |

Three properties are worth calling out as genuinely well done:

* **Barrier correctness is offset-based, not message-based.** `TunnelGate` tracks a monotonic
  `upstream_committed` and opens only when a *successful write* crosses `hello_end`
  (`src/gate.rs:217-244`); coalesced trailing bytes beyond H are reported as
  `relay_from_open` and are never re-forwarded. A late `on_connect_head` cannot shift the hello
  window (`:162-167`), which is the classic bug in this design.
* **Evidence insufficiency has its own verdict.** A pre-validation upstream byte maps to
  `Violation::EvidenceInsufficient → Effect::Unknown{NotYetValidated}` (`src/serving.rs:2634-2649`,
  `src/enforcement/policy.rs:136-138`), not to `BaselineOnly`. Operational errors are not folded
  into a clean negative.
* **Attribution is keyed on the approved pair**, not the hostname: `ordinal_for_pair`
  (`src/serve.rs:306-313`) and `Config::allowlist_position` (`src/config.rs:446-450`) are the single
  predicate shared by the worker decision and the serving attribution, so same-host/different-port
  cannot cross-close another entry's domain block.

---

## 5. Memory architecture — the real constraint

`inventory` is explicitly a **lower bound over named buffers** and says so
(`src/inventory.rs:176-196`). Summing the pinned constants at the target SHA:

| Component | Formula | Bytes | MiB |
|---|---|---|---|
| Traffic store | 512 × 2 × 128 KiB (`src/inventory.rs:10-13`) | 134,217,728 | 128.0 |
| Serving workspaces | 512 × (size_of::<ConnectParser>() + size_of::<ChInspector>()) (`:30-36`) | 80,310,272 | 76.6 |
| DNS named buffers | 512 + 16,386 + `size_of::<ResponseWorkspace>()` (`:43-44`) | ≈17 KB | 0.02 |
| Log queue | 256 × 2 KiB (`:49`, pinned equal in `src/log.rs:154`) | 524,288 | 0.5 |
| **Retained floor** | | **≈214.5 MB** | **≈204.6** |

Two structural observations follow from the code, not from any document:

1. **Per-slot cost is ≈ 409 KiB** (156,856 workspace + 262,144 buffers), so capacity is
   *pre-purchased*: 512 slots cost the same at zero load as at saturation. That is the price of
   "no post-boot allocation", and it is the single biggest architectural trade in the system.
2. **The workspace is dominated by two 64 KiB inspector buffers** plus an inline `ClientHello`
   whose largest field is `ciphers: [u16; 8192]` = 16 KiB
   (`src/client_hello.rs:6-18`, `:61-77`, `:411-419`). `MAX_CLIENT_HELLO` is 64 KiB while
   `MAX_HANDSHAKE_LEN` is 16 KiB, i.e. the retained per-slot scratch is 4× the security-relevant
   message bound (`:18` vs `:6`). That single ratio accounts for 64 MiB of the 76.6 MiB workspace
   total. The headroom is only reachable by multiple pre-hello records, so it is defensible — but
   it is headroom, not a requirement, and it is the obvious first lever if the footprint must fall.

The inventory's lower-bound framing is honest, but it means a capacity planner reading
`named_fixed_buffer_bytes()` (which reports traffic + workspace + DNS = 214,528,000) still misses
the per-slot gate/capture/cursor fields, the 512-entry JA4 baseline table (32 × 16 × 36 = 18 KiB,
`src/serving.rs:584-597`), the incident report (32 name reports + 512 slot markers,
`src/incident_report.rs:242-245`), and the per-turn stack frames described next. The order of
magnitude is right; the "128 MiB" headline is not the number to size a host with.

**Stack is a designed budget too.** `run_once` materialises a 1024-entry `(Token, Readiness)` array
(`src/serving.rs:1288`) and `dispatch_coalesced_batch` materialises a 512-entry
`CoalescedBatch` (`:1345`, type at `:478-489`). `tests/main_thread_stack.rs` exists precisely to
prove the inline serving path does not overflow the deployment `RLIMIT_STACK`; that test's
existence is itself architectural evidence that stack, not heap, is the per-turn resource under
management.

---

## 6. Event loop, fairness and scheduling

| Mechanism | Implementation | Why it matters |
|---|---|---|
| Single poll | `Serving.poll` (`src/serving.rs:918`); DNS and SIGTERM are external `SourceFd`/pipe registrations on the *same* registry (`:1224-1244`, `:1121-1131`) | One wait observes traffic, DNS freshness, signal and log deadlines; no cross-thread handoff |
| Token space | low 11 bits = local id; high bits = slot generation (`:152-162`, `:3307-3343`) | A stale event for a reused slot index is dropped before touching a socket |
| Batch coalescing | two-pass `CoalescedBatch`, arrival-ordered chain, O(seen) (`:1341-1432`, `:490-556`) | One visit per connection per batch; interleaved client/upstream tokens cannot false-reschedule |
| Visit budget | 16 ops / 64 KiB per visit (`:105-106`), `Readiness` merge (`:392-413`) | Prevents one hot tunnel from starving the loop |
| Timer recheck | `BatchProgress` pre-dispatch bound of 256 units (`:108-111`, `:296-319`, `:1997`) | A deadline cannot be delayed past a bounded amount of work |
| Deadline fold | `DeadlineSlots` bitmap + `poll_timeout` (`:850-915`, `:3163-3227`) | O(live deadlines), not O(512), per poll; four deadline sources folded into one wait |
| DNS bound | `DNS_ADVANCE_BOUND = 8` advances/turn (`src/runtime.rs:24`, `:417-436`) | A chatty/stalled resolver cannot starve traffic |
| Cooperative I/O | every DNS step is one nonblocking attempt (`src/startup_dns.rs:3023-3085`) | The owner always owns the wait; no blocking inside a turn |

The turn policy in `Runtime::turn` is a fixed, legible order: sweep → corroboration → start due
refresh → cooperative DNS turn if (event | sendable | deadline) → re-sync shared interest → monitor
→ incident → log drain (`src/runtime.rs:252-282`). Ordering is load-bearing and documented in
place; the corroboration/sweep/refresh mutual exclusion is enforced by explicit guards
(`:323-347`, `src/startup_dns.rs:3185-3191`, `:3238-3241`, `:3381-3383`).

Energy-wise (Priority 4): the loop blocks in `poll` whenever there is no runnable work, and the
log sink deliberately returns `Some(now)` only while the queue is non-empty (`src/log.rs:1637-1646`),
so a drained system sleeps rather than polls. The one deliberate zero-timeout case is a due
refresh while a sweep or shutdown holds the transport (`src/serving.rs:3210-3216`), which is floored
to 100 ms to avoid a spin.

---

## 7. Enforcement architecture

The enforcement subsystem is split on a clean axis:

* **Pure projection** — `policy::decide(&ControlTable, &mut FirstSlot, Violation) -> Effect`
  (`src/enforcement/policy.rs:113-146`). No state beyond the one-shot per-connection latch.
* **Stateful application** — `Enforcement::decide`
  (`src/enforcement/state.rs:262-334`): folds the pure effect into per-class `WindowedCounter`s,
  the all-scope latch, the per-ordinal blocked bitset, and the monitor counters.
* **Detection sites** — CONNECT parse / allowlist / hello rejection via `serving/reject.rs:68-77`,
  early upstream data via `serving.rs:2634-2649`, JA4 change via `:2784-2796`.

The violation lattice (`policy.rs:89-97`) has six cases and two of them exist solely to keep
"unknown" out of "harmless": `EvidenceInsufficient`, `Unattributed`, `MissingParseResult` all map
to `Effect::Unknown{reason}` (`:136-145`) and none consumes the first-slot latch. For a design whose
stated invariant is "no silent acceptance", that distinction is the mechanism that makes the
invariant honest: an internally inconsistent observation is *reported as unknown*, not silently
treated as a pass.

Two enforcement findings:

**F-01 (S2, inert knob).** The `early_data` All-scope gate can never arm. `Enforcement::decide`
notes the gate only when the *raw* effect is `Effect::Block{scope: All}`
(`src/enforcement/state.rs:271-277`). For `EarlyUpstreamData` the raw effect comes from the
per-FQDN control, and `config.rs` rejects any `early_data` `block` with a scope other than
`connection` (`src/config.rs:1110-1115`). Therefore the only reachable raw effects are
`BaselineOnly`, `Unknown`, `Notify`, or `Block{Connection}`; the `early_data` counter is never
noted and `crossed` is never true. The section is still parsed (`src/config.rs:800-805`), validated
(`:965-999`), stored in `GateSet` (`src/enforcement/state.rs:71-119`) and consumed
(`:242-246`). The unit test that appears to prove otherwise builds a `ControlTable` directly with
`early_data = Block{All}` (`src/enforcement/state.rs:1415-1450`) — a table state the production
parser cannot produce — so the test masks the unreachability. Consequence: `[early_data]
threshold/window_secs` is a documented operator control with no runtime effect; the per-connection
control still fires, so this is a *semantics* defect, not an open bypass.

**F-02 (S4, sound).** The `ja4` gate *is* reachable (`Block{All}` is legal for `ja4`), and the
per-class isolation between `bad_handshake` and `illegal_fqdn` is genuinely enforced by which
counter each cause notes (`src/enforcement/state.rs:264-286`).

---

## 8. DNS / DoT subsystem

`StartupDns` is a hand-rolled nonblocking state machine over one reusable TCP connection with one
outstanding query (`src/startup_dns.rs:1147-1282`). It carries four independent control planes:

| Plane | Trigger | State | Citation |
|---|---|---|---|
| Refresh schedule | due time per name×family | `Schedules` (`src/schedule.rs:201-208`) | `:679-708` |
| Failover | counted exchange failure | `degradations`, `active_resolver` | `:3523-3577` |
| Failback | grace after relocation | `failback_due`, `failback_source`, 3 consecutive successes | `:3178-3210`, `:3631-3638` |
| Sensor probes | post-window sweep, sustained-negative corroboration | `probe_sweep`, `corroboration` (pure sensor, never applies cache) | `:3238-3258`, `:3320-3347`, `:3377-3413` |

Design decisions that hold up:

* **Only fully validated outcomes reach the cache.**
  `dns::apply_outcome` prepares the schedule delta *before* mutating the cache
  (`src/dns.rs:366-428`; prepared deltas at `src/schedule.rs:358-391`, `:502-537`), so a
  `DeadlineOverflow` leaves both resources untouched.
* **Transaction id is CSPRNG-drawn per exchange** (`src/startup_dns.rs:1363-1366`) and the
  response is matched on tid + question fields (qname + qtype + qclass) (`src/dns.rs:983-1027`);
  QR/opcode/TC are validated from the response flags and RCODE is classified or rejected
  (NOERROR/NXDOMAIN handled, every other RCODE refused, `:1199-1230`) — RCODE is validated, not
  matched against the query — with `DNAME` rejected everywhere and trailing bytes rejected
  (`:1181-1183`).
* **Bailiwick is per-entry**, so one allowlist entry's declared CNAME suffixes cannot widen a
  neighbour's trust (`src/dns.rs:863-953`), and same-bare-name entries across ports must declare
  byte-identical suffix lists or boot fails (`src/config.rs:1244-1262`).
* **Failover is fail-closed on identity**: relocations never downgrade a `DoT` entry to plain DNS
  silently — a downgrade is counted as a `dp` fact (`src/startup_dns.rs:3216-3230`), and the
  resolver set itself must be trust-homogeneous (`src/config.rs:829-836`).

Trust model, stated precisely because it is easy to misread: with a `#pin-sha256=` pin, the
verifier checks **SPKI pin + SNI/SAN + TLS handshake-signature verification** — the peer must
prove possession of the pinned certificate's private key (`src/startup_dns.rs:827-859`,
`:861-877`). Certificate validity exclusion is best-effort and counted only when the DER validity
parse succeeds (`ep`, `:846-848`); the DER walk fails open, so a parse anomaly reports no warning
rather than a rejection (`:1074-1085`). Pin-or-nothing and fail-open validity parsing are distinct
facts. Without a pin, chain validation runs against an explicitly empty root store (`:851-857`) and
therefore always fails — a deliberate "no trust anchors yet" position that surfaces as startup
warnings (`src/main.rs:127-143`). The consequence is that **DoT trust is pin-or-nothing**: there is
no CA-validated mode in the current build. That is a legitimate choice, but it means "`IP#fqdn`
without pin" is a deterministically unusable resolver rather than a degraded one.

**F-03 (S2, allocation profile).** `build_tls_connection` (`src/startup_dns.rs:1101-1120`) allocates
per connect (per-TLS-upgrade): `Arc::new(provider)`, `ClientConfig` (containing `Arc`s and `Vec`s),
`target.fqdn.as_str().to_owned()` (`String`), `Arc::new(AluminaServerCertVerifier)`,
`ClientConnection::new` (rustls internal buffers), plus `Box::new(conn)` at `:2100`
(`src/startup_dns.rs:2096-2102`); close/reconnect paths drop that TLS state. The warm reuse path
additionally allocates a bounded number of rustls per-record buffers: the repository's own witness —
a single warm successful-exchange fixture — asserts up to eight allocations **and** up to eight
deallocations independently against `WARM_DOT_ALLOC_BOUND = 8`
(`src/startup_dns/dot_tests.rs:1340-1348`, `:1416-1423`), with the transport itself realloc-free
(`:1416-1419`). That is a calibrated fixture bound, not a universal protocol bound and never an
eight-*total*-event maximum; it bounds total allocation activity on that one exchange, distinct
from the retained named storage the inventory reports. The boot-window zero-allocation witness says
in so many words that it qualifies the claim for a plain-DNS resolver only
(`src/startup_dns/tests.rs:1217-1224`). So the fixed-profile statement "no post-boot heap
alloc/dealloc" is true for the plain profile and *false as written* for a DoT profile. This is a
contract-wording problem with a real consequence: an operator or reviewer can read a green
alloc-witness run as proof of a global property; resolving the fixed-profile mismatch is an owner
decision (`alumina-szmy0.11`), not a documentation fix.

---

## 9. Observability architecture

Logging is a fixed 256-slot × 2 KiB ring (512 KiB) owned at boot (`src/log.rs:53-54`, `:1429-1441`),
encoded in place, drained by a single nonblocking `write_vectored` under a 16-fragment / 64 KiB
budget per turn (`:2049-2123`). Three properties are architectural rather than cosmetic:

1. **The sink can never stall serving.** fd 1 is made nonblocking once, after boot, by the binary
   only (`src/log.rs:1579-1590`, `src/serve.rs:367-369`), and `write_vectored` either progresses or
   latches `WouldBlock` with a retained cursor and a 100 ms retry (`src/log.rs:72`, `:2085-2107`).
   `tests/stdout_stall.rs` and `tests/monitor_stdout.rs` are the executable form of this claim.
2. **Drops are always counted, never silent.** Ring-full and encode-failure both `drop_one`
   (`src/log.rs:2163-2174`), a hard sink error drops the whole queue *through* the same counter
   (`:2094-2101`), and exit paths strand-count the residue (`src/serve.rs:1163-1172`,
   `src/log.rs:1668-1677`).
3. **Priority classes exist.** A reserved record can displace the newest normal record on a full
   ring rather than being dropped (`src/log.rs:2205-2266`). This is the mechanism that keeps
   shutdown/fatal evidence from being evicted by a monitor burst.

The weakness is the terminal state: once the sink latches `failed`, `next_drain` returns `None`
forever (`src/log.rs:1637-1646`), so a broken stdout permanently ends observability. Given the
stderr-free-after-sink-switch decision (`src/main.rs:76-81`, `src/serve.rs:371-384`) there is no
fallback channel, and the only surviving signal is the exit code plus the `dropped` counter. This
is a defensible deliberate choice; it should be recorded as accepted risk rather than discovered
during an incident.

`IncidentReport` is the second observability axis: 32 preallocated per-name windows with 3800 s
rotation, coalesced skipped windows, sticky per-window incident snapshots, and eligible-binding
transition tracking (`src/incident_report.rs:14-15`, `:99-181`, `:242-250`). Its per-turn pass over
all names (`src/serve.rs:431-485`) is O(32) and bounded, but it runs **every turn** regardless of
whether any window is near a boundary — a small, constant, always-on cost.

---

## 10. Type-level invariants (inventory)

| Invariant | Carrier | Citation |
|---|---|---|
| A gate cannot arm with threshold 0 / window 0 | `AllScopeGate{NonZeroU32, NonZeroU64}` | `src/enforcement/state.rs:25-46` |
| A gate can never be told a caller-invented hello boundary | `ValidatedHello::new(_accepted: HelloAccepted, ..)` | `src/gate.rs:114-142` |
| A blocked scope is applied only via a range-bounded ordinal, validated against the current table's entry count on lookup (out-of-range ⇒ `Unknown`/no control) | `DomainOrdinal` — `u8` index; `from_index` takes no table | `src/enforcement/action.rs:98-132`, `:206-230` |
| A stale DNS publish cannot overwrite a newer entry | `Generation` + `StaleGeneration` | `src/cache.rs:50-62`, `:373-382` |
| A slot is exactly one of free / in-setup / established | `SlotState` enum owns the counts | `src/worker.rs:344-354`, `:634-692` |
| A setup handle cannot free an established tunnel (and vice versa) | `SlotIndex` / `TunnelIndex`, consumed by release | `src/worker.rs:316-337`, `:570-614` |
| Serving without a listener is unrepresentable | `Preallocated` has no `serve`; `attach` consumes `self` | `src/runtime.rs:26-43`, `:153` |
| Ambiguous evidence cannot become a clean pass | `Effect::Unknown` variants | `src/enforcement/policy.rs:136-145` |
| No production panic on attacker input | crate-level `deny(clippy::unwrap_used, expect_used)`; no `panic!` in `src/` outside tests | `src/lib.rs:1-2`, verified by grep at the target SHA |

The last row is worth stating precisely: every `expect(...)` in production code carries an
`#[expect(clippy::expect_used, reason = ...)]` with a proven-bound justification (e.g.
`src/serving.rs:853-856`, `src/config.rs:1001-1004`, `src/cache.rs:369-372`), and release builds use
`panic = "abort"` (`Cargo.toml:226-229`), so a residual invariant violation cannot unwind into
half-mutated state. For a single-binary security component this is the right combination.

---

## 11. Findings

| ID | Sev | Area | Finding | Evidence |
|---|---|---|---|---|
| F-01 | S2 | Enforcement | `[early_data]` All-scope gate is unreachable; operator knob is inert | §7 above; `src/config.rs:1110-1115`, `src/enforcement/state.rs:271-277`, `:1415-1450` |
| F-02 | S2 | Contract | "No post-boot heap alloc" holds only for plain DNS; DoT allocates per connect (per-TLS-upgrade) and, on its one warm successful-exchange fixture, up to eight allocations and up to eight deallocations — a calibrated fixture bound, not a total/universal bound; owner decision pending (`alumina-szmy0.11`) | `src/startup_dns.rs:1101-1120`, `:2096-2102`; `src/startup_dns/tests.rs:1217-1224`; `dot_tests.rs:1340-1348`, `:1416-1423` |
| F-03 | S2 | Capacity | Retained boot floor ≈ 205 MiB (409 KiB/tunnel), vs a 128 MiB headline; inventory is an explicit lower bound | `src/inventory.rs:10-49`, `:176-196`, `:273-285` |
| F-04 | S2 | Design economy | 64 KiB inspector buffers for a 16 KiB handshake cap = 64 MiB of the 76.6 MiB workspace headroom | `src/client_hello.rs:6-18`, `:411-419` |
| F-05 | S3 | Supply chain | `rustls-pki-types` and `rustls-webpki` declared as direct deps, referenced by zero Rust files | `Cargo.toml:199-200`; grep over `src/`, `tests/`, `examples/` |
| F-06 | S3 | Robustness | Exchange class is a positional 2-call protocol; runtime cancels anything not marked serving/probe | `src/startup_dns.rs:2996-3007`, `:1613-1621`; `src/runtime.rs:258-262`, `:345` |
| F-07 | S3 | Hygiene | Slot buffers are not zeroized on reuse; only lengths/cursors reset | `src/serving.rs:774-803` |
| F-08 | S3 | API surface | 21 `pub mod`s + public test-seam constructors (`Serving::new`, `Runtime::new`) for two consumers | `src/lib.rs:4-27`, `src/serving.rs:1157`, `src/runtime.rs:207` |
| F-09 | S4 | Observability | Sink failure is terminal and silent-by-design after the first hard write error | `src/log.rs:2094-2101`, `:1637-1646` |
| F-10 | S4 | Positive | Single-clock discipline (`origin`+`now0` threaded through worker, cache, DNS) with an explicit re-anchor seam | `src/serve.rs:204-227`, `src/worker.rs:97-105`, `src/startup_dns.rs:1369-1381` |
| F-11 | S4 | Positive | Per-entry CNAME bailiwick + config-time divergence rejection | `src/dns.rs:863-953`, `src/config.rs:1244-1262` |

### F-05 detail (why it is not just tidiness)

`rustls` re-exports `pki_types`, and `src/startup_dns.rs:36` imports from `rustls::pki_types`, not
from the direct `rustls-pki-types` crate. Likewise `rustls_webpki` appears only inside a doc comment
(`src/startup_dns.rs:814`). Two direct dependencies therefore add no code but do add: two lines of
`rust-dep-intake` review surface, two pinned versions in `Cargo.lock`, and two entries the
`deny.toml` ban/multiple-versions checks must reason about (`deny.toml` `[bans]`). The Cargo comment
explains why `ring` was promoted (`Cargo.toml:201-206`); no equivalent rationale exists for these
two, which suggests they are leftover from an earlier verifier design.

### F-06 detail (the fragile seam)

`start_exchange` unconditionally constructs `ActiveExchange{ serving: false, probe: false }`
(`src/startup_dns.rs:2996-3007`). A serving refresh is therefore valid only because
`starts_due_dns_if_idle` immediately calls `mark_serving_started()` (`src/runtime.rs:345`), and a
probe only because the probe paths call `mark_probe_started()` inline
(`src/startup_dns.rs:3341`, `:3411`). `Runtime::turn` then cancels any exchange that still carries
neither flag (`src/runtime.rs:258-262` → `src/startup_dns.rs:1613-1621`). No type prevents a future
caller from starting a serving exchange and forgetting the mark; the failure mode is a silently
cancelled refresh, which degrades to "DNS never refreshes" rather than to a loud error. An
`ExchangeClass` parameter on `start_exchange` (or deriving it from the transport phase) would make
the protocol unrepresentable-to-misuse at zero runtime cost.

---

## 12. Risks and Unknowns

| # | Kind | Statement | Why it is Unknown |
|---|---|---|---|
| U-01 | Risk | `run_once` replaces `self.events` with `Events::with_capacity(0)` every turn and restores it (`src/serving.rs:1263`, `:1307`). The per-turn zero-allocation property depends on `mio`'s `with_capacity(0)` not allocating and `epoll_wait` writing into the pre-existing buffer. | Not verified here (no build). The `Phase::Serving` alloc witnesses in `src/serving/tests.rs` (`:5896`, `:5971`, `:6008`, `:7361`, `:7664`) probably cover the steady state, but this review did not execute them. |
| U-02 | Risk | The `Vec<SlotWorkspace>` is built by `collect()` from an exact-size iterator (`src/serving.rs:1028-1035`), so it is one boot allocation; any later growth would allocate post-boot. | Depends on `Vec`'s exact `size_hint` path; true for this code but not enforced by a type. |
| U-03 | Unknown | Real RSS includes allocator fragmentation, rustls/ring heap, and the kernel socket buffers for up to 512×2 sockets — none of it modelled by `BootInventory`. | Requires measurement, out of scope for a source-only review. |
| U-04 | Unknown | Whether the `early_data` gate is *intended* to become reachable again if `Block{All}` is ever legalised for early data (the `F-02 close` comment at `src/config.rs:1076-1082` suggests the restriction is intentional and permanent). | Intent is not inferable from code alone; treated as an inert knob, which is the as-built truth. The disposition is an open F-01/U-04 owner decision (bead `alumina-szmy0.9`), not decided by this document. |
| U-05 | Risk | A `DoT` deployment performs DNS refresh on a single connection with a 5 s exchange deadline; a failed handshake forces a full reconnect (and a fresh rustls config) on the next exchange. There is no persistent re-handshake backoff separate from the schedule ladder. | Design appears intentional (schedule backoff is 1/2/4/8/16/30 s, `src/schedule.rs:16`); flagged as a latency/CPU cost under resolver flapping, not as a defect. |
| U-06 | Risk | `SlotWorkspace::reset` leaves prior tunnel bytes in the retained 128 KiB slabs for the process lifetime (`src/serving.rs:774-803`). No path writes them out, but the buffers outlive the tunnel by design (`process::exit` skips drops). | Memory-disclosure only if a future path misuses `buf_len`; currently no such path found. |

---

## 13. Fitness against the declared repository constraints

Used as *criteria* only (`AGENTS.md`), applied to code:

| Declared constraint | As-built verdict | Evidence |
|---|---|---|
| Single boot owner, single serving owner | **Holds.** Linear consuming chain; `Preallocated` cannot serve; `attach` consumes. | `src/runtime.rs:40-172` |
| Two reused 128 KiB buffers per tunnel | **Holds, but understates cost.** The pair is real, and each slot *also* retains 153 KiB of parser/inspector. | `src/inventory.rs:10-36`, `src/serving.rs:625-697` |
| No post-boot heap alloc/dealloc | **Holds for plain DNS; a real mismatch for a DoT profile** (a calibrated fixture bound, not documentation-qualified; owner decision owns resolution). | `src/startup_dns/tests.rs:1217-1224`, `dot_tests.rs:1340-1348`, `:1416-1423` |
| No runtime-surface expansion (no CLI/env policy) | **Holds.** Fixed `config.toml`; only `/proc/self/status` is read; the `fixture-facts` feature is compile-time only. | `src/main.rs:22`, `:150-169`, `src/preflight.rs:123-130` |
| No silent acceptance; tripwires fire on first deviation | **Holds in mechanism** (default threshold 1, first-slot latch, `Unknown` never `BaselineOnly`). **One lexicon gap**: the `[early_data]` bar is inert (F-01). | `src/enforcement/state.rs:12-17`, `policy.rs:113-146` |
| Operator chooses the action; proxy owns the semantics | **Holds.** Actions/scopes are config; the latch, the two barriers, the refusal bodies and the two-barrier ordering are code constants. | `src/config.rs:855-999`, `src/gate.rs`, `src/serving/policy.rs:16-34` |
| Scope stays CONNECT-egress-with-allowlist | **Holds.** No payload inspection, no ingress policy; the client hello is inspected only for the three profile rules. | `src/client_hello.rs:1108-1121` |

---

## 14. Recommended next steps (ordered by value/cost)

1. **Decide the DoT allocation stance and write it down in the profile.** Either (a) keep the
   bounded seam and state the profile as "plain: zero; DoT: bounded per-connect (per-TLS-upgrade),
   up to eight allocations and up to eight deallocations per warm successful exchange",
   or (b) hoist the rustls `ClientConfig`/verifier to boot so only the `ClientConnection` allocates
   per connect. Option (b) removes the `Arc`/`String` churn and makes the per-connect cost one
   object; it does not remove rustls's internal allocations, so the profile must be qualified either
   way. (F-02)
2. **Decide F-01/U-04 in a separately governed step.** The `[early_data]` All-scope knob is inert as
   built; the disposition — document it as inert in operator material, or reconcile the schema/spec
   in a separately governed decision — is not settled by this document (owner bead
   `alumina-szmy0.9`). Independent of that decision, replace the `state.rs` test's direct
   `ControlTable` construction with a config-derived one (`src/enforcement/state.rs:1415-1450`) so
   any future reachability is proven against a config the parser can actually produce.
3. **Publish the real retained-memory figure** (≈409 KiB/slot, ≈205 MiB at 512 slots) wherever
   capacity is described, and consider folding the excluded per-slot fields into `BootInventory`
   so the accessor stops being a lower bound over a subset.
4. **Delete or justify the two unused direct dependencies.** Cheapest finding to close. (F-05)
5. **Make the exchange class a parameter of `start_exchange`.** Small change, removes a silent
   degradation mode from the refresh path. (F-06)
6. **State the terminal-sink behaviour as accepted risk** in the operator-facing material: after the
   first hard stdout error, log loss is counted but unrecoverable. (F-09)

Not recommended: shrinking the 64 KiB inspector buffers without first deciding whether multi-record
pre-hello fragmentation is a stated requirement. The 4× headroom is the cheapest memory lever
(F-04) but it is also the one most likely to break an adversarial fixture.

---

## 15. Review verification

* Target SHA re-read before and after the review: `git rev-parse HEAD` →
  `3f587e947fa8f050954b2f1fa7ec6b47012ac769`, branch `main`.
* `git status --porcelain` before review: `?? scripts/verify_alt.sh` only (pre-existing, owned by
  another job; untouched).
* Evidence base: 27 tracked `src/` files and 8 tracked `tests/` files read directly at the target
  SHA. No `docs/` file was opened for architectural claims; `AGENTS.md` was read only as the
  stated constraint set.
* No build, test, formatter, clippy, git mutation, or long-running command was executed. Findings
  are static-reading findings; severity reflects confidence in the *code reading*, not runtime
  observation. Unknowns are enumerated explicitly in §12 rather than resolved by inference.
* Deliverable: this file only, under `arch_alt/`.

```text
→ to: moltke | status: complete | next_input: triage F-01 (inert [early_data] gate) and F-02 (DoT allocation profile wording); both are contract-semantics decisions, not code edits | artefact: arch_alt/architecture-review.md
```
