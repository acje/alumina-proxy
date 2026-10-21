# Group 11 — Robustness / Telemetry

**Subsystem:** `client_hello.rs`, `serving/reject.rs`, `startup_dns.rs`, `serving/startup.rs`, `main.rs`
**TRUE POSITIVE findings:** 3
**Severity mix:** Low/Obs ×1, Info ×2

---

## W1-H1b-F4 — Info — `HandshakeTooLarge` folds to `Profile`, not tripwire-distinct

**Scorecard row:**
```
| W1-H1b-F4 | Info | src/client_hello.rs:203-220, serving/reject.rs:46-51 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | ChError::HandshakeTooLarge { got } (client_hello.rs:80, produced :394-395 when need=4+msg_len > MAX_HANDSHAKE_LEN=16KiB) folded to HelloRejectReason::Profile via from_ch_error (client_hello.rs:203-204,220); got discarded; serving reject_hello(index, from_ch_error(&err)) at serving.rs:2533,2556; telemetry: single Profile counter slot (policy.rs:17, monitor.rs:137) shared by ~17 ChError variants; log fixed "tls_validation" (log.rs:79,90); gate TerminateReason::ClientHelloRejected (gate.rs:205-207); no distinct counter/log; fold documented intentional (docs/alumina-proxy.md:480, client_hello.rs:193-196); tests pin ChError-level only (client_hello.rs:1100-1128); Info fair |
```

**Working description (alox-f, H1b):**
F4 [Info] V34 observability — `HandshakeTooLarge` folds to `HelloRejectReason::Profile` (`client_hello.rs:203-220`, `serving/reject.rs:46-51`); not tripwire-distinct.

---

## W6-H6b-F4 — Low/Obs — four `unwrap_or` sites would mask a broken invariant

**Scorecard row:**
```
| W6-H6b-F4 | Low/Obs | src/startup_dns.rs:2424,2429; serving/startup.rs:87,116 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | four unwrap_or sites confirmed: startup_dns.rs:2422-2424 last_published.take().unwrap_or(ResolvedPositive), :2428-2429 last_failed.take().unwrap_or(Receive), serving/startup.rs:83-87 take_published_kind().unwrap_or(ResolvedPositive), :112-116 take_failed_reason().unwrap_or(Receive); Published invariant holds — last_published set at sole site :1881 immediately before sole RecvStep::Published return :1899, sole source of TurnResult::Published :2370-2376; Failed invariant holds — last_failed set at sole site :2556 inside note_failure :2549-2561, every TurnResult::Failed return (:2335,:2343,:2352,:2361,:2368) preceded by Step::Failed preceded by note_failure (connect :1469-1509,:1567; handshake :1586-1593; send :1699-1763; send_tls :1798-1812; recv :1850-1914); no debug_assert/assert/log at unwrap sites or ledger consumers (serving/startup.rs:99,117) → broken invariant would silently mask (defaults plausible benign values :160,:326); structural fix aligned with ExchangeResult::Published/Failed design (:185-189); no reachable violation at HEAD; Low/Obs fair |
```

**Working description (alox-f, H6b):**
F4 [Low/Obs] `.unwrap_or(PublishedKind::ResolvedPositive)` / `.unwrap_or(FailureReason::Receive)` (`startup_dns.rs:2424,2429`; `serving/startup.rs:87,116`) — invariant holds today (every Published preceded by `last_published=Some` :1881; every Failed by `note_failure` :2549-2561); default would mask a bug if invariant broken. Fix: return reason/kind structurally.

---

## W6-H6b-F6 — Info — `main.rs:126` best-effort stderr write on immediately-exiting boot path

**Scorecard row:**
```
| W6-H6b-F6 | Info | main.rs:126 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | write_stderr helper main.rs:124-127 (`let _ = std::io::stderr().write_fmt(args);` :126, Result discarded); exactly 4 call sites, all immediately-exiting boot paths: :67→exit(EX_CONFIG) :68, :74→:75, :79-81→:82, :118→:119; EX_CONFIG=78 (boot.rs:7); write genuinely best-effort (I/O error silently ignored); no fail-closed impact — process::exit unconditional in every call site, write only suppresses diagnostic on already-decided EX_CONFIG exit, cannot let process proceed past any fail-closed gate (preflight/config/storage/log-sink); separate emit_fatal_and_drain/emit_shutdown_and_drain (:92,:107,:112) out of scope; Info fair (cosmetic, idiomatic let _ discard, no action implied) |
```

**Working description (alox-f, H6b):**
F6 [Info] `main.rs:126` best-effort stderr write on immediately-exiting boot path — no fail-closed impact.
