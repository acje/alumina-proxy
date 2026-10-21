# Group 3 — CONNECT & ClientHello Parsing

**Subsystem:** `src/connect.rs` request-line/head parsing, `src/client_hello.rs` TLS handshake bounds, `src/serving.rs` gate wiring
**TRUE POSITIVE findings:** 5
**Severity mix:** High ×1, Medium ×2, Info ×2

---

## W1-L1b-F2 — Medium — space-in-target mis-split

**Scorecard row:**
```
| W1-L1b-F2 | Medium | src/connect.rs:361-368 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | target_end = first space after method (connect.rs:354-362); space-in-target mis-splits authority/version; parse_target validates but split flaw real |
```

**Working description (alox-f, L1b):**
[Medium] Request-line parsing, `src/connect.rs:361-368` — `target_end` = first space after method; crafted `CONNECT <target_with_space> HTTP/1.1` could mis-parse (parse_target strict about `:port` mitigates).

---

## W1-L1b-F6 — Info — O(N) head scan, bounded

**Scorecard row:**
```
| W1-L1b-F6 | Info | src/connect.rs:246-252 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | find_end_of_head is O(N) linear scan (connect.rs:243-248); bounded by CONNECT_LIMIT 8KiB; accurate Info observation |
```

**Working description (alox-f, L1b):**
[Info] `find_end_of_head` O(N) window, `src/connect.rs:246-252` — trivial.

---

## W1-H1b-F5 — Info — 16 KiB bound rejects spec-legal multi-record ClientHello

**Scorecard row:**
```
| W1-H1b-F5 | Info | 16 KiB bound | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | MAX_HANDSHAKE_LEN=16KiB (client_hello.rs:12) enforced on total accumulated handshake message via 3-byte header length claim need=4+msg_len (client_hello.rs:390-396); per-record limit separate RECORD_PAYLOAD_LIMIT (client_hello.rs:9,:364-367); check fires as soon as 4-byte header flattened, before full reassembly; RFC 8446 §5.1 allows messages spanning records (per-record ≤2^14); multi-record >16KiB message rejected → HandshakeTooLarge; pinned by exact_fill_64k_incomplete_stream_does_not_panic (client_hello.rs:1140-1166, 4 records ≤16KiB → HandshakeTooLarge{got:65536}), rejects_handshake_length_claim_over_bound (:1100), exactly-at-bound not rejected (:1116); enforced live path serving.rs:2524,2532-2534; documented V34 (docs/alumina-proxy.md:478-480, future-hardening-vectors.md:147); Info fair |
```

**Working description (alox-f, H1b):**
F5 [Info] V34 interop bound — 16 KiB rejects spec-legal multi-record ClientHello (per-record ≤16 KiB but message may span records).

---

## W7-L7a-F2 — High — slow-client pseudo-handshake holds slot buffer (bounded)

**Scorecard row:**
```
| W7-L7a-F2 | High | src/client_hello.rs:10 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | MAX_CLIENT_HELLO=64*1024 at client_hello.rs:6 (finding cites :10 = RECORD_PAYLOAD_LIMIT — citation drift only); ChInspector buf+scratch 2×64 KiB (client_hello.rs:262,266), feed() retains bytes on incomplete records (:315-320,:343-374); per-slot inspector serving.rs:569 fed via buffer_and_validate :2515-2541; expire_sweep serving.rs:3009-3040 → expire_setup closes ValidatingHello :3046-3059; SETUP_DEADLINE_SECS=10 (worker.rs:51), Deadline::setup=accept+10s never reset (worker.rs:219-223), armed at admit serving.rs:1725-1729, enforced every poll turn (poll_timeout :2931-2991 + run_once/expire_sweep :1185-1187); bounded ≤128 pending setups (worker.rs:45) × ~256 KiB ≤10s, fixed boot-owned memory (inventory.rs:18); slowloris seat-occupancy, not unbounded — severity nuance High→Medium |
```

**Working description (alox-f, L7a):**
[High] TLS handshake, `src/client_hello.rs:10` — MAX_CLIENT_HELLO 64 KiB; a slow-client/fragmentation "pseudo-handshake" (validly framed records never completing a ClientHello) holds a slot's buffer up to max; `expire_sweep` mitigates long-term but per-slot exhaustion is a localized resource-exhaustion vector; ensure `setup_deadline` (serve.rs) is aggressive enough. *(Scorecard nuance: bounded ≤128 pending setups × ~256 KiB ≤10s — slowloris seat-occupancy, not unbounded; severity nuance High→Medium.)*

---

## W7-L7a-F3 — Medium — CONNECT gate wiring correct at HEAD

**Scorecard row:**
```
| W7-L7a-F3 | Medium | src/serving.rs:2470 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | CONNECT gate wiring correct at HEAD: upstream_readable serving.rs:1421 → gate.is_open() :2411-2412 gates sole relay entry; closed gate → observe_upstream_read :2440 reads into local scratch (never ws.down), gate.observe_upstream_activity :2460 terminates setup (gate.rs:249-256), violation EarlyUpstreamData{:2470}/EvidenceInsufficient{:2474} → project_tripwire :2476 → close_slot :2487 (reject.rs:53-73); is_open() true only in RelayActive (gate.rs:261-263), reachable only via upstream_write crossing validated hello end H (gate.rs:217-244, serving.rs:2658-2672); no bypass — relay_upstream_to_client :2764 only from is_open() branch :2412 or Stage::Relay :2833 (set :2672 post-open; :1646 cfg(test)-only); dual barriers real (A client→upstream, B upstream→client); tests pin behavior (serving/tests.rs:4446-4511 prevalidated_early_data_folds_unknown_without_any_block, :4390-4444); terminology slip only — finding labels early_upstream_data "Barrier A" but it's a Barrier B concern (non-substantive) |
```

**Working description (alox-f, L7a):**
[Medium] CONNECT gate wiring, `src/serving.rs:2470` — early_upstream_data (Barrier A) → `project_tripwire` + `close_slot`; correct. Upstream data before ClientHello validated → anomaly via `gate.is_open()` (:2412, :2440). Dual-barrier robust against early-data injection. *(Scorecard nuance: terminology slip only — early_upstream_data is a Barrier B concern, not Barrier A; non-substantive.)*
