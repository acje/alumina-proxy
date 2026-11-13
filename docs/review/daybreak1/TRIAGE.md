# Daybreak-1 triage — alumina-proxy security scan

Status: triage v1, 2026-11-12. Working register, not an acceptance record.
Epic: `alumina-gzqn4` · Ledger: `alumina-gzqn4.1` · First mission: `alumina-gzqn4.2`

Authority: `docs/alumina-proxy.md` is the sole byte-canonical governing specification
(sha256 `416062eb…`, byte-frozen). This document records triage verdicts that arbitrate
code-versus-spec deviations. It does not amend the specification, and it is not
authoritative over `bd`: binding dispositions live in the ledger bead.

---

## 1. Provenance

| Field | Value |
|---|---|
| Scan | `3053f742-e10f-4e92-82c2-d46a941c1a82` (daybreak1) |
| Producer | `codex-security-plugin` 0.1.32, mode `deep_repository` |
| Target | git revision `4f1c2c16b89d30eeef20e2f3b8354ed6243bbde3` (= current `HEAD`) |
| Status | **canceled** — `sealedAt` 2026-11-11T13:54Z → 2026-11-12T09:47Z |
| Coverage | **partial**: 126 files in scope, 63 fully reviewed by one worker, 33 deferred records |
| Saved findings | 32 (14 medium, 18 low); 21 `validated`, 1 `confirmed`, 10 unlabelled; 20 high / 12 medium confidence |
| Method | offline static source tracing; **no execution, no runtime reproduction, no advisory lookup** |

Artifact digests (record these with any future comparison):

```
95fefba08dca75f1348ec9e2a5fa0353af941403c9d8eaa1b16f4d36f4c1631e  findings.json
f3f3c314a42b31d720693f0873786c70bbbeb58c5ea7733d77355568bfc5456a  coverage.json
c7d34e162e18e6e8abcee658e5718a697b44cc8709d44e31fb7d95e71b2eb994  scan-manifest.json
870bd9257c0ed1cc21ed3b79fb4a614549271201a3b63cb2364e8d8547051541  alumina-proxy · Canceled Deep Security Scan.html
```

### What this document can and cannot claim

- Every row below was **re-verified against `HEAD 4f1c2c1` by this triage pass**, not
  carried over from the scanner. Where the scanner's reasoning did not survive that
  re-check, the row says so (D6).
- The scan was **canceled**, so coverage is partial. **Absence of a finding is not
  absence of a defect.** No row, and no summary here, may be used as a clean-scan claim.
- Findings are **conditional** wherever they depend on deployment facts (firewall,
  resolver pins, stdout collector, test-host temp isolation, 32-bit target, operator
  JA4 policy) that the scan did not have and this repository cannot supply. Those
  conditions are stated per row; they are not softened into the verdict.
- 32 findings are **26 distinct titles and 18 distinct root causes**. The scanner's own
  index notes that duplicate titles are preserved, not merged. Deduplication is this
  document's job and is done structurally (root cause + code region + fix), never by
  title.

---

## 2. Vocabulary

Verdict (what is true):

| Verdict | Meaning |
|---|---|
| `Confirmed` | Defect reproduced at source against the governing spec or a stated objective; conditions are either met by the documented deployment or stated as a prerequisite. |
| `Confirmed-Conditional` | Defect is real at source, but exploitability/impact depends on an unverifiable deployment or timing precondition. Fix or accept on merit. |
| `Spec-Intended` | Code matches an explicit, recorded specification decision. Not a defect. Residual risk is a governance question, not a bug. |
| `Refuted` | Scanner claim does not hold at `HEAD`. Recorded so it is never re-triaged. |
| `Duplicate` | Same root cause and same fix as another finding; folded, never independently fixed. |

Disposition (what we do): `Fix` · `Accept-risk (recorded)` · `Correct-documentation` ·
`Governance-decision`.

---

## 3. Register — 18 root causes

Priority is remediation order, not severity alone: spec-violating enforcement and
release-assurance gates first, telemetry and test hygiene last.

| ID | Root cause | Findings | Sev | Verdict | Disposition | Pri | Mission |
|---|---|---|---|---|---|---|---|
| D1 | JA4 Block leaves the triggering tunnel active (no Connection branch; Domain excludes the offender) | 9 | med | Confirmed | Fixed — `681e81e`, `0205f69` | P1 | M1 ✓ |
| D2 | JA4 block decided after the first upstream flush | 1 | med | Confirmed | Fixed — `c0885b3` | P1 | M1 ✓ |
| D3 | JA4 baseline seeds 16 fingerprints; decision only on overflow | 1 | med | Spec-Intended | Fixed — amendment G1 (SP-015) `68c064c`, `c8336e1`, `48a90f5` | P1 | G1 ✓ |
| D4 | Per-domain JA4 peer attribution collapses to one global pair | 1 | low | Confirmed | Fixed — `325034e` | P2 | M3 ✓ |
| D5 | Bare-IP resolver uses plain DNS under default `resolver_trusted` | 1 | med | Confirmed-Conditional | Fixed — amendment G2 (`b48e320`) + G2a (`cbaecfa`) | P2 | G2 ✓ |
| D6 | Unsafe-surface docs gate can certify production `unsafe` (symlink + second declaration) | 2 | med | Confirmed (1 sub-claim Refuted) | Fixed — `467e13c`…`56eb45d` | P1 | M2 ✓ |
| D7 | E2E receipt omits untracked compiled build inputs | 2 | low | Confirmed | Fixed — `68e9af1`, `66df647`, `c1b54b8`, `94b9a28` | P2 | M5 ✓ |
| D8 | Shutdown E2E no-admission witness can pass on a forgotten reachable probe | 1 | low | Confirmed | Fixed — `813cd43`, `e64876e` | P2 | M5 ✓ |
| D9 | Expired connect/setup/idle deadline consumed or replaced at a transition | 1 | low | Confirmed-Conditional | Fixed — `c316ecf` | P2 | M4 ✓ |
| D10 | Listener accept backoff has no pause guard and no poll wake | 1 | med | Confirmed | Fixed — `f86213d`, `22e63d7`, `e110da9` | P2 | M4 ✓ |
| D11 | 32-bit slot token truncates the generation field | 1 | low | Confirmed-Conditional | Fixed — `ed7f97c` | P2 | M4 ✓ |
| D12 | Pending setup pool has no per-peer fairness; 128 incomplete heads deny new clients | 1 | low | Confirmed-Conditional | Fixed — `1d7e1e0` (+`00beb19`) | P2 | M4 ✓ |
| D13 | Report-time drop accounting mutates after the summary is encoded, then clears | 1 | low | Confirmed | Fixed — `f24d401` | P2 | M3 ✓ |
| D14 | Reserved forced monitor summary displaces the queued `shutdown_final` verdict | 1 | low | Confirmed | Fixed — `ea48493` | P2 | M3 ✓ |
| D15 | Reopened DNS incident inherits the other family's prior failure snapshot | 1 | low | Confirmed | Fixed — `e591abd` | P2 | M3 ✓ |
| D16 | Predictable test/benchmark temp paths permit symlink clobber (4 sites) | 5 | low | Confirmed-Conditional | Fixed — `e6a25c9`…`9be04d6` | P3 | M6 ✓ |
| D17 | Reference deployment admits the whole VPC subnet to the proxy | 1 | low | Confirmed | Correct-documentation | P3 | M7 |
| D18 | Combined upstream error+readable readiness skips early-activity telemetry | 1 | low | Confirmed-Conditional | Fixed — `5b31ef2` | P2 | M3 ✓ |

Sum check: 9+1+1+1+1+2+2+1+1+1+1+1+1+1+1+5+1+1 = **32**. Mediums: D1(9)+D2(1)+D3(1)+D5(1)+D6(1)+D10(1) = **14**; lows = **18**.

---

## 4. Register detail

### D1 — JA4 Block leaves the triggering tunnel active · Confirmed · Fixed (M1)

Claim: with a full 16-entry JA4 baseline for an allowlisted ordinal, a 17th distinct
ClientHello fingerprint that selects `block` does not close the triggering tunnel.

Verification at HEAD:
- `src/runtime/reactor.rs:2405-2429` `project_tripwire` matches only `Effect::Block { scope: All }`.
  There is **no** `Scope::Connection` arm.
- `src/runtime/reactor.rs:2371-2381` `stop_domain_block(ordinal, except)` closes same-ordinal
  slots **except** the triggering index; the JA4 call site passes `index`, so the offender
  survives its own block.
- Later relay I/O checks only the all-scope latch.

Arbitration — `docs/alumina-proxy.md:309-311` §Block and Notify semantics:
"**Block Connection:** terminates the offender connection only"; "**Block Domain:** … it
affects current and future flows matching that ordinal until restart". Block All
"synchronously prevents all subsequent application I/O … before any further I/O".
No clause permits the offender to continue, and the §No-silent-acceptance doctrine makes
a fired tripwire a high-value signal that must be acted on. **Code violates the spec.**

Fix: close the triggering slot for **every** `Effect::Block`; keep Domain's closure of
other same-ordinal slots and drop the offender exclusion. No config or spec change.

Named tests: seed 16 distinct JA4s, then a 17th with Block Connection → zero upstream
bytes and slot closed; repeat for Block Domain; All-scope threshold crossing with
coalesced trailing bytes and a `WouldBlock` write path.

Duplicates folded: 9 findings (`csf_5cf9845c…`, `csf_2c5f1141…`, `csf_4c880ecd…`,
`csf_a3e98acd…`, `csf_989ba59d…`, `csf_d43ae0b1…`, `csf_1352c94f…`, `csf_b61ca9b8…`,
`csf_8cc1dbf7…`).

**Fixed at `0205f69`** (candidate): `project_tripwire` gained a `Scope::Connection` arm and
the Domain arm no longer excludes the offender. Red evidence: 92 B and 98,396 B reached the
upstream under a configured block; after, zero bytes and the slot closes. Boundary
`host-mid union` PASS at `0205f69` (`UNION-MID-OK`, `ALT-COPY-OK`, binary sha256
`af65fa86…`), 1,119 lib tests pass, adversarial review APPROVE (`alumina-gzqn4.2.4`):
0 Critical/High/Medium.

### D2 — JA4 block decided after the first upstream flush · Confirmed · Fixed (M1)

Verification at HEAD: `src/runtime/reactor.rs:2853` calls `flush_client_upstream(index)`
immediately before `2854 maybe_record_ja4_baseline(index)`; the drain writes the retained
buffer at `2935-2943`. The block decision therefore cannot precede the bytes it is meant
to stop — including for Block All, whose contract is "before any further I/O".

**Fixed at `c0885b3`**: the JA4 decision precedes the first upstream flush, and both the
`hello_complete` and `dial` paths withhold I/O on a Block effect. Red evidence: Block All
leaked 98,396 B (ClientHello + coalesced tail) and a `WouldBlock` path leaked 4,096 B
(SO_SNDBUF partial write); after, both are zero with `buf_len == 0`.

Distinct defect, same seam as D1, separate red test. Remediated in M1 as increment 1.

Registry: `csf_0ac80ddb…` (`ja4-block-late-enforcement`).

### D3 — JA4 baseline seeds 16 fingerprints · Spec-Intended · Fixed (G1)

Verification at HEAD: `Ja4BaselineTable::record` (`src/runtime/reactor.rs:596-625`)
returns `FirstSeen` for any value not already present, and
`maybe_record_ja4_baseline` (`2886-2898`) selects an action only on `Overflow`.

Arbitration: this is **deliberate**. SP-005 (`docs/alumina-proxy.md:1068-1078`) makes the
per-ordinal set of K=16 distinct JA4 strings normative — chosen to stop per-IP baselining
from conflating clients behind one proxy — and records suppress-with-count.
F-08 (`1231-1233`) then separates "deviation decision" from "bounded detail set" and makes
**overflow** the decision point. Prior decision bead: `alumina-smigc.12`.

Note: T4 prose at `docs/alumina-proxy.md:952` and `:700` still says "per-ordinal+address
baseline"; `:1249` explicitly corrects that and states there is no per-(ordinal,IP)
baseline. That is stale prose inside the spec, not a code defect.

Residual risk (real, accepted by design): an attacker may consume up to 16 baseline slots
per ordinal before any selection occurs; those 16 profiles are never action-selected.
This is the intended F-08 trade-off, not a bypass.

Disposition: **G1** — the user elected on 2026-11-12 to open a governed amendment
rather than record an acceptance. Draft only; adoption requires explicit user
authorisation of the exact text plus the full governed increment (spec + digest pin +
code + tests, independent source and governance review). Implementation is gated on that
adoption.

**Adopted at `48a90f5`**: SP-015 makes seeding exactly the ordinal's first distinct
fingerprint; every later distinct value selects the configured action, in capacity or at
overflow. Two in-place coherence corrections were authorised mid-increment: the P-F09 block
(`:1683`, `:1690-1692`, `:1695-1699`) and the tag `BaselineOutcome { Seed, Changed,
Unchanged, Overflow }`. The detail-loss latch was split out of `note_fact_ja4_change`
(`0367b28`) so an in-capacity change cannot report suppressed detail. Two review repairs
landed (`bc91d87` comment drift, `48a90f5` ignore parity). Digest `b9941f00…` → `d43d938f…`;
boundary PASS on the repaired candidate (`ALT-COPY-OK`, binary `1259782f…`); both gates
APPROVE (`alumina-gzqn4.3.3` source, `alumina-gzqn4.3.6` governance). Boundary attempt 1
failed on the pre-existing `due_refresh::sigterm_stops_due_refresh_flow` ephemeral-port race
(`alumina-t4vlg`), unrelated to JA4; attempt 2 passed.

**G1a repair (`53810b8`, digest `73bd18be…`)**: T4 now states the trigger as a delta from
the per-ordinal baseline and names the ordinal's first distinct fingerprint as the seed;
SP-015's citation of `note_fact_ja4_change` corrected to `monitor.rs:269-280`. Governance
APPROVE (`alumina-gzqn4.3.7`); no source review, because the increment changed no code.

Remaining text residuals are **batched into G3**, not chased per-nit: `:701` (SP-015's
other declared-superseded sentence, still byte-identical by design) and `:1348` (a second
stale `monitor.rs` line citation). Both are citation/precision drift, not false claims.

Registry: `csf_bf60a65e…` (`ja4-change-detection-bypass`).

### D4 — Per-domain JA4 peer attribution · Confirmed · Fixed (M3)

Verification at HEAD: `src/enforcement/monitor.rs:281-282` stores a single global
`ja4_peer_ip` plus `ja4_peer_ordinal`; `src/log/encoding.rs:1014-1019` emits `d<j>p` only
when that stored ordinal equals the domain being encoded. Two domains changing in one
report interval leave the first domain without `d<j>p`.

Arbitration: F-08 (`docs/alumina-proxy.md:1233`) specifies per-domain
`d<j>p` = "triggering peer"; SP-013 (`:1160-1181`) makes the triggering peer part of the
record. **Code violates the spec.**

**Fixed at `325034e`**: per-ordinal peer storage (boot-fixed, 544 B, zero heap) with one
`d<j>p` per changed ordinal inside its own domain block. Red evidence: `d0j`/`d0v` rendered
with **no `d0p`** and only the last ordinal's peer appeared.

**Geometry re-measured, and my estimate was wrong.** Measured `monitor_domain` worst case is
**1,870 B / 178 B headroom**, not the ~1,854 B I fabricated. The first pin (1,800 B) was also
wrong: the batch under-filled with 10 single-digit plus 1 two-digit block; the maximal
eleven two-digit-index batch (11 × 164 B + 66 B framing) is now pinned (`a4fe926`). At 178 B
`monitor_domain` is now the **tightest record** in the vocabulary, ahead of `resolver_probe`
(191 B) — which makes the spec's "resolver_probe is the tightest" sentence false and is
routed to G3 (`alumina-gzqn4.19`).

Test: two domains overflow in one interval; both `d<j>p` present and correct, plus the
record-geometry test re-measured against 2048 B.

Registry: `csf_ecd441bf…`.

### D5 — Plain-DNS resolver under default assurance · Confirmed-Conditional · Fixed (G2 + G2a)

Verification at HEAD: `src/dns/resolver.rs:190-212` gives a bare-IP entry port 53 (plain
TCP) and no DoT identity; `src/config/mod.rs:946-957` defaults per-entry
`dns_assurance` to `ResolverTrusted`. A network-positioned attacker on the resolver hop
can substitute answers, redirecting an allowlisted CONNECT to an attacker-chosen public
IP. The proxy does not verify the upstream certificate; the **client** does.

Arbitration: `docs/alumina-proxy.md:1729` explicitly admits `resolver_trusted`
(including omissions) as "unauthenticated trust; legacy behaviour preserved". This is a
declared operator capability, not an implementation bug. Impact is bounded by the
allowlist and by client-side TLS verification.

Disposition: **G2** — the user elected on 2026-11-12 to open a governed amendment rather
than record an acceptance; semantics chosen and text authorised 2026-11-13.

**Adopted at `cbaecfa`** (`b48e320` amendment, `ea1661a`/`408b550`/`ab63f18`/`7a54d76`
migration, `cbaecfa` coherence). `dns_assurance` is now a mandatory per-entry key; a missing
key is `InvalidDnsAssurance` (exit 78), never a silent legacy admission. Five spec sites
were corrected in G2a after adoption closed two live self-contradictions (`:792-793` had made
the mandatory key invalid). One deliberate deviation, reviewed and accepted: the parser
holds `Vec<AssuranceRequirement>` instead of a fixed array, because a fixed array needs the
removed placeholder; allocation stays pre-serving and `ALLOWLIST_MAX` is still enforced.
Residual: no unauthenticated *path* remains, but `resolver_trusted` still admits
unauthenticated evidence when explicitly declared — accepted as the operator's stated choice.

Registry: `csf_301d7454…`.

### D6 — Unsafe-surface docs gate can certify production `unsafe` · Confirmed (one sub-claim Refuted) · Fixed (M2)

Verification at HEAD (`scripts/verify.sh`):
- **Symlink bypass (holds).** `859-875` scans with `rg -l '\bunsafe\b' --glob '*.rs'`;
  ripgrep does not traverse symlinks. `890-918` (`intended_coverage_gate`) enumerates
  `find src tests \( -type f -o -type l \)` and *admits* a resolving `.rs` symlink. A
  production `src/*.rs` symlink is therefore admitted by the inventory and skipped by the
  scanner → false `UNSAFE-SURFACE-OK`.
- **Second-declaration masking (holds).** `921-979` `cfg_test_parentage_gate` accepts the
  **first** matching `#[cfg(test)] mod <stem>;` and stops scanning, so
  `#[cfg(feature = "x")] mod tests;` placed after a `#[cfg(test)]` declaration still passes.
  Probed by this triage pass: first-match = pass.
- **"Raw text can match comments" (Refuted).** Both awk branches anchor at
  `^[[:space:]]*#\[cfg\(test\)\]`; neither a `//` line nor a `/* … */` line can match.
  Probed: line-comment and block-comment fixtures both report `no-match`. The scanner
  over-claimed this variant.
- **Symlinked test module (holds).** `cfg_test_parentage_gate` uses
  `find src -mindepth 2 -type f`, which skips `-type l`; a symlinked `tests.rs` is admitted
  by filename elsewhere but never parentage-checked.

Arbitration: the gate is a local release-assurance control; a false PASS is a verification
defect, not a runtime exploit. The scanner's medium rating assumes a trusted workflow
relies on `verify.sh docs` for untrusted contributions — unestablished but plausible.

Fix (M2): (a) decide unsafe on the **resolved content of every admitted path** (explicit
file list or `rg -L`); (b) parentage gate enumerates symlinks and rejects any additional
non-`cfg(test)` declaration of the same stem. Guard proof required per shape:
`plant → fail → revert → clean`. Review tier: adversarial.

**Fixed at `56eb45d`** (`467e13c` universe, `3115cd5` every-declaration attribution,
`8b084b8` regression pins, `549d84c` structural attribution, `56eb45d` NUL-safe transport).
The scan now decides over the resolved content of the find-enumerated path list passed as
explicit arguments; the parentage gate counts **every** declaration of the stem under any
visibility prefix and accepts attribution only from a structural attribute prefix. Guard
proofs on the final candidate: symlinked production `.rs` → exit 1 (was **0, false pass**);
second non-`cfg(test)` declaration → exit 1 (was **0**); whitespace-bearing path → exit 1;
each reverts to exit 0. `verify_test.py` 30 tests OK (23 gate pins, red-proven against
pre-fix bodies); `verify.sh docs` exit 0; boundary `host-mid union` PASS at `56eb45d`
with binary sha256 `af65fa86…` — **identical to M1**, independently proving no production
code was touched. Review round 1 NEEDS WORK (whitespace-path false pass, OK-line
overclaim) → round 2 APPROVE, 0 blocking.

Accepted residual (recorded, `alumina-gzqn4.5`): the gate is deliberately **stricter than
Rust**: `cfg(all(test, …))` and doc comments inside an attribute block fail closed, and a
whitespace-bearing path is a scan failure rather than a scanned path. That is the correct
bias for an enforcement gate (it can only get stricter, never greener), but it is a
maintainability cost: a legitimate future shape fails with a named parent and declaration,
so the remedy is visible. No new dependency; fail-closed producer semantics preserved
(exit ≥ 2 fails, exit 1 from the producer is a clean no-match).

Registry: `csf_a4bf4a95…`, `csf_f2b0f388…`.

### D7 — E2E receipt omits untracked build inputs · Confirmed · Fixed (M5)

Verification at HEAD: `scripts/verify.sh:1526-1546` builds the receipt from `HEAD`,
`git diff HEAD`, and three explicit harness/shell hashes. Untracked files are absent
(`git diff` does not see them). The E2E selectors (`1640-1670`, `1705-1722`) do not invoke
the separate untracked-file inventory gate. A checkout containing an untracked
`build.rs` (or any Cargo-consumed input) can produce a different binary under the same
source receipt; the binary hash is recorded, so the artifact is still distinguished.

**Fixed at `68e9af1`…`94b9a28`**: the E2E selectors now refuse untracked build inputs before
the receipt is taken. Guard proof: an untracked root `build.rs` produced
`E2E-shutdown-BLOCKED: untracked path(s) outside the explicit allowlist …: build.rs`; removing
the plant restored `E2E-SHUTDOWN-OK` / `CORRESPONDENCE-OK`.

Review found two fail-opens the first fix introduced, both corrected: unpinned ignore sources
(`--exclude-standard` honoured a local `.git/info/exclude`, giving a 0-path universe and a
false pass — now `--exclude-per-directory=.gitignore` with one standing allowlist entry), and
an incomplete observation (`git ls-files --others` exit 0 with a "could not open directory"
warning certified a partial universe — now diagnosed and refused; a blanked diff via
`GIT_EXTERNAL_DIFF` is likewise refused). Accepted residuals are recorded in
`alumina-gzqn4.22`. Registry: `csf_2ff93526…`, `csf_d31dd37c…`.

### D8 — Shutdown E2E no-admission false green · Confirmed · Fixed (M5)

Verification at HEAD: `scripts/e2e_shutdown.py:226-239` `probe_refused_sampled` classifies
each sample; on `("reachable", …)` it calls `sample_no_bind()`, which **probes a second
time**. If that second probe is `refused`, `sample_no_bind` returns `True` and the loop
continues — the earlier reachable observation (the actual no-admission violation) is
forgotten, and the case can pass.

This is a false-green in the witness, not evidence that the proxy admits post-shutdown
clients.

**Fixed at `813cd43` + `e64876e`**: exactly one probe is classified per sample, and the first
reachable observation is terminal. Guard proof: the `reachable→refused` shape returned
`WITNESS-RETURN: True` with `CALLS: 3` before the fix (a false green); after it, `CALLS: 1`
and `SHUTDOWN-D8-WINDOW: FAIL listener bound at a sampled probe point`.

One judgement worth recording: a sample fires microseconds after `os.kill`, while the owner
observes `SIGTERM` on its next poll turn, so a kernel-backlog connect there is
*pre-observation*, not an admission. `SIGNAL_SETTLE = 0.25 s` makes no connect and judges
nothing during that window; the remainder of the interval to the deadline is sampled with
terminal-per-observation judgement — strictly stronger than the old retry loop. The trade is
a 0.25 s blind window at the start, recorded rather than hidden. Registry: `csf_dc9dbfaf…`.

### D9 — Expired deadline consumed/replaced at a transition · Confirmed-Conditional · Fixed (M4)

Verification at HEAD: expiry is swept at pre-dispatch and periodic batch boundaries, but
the protected transitions do not re-check:
- `src/runtime/reactor.rs:2937-2943` and `3037-3043` call `arm_idle(Instant::now())`
  after a successful relay write, replacing an already-expired idle deadline;
- `2985-3006` clears `setup_deadline` and arms idle on graduation;
- connect acceptance consumes an expired connect deadline.

Bypass requires narrow timing around an otherwise valid setup or relay write; destination
and TLS identity checks still apply. Note: the scan also carried this as deferred candidate
`relay-idle-deadline-001` — same code region, one fix.

**Fixed at `c316ecf`**: expiry is re-checked at dial-accept, hello graduation and both
relay-write transitions. Red evidence: `expired_connect_deadline_refuses_at_connected_writable`
(advanced → refused), `expired_setup_snapshot_closes_at_hello_graduation` (Relay + fresh idle
→ close-only), `expired_idle_deadline_closes_on_relay_write_instead_of_rearming` (survived
both directions → closed). Registry: `csf_82d66ee4…`.

### D10 — Listener accept backoff · Confirmed · Fixed (M4)

Verification at HEAD: `src/runtime/reactor.rs:1898-1901` records `listener_pause_until =
now + ACCEPT_BACKOFF` on a non-`WouldBlock` accept error, but listener dispatch (`1876-1901`)
has **no pause guard**, and `poll_timeout` (`3272-3310`) never folds the pause deadline
into its earliest-deadline computation. Rearm happens only at the start of a later turn,
so neither the 100 ms cadence nor a guaranteed wake is enforced; a quiet owner can leave
queued clients stalled. This is the only finding the scanner marked `confirmed`.

**Fixed at `e110da9`** (`f86213d` pause + fold, `22e63d7` rearm regression, `e110da9`
error classification): a `ListenerArm` state machine withdraws the listener while paused,
re-registers (never `reregister`) on rearm, folds the pause into `poll_timeout`, and pauses
only for resource accept failures — `Interrupted`/`ConnectionAborted`/`ConnectionReset` are
drained instead, so the backoff cannot be turned into a global throttle. The rearm path was
a real fatal defect caught in-mission: `reregister` on a withdrawn listener returned
`ServeError{NotFound}`. Red evidence: `paused_listener_dispatch_accepts_nothing`,
`paused_listener_folds_into_poll_timeout`,
`elapsed_listener_pause_resumes_and_serves_the_queued_client`,
`listener_rearm_after_pause_registers_the_deregistered_listener`. Registry: `csf_7a4298f1…`.

### D11 — 32-bit slot token truncation · Confirmed-Conditional · Fixed (M4)

Verification at HEAD: `src/runtime/reactor.rs:3399-3406` `shifted_generation` casts the
`u64` generation to `usize` before shifting; `1470-1477` compares the decoded `event_gen`
to `slot_gen`. On a 32-bit target the packed generation field is narrower than the stored
counter, so after enough reuses of one slot a legitimate readiness token can never match
and the slot stops being serviced. Documented appliance is x86_64, so this is conditional
on an unsupported target.

**Fixed at `ed7f97c`**: one derived width (`GEN_BITS = usize::BITS - GEN_SHIFT`), the stored
counter masked at its single increment site, and mask-before-pack/mask-on-decode so
`decode(pack(g)) == g` at every pointer width. Rejected: compile-fail 32-bit (turns a
liveness defect into a build break with no red/green on the supported host) and fail-closed
exhaustion (the defect itself). Red evidence:
`g1_e1_field_ceiling_generation_wraps_and_dispatches_own_token` (own token dropped →
serviced), `generation_field_round_trips_at_the_simulated_32_bit_shape` (21-bit round-trip at
wrap). Generation isolation survives: a stale token lives at most one poll batch, while a
wrap needs `2^field_bits` accepts. Registry: `csf_7490db28…`.

### D12 — Pending setup pool has no per-peer fairness · Confirmed-Conditional · Fixed (M4)

Verification at HEAD: `src/runtime/tunnel.rs:439-452` `admit` checks only global
`occupied_count`/`pending_count`; a short incomplete CONNECT head holds a setup slot until
the 10 s setup deadline (`src/inspection/connect.rs:229-251`, `3327` sweep). One reachable
peer can therefore occupy all 128 pending setups and cause later clients to receive 503.
Prerequisites: shared reachable ingress and a replenishing offender; the idiomatic
deployment has one protected client behind an ingress firewall.

**Fixed at `1d7e1e0`** (`00beb19` peer attribution): `MAX_PENDING_PER_PEER = 32` of 128,
enforced by a bounded O(512) allocation-free scan using the canonical peer already attributed
to each pending setup; the global 128/512 bounds and the no-eviction rule are untouched.
Cost: +8 KiB boot-fixed state (`28 → 40 B` per slot), no post-boot allocation (alloc-witness
green). Rejected: shorter incomplete-head deadline (a replenishing offender still starves),
reserved headroom (cannot be keyed before the head is read), per-peer table with eviction
(more state and attack surface for no added guarantee). Red evidence:
`per_peer_pending_cap_denies_one_peer_and_admits_a_distinct_peer` (33rd peer-A admit `Ok` →
refused, peer B admitted), `per_peer_cap_frees_only_its_own_peer_seat`,
`worker_admits_up_to_128_pending_setups_and_rejects_the_129th`,
`per_peer_pending_capacity_refuses_with_503`. Registry: `csf_0eb83a4a…`.

### D13 — Monitor report-drop count clears before report · Confirmed · Fixed (M3)

Verification at HEAD: `src/log/mod.rs:986-1017` encodes and commits the **reserved**
summary first, then enqueues detail batches, mutating `Monitor` via `note_report_drop()`
*after* the summary bytes exist; the caller then marks the monitor clean, so the new dirty
state is treated as already reported and the loss count never reaches a summary.
Spec `docs/alumina-proxy.md:343` makes the summary authoritative and requires
`report_drops` to count each dropped batch.

**Fixed at `f24d401`**: report-time losses are projected before the summary bytes are
encoded, so the causing summary reports them (`report_drops=1` where it previously showed 0
while the ring dropped a batch). Rejected: carrying the count to the next summary (defers
the fact and needs a dirty-carry flag). Registry: `csf_f853ca26…`.

### D14 — Shutdown verdict displaced by reserved summary · Confirmed · Fixed (M3)

Verification at HEAD: `src/runtime/owner.rs:30-40` enqueues `shutdown_final` as a normal
record, then forces `report_monitor_if_due(now, true)`; the forced summary is reserved, and
`src/log/queue.rs:206-227` `displace_reserved` evicts the **newest normal** record — the
verdict. `src/log/tests.rs:1890-1927` already asserts this displacement.

Spec: the shutdown verdict is the terminal stdout status
(`docs/alumina-proxy.md` §Lifecycle; priority classes at `1136-1138`).

**Fixed at `ea48493`**: the verdict takes the existing reserved priority class, so it
survives the forced summary; the only victim left is the spec-sanctioned all-reserved case,
still counted as loss. Rejected: emit the summary first (detail batches could still push the
verdict out). Registry: `csf_4c8a71c0…`.

### D15 — DNS incident inherits prior family snapshot · Confirmed · Fixed (M3)

Verification at HEAD: `src/dns/incident_report.rs:321-342` `note_incident_open` overwrites a
family snapshot only when the incoming `Option` is `Some`; `467-481` `close_window` clears
`window_open` but leaves `nr.incident[..]` intact (only hourly rotation clears it). After
full recovery, a later one-family incident therefore reports the other family's earlier
failure. Telemetry-only; no effect on cache admission or routing.

**Fixed at `e591abd`**: a full-recovery close clears per-family snapshots, so a later
one-family incident reports only its own family; the within-window stickiness property is
guarded by its own test. Registry: `csf_3480bec0…`.

### D16 — Predictable test/bench temp paths · Confirmed-Conditional · Fixed (M6)

Verification at HEAD:
- `src/log/tests.rs:21-35` — `%TMPDIR%/alumina-log-<pid>-<counter>.log`, `create(true).truncate(true)`;
- `src/runtime/storage/startup_integration.rs:585-600` — same shape for the startup sink;
- `tests/support/temp_dir.rs:8-24` — `create_dir_all` on a predictable `alumina-boot-…`
  dir, then `fs::write` to `config.toml` through it (accepts a pre-existing symlink);
- benchmark/E2E host scripts use fixed names under `/tmp` (`scripts/bench_workload.py`,
  `scripts/e2e_shutdown.py:809-810`).

All conditional on a shared writable temp namespace plus permissive symlink policy plus a
runner-writable target. **No production serving path uses these helpers.**

Fix: one shared test-only helper — atomically created private directory with a random name,
`create_new` semantics, and rejection of pre-existing paths/symlinks. No new runtime
dependency; no production code touched. Registry: `csf_7a1d1b85…`, `csf_71878c86…`,
`csf_ebf1e194…`, `csf_a72f99bc…`, `csf_f653b18d…`.

**Fixed at `e6a25c9`…`9be04d6`**: one test-only owner, `tests/support/temp_dir.rs`, holds
the whole mechanism — an unpredictable name (`alumina-<tag>-<pid>-<32 hex>`) drawn from
`/dev/urandom`, created with `fs::create_dir` (never `create_dir_all`) so a pre-existing
path or symlink is refused by `EEXIST` whatever it points at, with no `lstat` and no TOCTOU
window, then set to `0o700`; writes are `O_EXCL` `create_new`, and the log and startup sinks
take a read+write seekable descriptor on an unlinked inode from a private directory created
and removed around it — pathless, so there is nothing to preplant. The two clobber opens
(`src/log/tests.rs`, `src/runtime/storage/startup_integration.rs`) and the boot fixture
(`tests/boot.rs`, `src/boot/tests.rs`) now go through it. `scripts/e2e_shutdown.py` writes
case logs only inside a private per-run `mkdtemp` workspace (`O_EXCL`, 0700, `atexit`
cleanup, no `/tmp` glob), and `scripts/bench_workload.py`'s selftest workspace and its B8/F4
embedded-shell probes live inside one (`--selftest-tmp` override kept).

Guard proof is per site — old follows the plant, new refuses, clean — from a scratch probe
whose bodies are extracted byte-for-byte from `git show 699879c:<file>`: the old helper wrote
`victim/config.toml` through a planted directory symlink and both sink opens truncated a
victim to 0 bytes; the new owner refused every plant with the target intact, the sink
descriptors round-tripped seekably with no path left, and both scripts left regular-file and
symlink plants untouched with no `/tmp` residue. 8 permanent guard tests in `tests/boot.rs`;
`--lib` 1145 before and after, `--test boot` 28→36. `sh scripts/verify.sh docs` green.
Boundary `host-mid union` PASS on the final candidate, with the `ALT-COPY-OK` release binary
sha256 `685898ee…` identical to M3/M5 — the strongest proof that no production path changed.
Standard-tier review APPROVE (`alumina-gzqn4.24.2`) plus script review APPROVE
(`.ooda/review-1794578195.md`).

Residuals are recorded rather than dropped (`alumina-gzqn4.25`): `scripts/e2e_relay.sh` keeps
fixed `/tmp` names but runs inside a fresh `--network none` container whose namespace is
destroyed with it, and the `owner`/`transport` test sinks are already exclusive (a plant fails
that run loudly) though still predictable. The class is not left silently half-covered.

### D17 — Reference ingress admits the whole VPC subnet · Confirmed · Correct-documentation (M7)

Verification at HEAD: `docs/deployment.md:23` "INGRESS: ALLOW tcp:5353 from VPC subnet
CIDR only", enacted at `:100` as
`iptables -I INPUT -p tcp -s <vpc-subnet-cidr> --dport 5353 -j ACCEPT`. The proxy performs
no client authentication at accept (`src/runtime/reactor.rs:1889-1920`); admission is
delegated entirely to the network boundary. The documented boundary is therefore wider
than the stated single-workload intent, and any peer in that subnet inherits the
allowlist and capacity limits.

Disposition: documentation correction — narrow the rule to the workload's identity
(subnet/instance tag) or state the subnet-trust assumption explicitly. No runtime change.
Registry: `csf_b3172a74…`.

### D18 — Combined upstream error+readable skips early-activity telemetry · Confirmed-Conditional · Fixed (M3)

Verification at HEAD: `src/runtime/reactor.rs:1575` and `1616` short-circuit on
`ready.error` before the pre-gate upstream read path, its tripwire projection (`2749`) and
its log sink (`2766`). When a single readiness event carries both error and readability,
the early-activity fact is never reported. Forwarding remains blocked and the slot closes;
impact is missed detection/notification for a constrained event combination.

**Fixed at `5b31ef2`**: the pre-gate read path runs before the error short-circuit, gated to
pre-gate upstream only. Zero bytes forwarded, gate cannot open, slot closes; the fact and
its tripwire projection are recorded. Registry: `csf_f165dde7…`.

---

## 5. Governance decisions

Decision of record (user, 2026-11-12): **G1 and G2 are opened as governed amendments**,
not accepted as risk. An amendment is a deliberate change to the byte-frozen
specification and therefore follows the AGENTS.md path: explicit user authorisation of the
exact text, one increment that updates spec + digest pin + code + tests together,
independent source and governance review before adoption, and no relaxation of security or
resource limits. **Nothing in this section is adopted text.** Each row below is a design
question that must be answered before a draft can exist.

| ID | Question | Chosen (user, 2026-11-12) | Consequence |
|---|---|---|---|
| G1 | D3: what is the JA4 baseline/change contract? | **(b)** keep the K=16 set; the first distinct fingerprint seeds, **every** subsequent new fingerprint selects the configured action; overflow keeps F-08's detail-loss latch. **Adopted** 2026-11-13 (SP-015, `48a90f5`): digest `d43d938f…`, both gates APPROVE | Table unchanged (18,432 B), no per-address state, zero new allocation. `BaselineOutcome` must distinguish an empty row (seed) from a non-empty row gaining a new value (change). The T4 prose at `:700`/`:952` must be rewritten to the per-ordinal set — the amendment also removes the stale "per-ordinal+address" phrasing (G3 instance). Monitor grammar unchanged; `ja4_seed` becomes ≤ 32 per process |
| G2 | D5: what is the resolver assurance contract? | **(c)** require an explicit `resolver_trusted` per entry; the omission default disappears. **Adopted** 2026-11-13 (`b48e320`, `cbaecfa`): digest `b9941f00…`, both reviews APPROVE, spec + pin + parser + tests + 102 fixture lines migrated together | Bare-IP stays usable; silent defaulting ends. All four harness configs (`e2e_relay.sh:134`, `e2e_shutdown.sh:93`, `bench/run.sh:159`, `verify.sh:526`), the QA example and every cited non-canonical doc must state the class explicitly; missing key becomes `InvalidDnsAssurance` (exit 78) rather than a default |
| G3 | Spec/doc measurement consistency | **Adopted in part** 2026-11-13 (`5012527`, digest `416062eb…`): geometry table, tightest-record sentence, duplicate prose, stale JA4 storage row, citation | Verify first, then reconcile as a documentation correction (or a spec amendment if the spec is the wrong side). **Verified instances to include:** the JA4 keying prose (G1) and the stale 8,192 B geometry in earlier amendment layers (`:1131`, `:1168`, `:1249`, `:1257`) against the binding 2048 B (spec `:878-903`, `:1309-1319`) |
| G4 | Deployment-doc inconsistencies: spec names a Cloud Run worker pool while `docs/deployment.md` prescribes a dedicated VM; host-network appliance is said to bind `0.0.0.0:5353` while the shipped example binds `127.0.0.1:5353` | open | Verify against spec intent, then correct the non-canonical document |

G1 and G2 must not be bundled with remediation missions: an amendment that changes
enforcement semantics and a bug fix that conforms to current semantics are different
increments with different review obligations. Sequence them after M1/M2 land so the
amendment is reviewed against a clean gate.

G3/G4 are **intake observations**, not scanner findings. They are not counted among the
32 and must be verified before any disposition.

---

## 6. Duplicate map

| Row | `findingId`s |
|---|---|
| D1 | `csf_5cf9845c…` `csf_2c5f1141…` `csf_4c880ecd…` `csf_a3e98acd…` `csf_989ba59d…` `csf_d43ae0b1…` `csf_1352c94f…` `csf_b61ca9b8…` `csf_8cc1dbf7…` |
| D2 | `csf_0ac80ddb…` |
| D3 | `csf_bf60a65e…` |
| D4 | `csf_ecd441bf…` |
| D5 | `csf_301d7454…` |
| D6 | `csf_a4bf4a95…` `csf_f2b0f388…` |
| D7 | `csf_2ff93526…` `csf_d31dd37c…` |
| D8 | `csf_dc9dbfaf…` |
| D9 | `csf_82d66ee4…` |
| D10 | `csf_7a4298f1…` |
| D11 | `csf_7490db28…` |
| D12 | `csf_0eb83a4a…` |
| D13 | `csf_f853ca26…` |
| D14 | `csf_4c8a71c0…` |
| D15 | `csf_3480bec0…` |
| D16 | `csf_7a1d1b85…` `csf_71878c86…` `csf_ebf1e194…` `csf_a72f99bc…` `csf_f653b18d…` |
| D17 | `csf_b3172a74…` |
| D18 | `csf_f165dde7…` |

The HTML report preserves all 32 entries in report order without merging; locate a
duplicate by title + `findingId`, not by report index.

### Where triage changed the scanner's picture

- 10 JA4 "block bypass" findings (6 identical titles) are **one root cause plus one
  ordering defect** — D1/D2 — not ten issues. Fixing one code seam closes all ten.
- D3 is a genuine security observation about an **explicitly chosen design**, not a code
  defect. It belongs in governance, not a fix queue.
- D6's "commented declaration" sub-claim is **refuted**; the symlink and
  second-declaration variants hold.
- D9 and D10 were each raised twice across scans (and D9 once as a deferred candidate);
  they are single defects.

---

## 7. Residual coverage backlog

The scan was canceled, so this register is **not** a complete audit. Deferred material
must be tracked separately before any clean claim:

- `src/runtime/reactor/tests.rs` (~9.8k lines) and `src/runtime/owner/tests.rs` — sampled,
  not reviewed line by line (repeatedly deferred by the scanner).
- 29–56 test, fixture, benchmark and documentation files per deferred record, including
  `scripts/verify.sh`, `scripts/bench_workload.py`, `scripts/e2e_relay.py`,
  `docs/alumina-proxy.md`.
- Open scanner candidates not promoted to findings: test-only DNS loopback responder
  availability (`dot_tests`, `transport/tests`); nonempty-TCP-write/`Ok(0)` progress
  question (`src/runtime/reactor.rs:2917-2973,3022-3078`); whether `CASE_FILTER` can cross
  a CI trust boundary.
- Dependency advisories were **not** checked (offline scan).

Proposed handling: one follow-up task after M1–M2 land, scoped to the highest-value
deferred paths (large reactor/owner test suites, verification scripts), not a re-run of the
whole scan.

---

## 8. Process — Daybreak triage & remediation loop

The process is a closed loop around the register. It is deliberately the same shape as the
`alumina-smiy` security-hardening mission so the fleet has one pattern.

0. **Intake freeze.** Record scan provenance and artifact digests (this §1). Scan artifacts
   stay **untracked**, matching the `alumina-smiy` precedent (`SECURITY-REVIEW*.md`
   untracked); the register is the tracked artefact. Never edit scanner output.
1. **Deduplicate to root cause.** One register row per code seam and fix. Duplicates are
   mapped (§6), never re-triaged and never independently fixed. A row is created only when
   the root cause is identifiable; otherwise it stays in the backlog.
2. **Evidence gate (per row).** A row is admissible only with: (a) a re-verified source
   citation at the current `HEAD`, (b) a spec clause or an explicit "no governing clause",
   (c) a verdict from §2, (d) a **named red test**. A row without a red test cannot be
   dispatched for `Fix` — only for `Accept-risk`, `Correct-documentation`, or
   `Governance-decision`.
3. **Arbitrate, don't default.** Code-versus-spec discrepancies are resolved on merit in
   either direction (AGENTS.md §Reconciling a deviation). A `Spec-Intended` verdict
   produces a recorded acceptance with rationale, never a code change. A spec change
   requires explicit user authorisation and the governed amendment path (spec + digest pin
   + code + tests in one increment, independent source and governance review).
4. **Package and dispatch.** `@moltke` receives the row(s) + commander intent + bounds +
   named verification and authors the mission contract. Build mode does not re-plan.
   One active drafter (SCAR): missions run sequentially, not in parallel.
5. **Execute red→green.** `@hopper` writes the failing test first, then the fix, then the
   refactor. Fixed profile holds: no post-boot first-party allocation, no runtime-surface
   expansion, two reused 128 KiB buffers, single boot/serving owner.
6. **Review by surface.** Adversarial tier for enforcement semantics (D1/D2),
   verification gates and verifiers (D6/D7/D8), admission and deadline surfaces
   (D9–D12). Standard tier elsewhere. Rust diffs → `@linus`; scripts → `code-review`.
   Mechanical verification is `@hopper`'s, never the reviewer's.
7. **Guard proofs.** Any change to a gate/tripwire requires
   `plant → fail → revert → clean` evidence, attached to the bead.
8. **Close with evidence.** Per row: commit SHA + the red test that now passes, or the
   recorded acceptance reason. Update the ledger bead and this register's status column.
   `@gardener` closes the epic at 18/18.

**Verification tiers.** INNER per edit on the touched crate/file; MID once per
sub-mission (changed crate + reverse-dependent closure); BOUNDARY once per stable
candidate. On macOS use `sh scripts/verify.sh host-mid <scope>`; `mid` selectors are
Linux-only and fail closed off-Linux. Doc-only rows use `sh scripts/verify.sh docs`.

**Stop rules.** Halt and escalate when a row needs: unbounded memory, a new runtime
surface, a new dependency, a spec amendment, or two failed review rounds
(circuit breaker → `@feynman` reframe, then a structured user choice).

**What this process refuses to do.** Treat the canceled scan as a clean result; close a row
on scanner confidence alone; fix a duplicate twice; change a gate without a guard proof;
soften a conditional finding by dropping its precondition.

---

## 9. Mission sequence

Sequential (single drafter). M1 and M2 first: they are spec-binding enforcement and
release-assurance defects, and M2 protects the gates that later missions rely on.

| Mission | Rows | Bounds | Verification | Tier |
|---|---|---|---|---|
| M1 | D1, D2 | `src/runtime/reactor.rs` (+tests) only; no config surface | 3 red tests (Connection/Domain/All with pre-flush bytes); MID runtime; zero-alloc preserved | adversarial | ✓ `0205f69` |
| M2 | D6 | `scripts/verify.sh` (+`verify_test.py`) only | guard proofs for symlink + second-declaration shapes; `verify.sh docs` | adversarial | ✓ `56eb45d` |
| M3 | D4, D13, D14, D15, D18 | monitor / log / dns-incident / reactor-readiness | exact-grammar tests; every record kind still ≤ **2048 B** slot (`monitor_domain` re-measured to 1,870 B / 178 B); per-ordinal peer size budget | adversarial | ✓ `9e1f95a` |
| M4 | D9, D10, D11, D12 | reactor / tunnel; deadlines, admission | clock-stepped expiry tests; injected accept error; 32-bit assertion; pool quota test | adversarial | ✓ `e110da9` |
| M5 | D7, D8 | `scripts/verify.sh` E2E receipt; `scripts/e2e_shutdown.py` | untracked-input rejection; held-open-listener case must FAIL | adversarial | ✓ `94b9a28` |
| M6 | D16 | test-only helpers + bench/E2E temp paths | symlink plant test per site; no production path; no new runtime dep | standard | ✓ `9be04d6` |
| M7 | D17 (+G4) | `docs/deployment.md` (non-canonical docs only) | `verify.sh docs`; no spec digest change | standard |
| G1–G2 | D3, D5 | spec + digest pin + config/table + tests **in one increment**; independent source and governance review; explicit user authorisation of exact text | amendment dossier: options analysis, fixed-profile and size re-measurement, migration note for existing configs | governance |
| G3–G4 | — | non-canonical docs first; spec only if the spec is the wrong side | `verify.sh docs`; digest re-pin only if spec text changes | standard |

**Sequencing coupling (found during M2 close-out).** M3's D4 fixes per-domain peer
attribution inside the same JA4 baseline/monitor structure that G1 may redefine. If G1
chooses per-(ordinal, address) keying, the peer field becomes per-(ordinal, address) and
D4's storage shape changes with it. Therefore **G1 resolves before M3 starts**; otherwise
D4 is likely rework. G2 is independent of every remaining row and can proceed in parallel.

---

## 10. Ledger

| Row | Disposition | Bead | Status |
|---|---|---|---|
| D1, D2 | Fixed | `alumina-gzqn4.2` | closed — `0205f69`, boundary PASS, review APPROVE |
| D6 | Fixed | `alumina-gzqn4.5` | closed — `56eb45d`, guard proofs + boundary PASS, review r2 APPROVE |
| D3 | Fixed (G1, SP-015) | `alumina-gzqn4.3` | closed — `48a90f5`, digest `d43d938f…`, source + governance APPROVE; 2 text residuals open |
| D5 | Fixed (G2 + G2a) | `alumina-gzqn4.4`, `alumina-gzqn4.15` | closed — `cbaecfa`, digest `b9941f00…`, source + governance APPROVE |
| D9–D12 | Fixed | `alumina-gzqn4.6` | closed — `e110da9`, boundary PASS, review r2 APPROVE |
| D4, D13–D15, D18 | Fixed | `alumina-gzqn4.17` | closed — `9e1f95a`, boundary PASS, review r2 APPROVE |
| D7, D8 | Fixed | `alumina-gzqn4.20` | closed — `94b9a28`, guard proofs, real e2e shutdown 10/10, review r3 APPROVE |
| D16 | Fixed | `alumina-gzqn4.24` | closed — `9be04d6`, boundary PASS on the final candidate, review APPROVE (`alumina-gzqn4.24.2`, `.ooda/review-1794578195.md`), residuals `alumina-gzqn4.25` |
| D17 | per §3 | `alumina-gzqn4.1` | registered (M7) |
| G3 | Adopted in part | `alumina-gzqn4.21` | closed — `5012527`, five hunks, governance APPROVE; residuals R1/R3/R4 open |

Epic: `alumina-gzqn4`. Ledger updates go to `alumina-gzqn4.1`; the register above is the
durable narrative.

---

## 11. Correction log

Errors found in this register after publication, corrected forward (never silently edited):

| Date | Row | Correction | Source |
|---|---|---|---|
| 2026-11-13 | D4 | `monitor_domain` re-measured after D4: **1,870 B / 178 B headroom**, and it is now the tightest record ahead of `resolver_probe` (191 B). My pre-fix estimate (~1,854 B) was close but fabricated; the first pin (1,800 B) was wrong because the batch under-filled. Spec table still states 1,370 B/678 B — routed to G3 (`alumina-gzqn4.19`). | `alumina-gzqn4.17`, `a4fe926`; `src/log/tests.rs` |
| 2026-11-12 | D4, §5 G1, §9 M3 | The log slot is **2048 B** (`SLOT_BYTES`, `MONITOR_RECORD_MAX`), not 8,192 B. The 8,170/8,192 figure came from a superseded spec layer (`docs/alumina-proxy.md:1249`) and was carried into v1 of this register. Worst cases measured at that time: `monitor_summary` 763 B, `monitor_domain` 1,370 B, `monitor_capture` 1,237 B, `resolver_probe` 1,857 B (superseded by the 2026-11-13 row above). | `alumina-gzqn4.7` (evidence); `src/log/mod.rs:54-59`; spec `:878-903`, `:1309-1319` |

The same evidence bead recorded that the spec still contains both JA4 keying phrasings
with only partial declared supersession (`:700`/`:952` vs `:1070-1073`/`:1233`/`:1164`), and
that the stale 8,192 B geometry survives in earlier amendment layers (`:1131`, `:1168`,
`:1249`, `:1257`). Both belong to **G3** (spec/documentation consistency) as verified
instances, not to G1/G2.
