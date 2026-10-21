# Group 8 — Tooling / CI / Scripts

**Subsystem:** `scripts/` (seam_echo.sh, qryg_runner.sh, verify.sh, e2e_relay.sh/py, e2e_shutdown.sh/py), docs/verification.md
**TRUE POSITIVE findings:** 5
**Severity mix:** Medium ×1, Info ×4

---

## W5-H5a-F1 — Medium — retained-binary schema mismatch (SEAM-BLOCKED)

**Scorecard row:**
```
| W5-H5a-F1 | Medium | scripts seam_echo.sh:125-135,147-170 / qryg_runner.sh:166-188 | TRUE POSITIVE | TP,I,I,TP,TP → 3T-2I | medium | /work/resolv.conf stage dropped at HEAD (3bb5865 alumina-hrdn4 removed the printf nameserver line from both stage heredocs, replaced with resolver=["127.0.0.1"] in config.toml; seam_echo.sh:154, qryg_runner.sh:173); as-is/to-be pin frozen pre-migration binaries (seam_echo.sh:86-89, shas 170fae6c/8a9f1f5b measured 2026-10-13 @54a34ce per docs/benchmarks/results/*.json) whose contract reads cwd resolv.conf + rejects unknown resolver key (3bb5865^ main.rs:18-19, config.rs:638-639) → cannot boot at HEAD → no valid measurement; binaries absent (gitignored .ooda/, no alumina-vdpi dirs) → fail-closed SEAM-BLOCKED at :126-127; mismatch fully provable from git history + pre-migration source independent of binary absence; qryg_runner.sh location weaker (HAProxy/Envoy pinned images don't read resolv.conf); 2 dissenting passes (IND: binaries absent → breakage latent/unobservable) |
```

**Working description (alox-f, H5a):**
F-01 [Medium] `seam_echo.sh`/`qryg_runner.sh` retained-binary schema mismatch — the `/work/resolv.conf` stage was dropped at HEAD (`3bb5865`), but the pinned frozen binaries' contract reads cwd `resolv.conf` and rejects the unknown `resolver` key → cannot boot at HEAD → no valid measurement; fail-closed SEAM-BLOCKED. Mismatch fully provable from git history + pre-migration source independent of binary absence.

---

## W5-H5a-F3 — Info — no-unsafe not script-enforced

**Scorecard row:**
```
| W5-H5a-F3 | Info | scripts/verify.sh (no unsafe gate); src/alloc.rs, src/log.rs | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | verify.sh gates (whitespace/static/fmt/clippy/docslink/identity/audit-deny/e2e/fixtures) contain no unsafe grep; no #![forbid/deny(unsafe_code)] anywhere; Cargo.toml:18 undocumented_unsafe_blocks="warn" only → documented unsafe passes -D warnings; unsafe surface confined to src/alloc.rs (GlobalAlloc :130-170) + src/log.rs (fcntl/writev :1429,:1438,:1461) + 2 test files; count/locations unchanged in window (no unsafe-line diffs in 3bb5865~1..HEAD; 1c8b4e2 write→writev same-block swap, count unchanged) |
```

**Working description (alox-f, H5a):**
F-03 [Info] no-unsafe not script-enforced — `verify.sh` gates contain no `unsafe` grep; no `#![forbid/deny(unsafe_code)]` anywhere; `undocumented_unsafe_blocks="warn"` only; unsafe surface confined to `src/alloc.rs` + `src/log.rs` + 2 test files; count/locations unchanged in window.

---

## W5-H5a-F4 — Info — doc-budget/comment-free gate not in script gate path

**Scorecard row:**
```
| W5-H5a-F4 | Info | scripts/verify.sh; docs/verification.md:60 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | verify.sh runs no doc-budget/comment-free gate; scripts/docs_check/check.mjs is link/slug validation only; repo-wide grep for comment-free/doc-budget/word-budget = 0 matches (incl. git -S history); no CI/Makefile/justfile; docs/verification.md:60 explicitly excludes rustdoc/doctests; no owner attributed; gate exists only as fleet-level skill outside repo |
```

**Working description (alox-f, H5a):**
F-04 [Info] doc-budget/comment-free gate not in script gate path — `verify.sh` runs no doc-budget/comment-free gate; `check.mjs` is link/slug validation only; repo-wide grep for comment-free/doc-budget/word-budget = 0 matches; no CI/Makefile/justfile; no owner attributed.

---

## W5-H5a-F5 — Info — world-writable WORKDIR (verdict tampering only)

**Scorecard row:**
```
| W5-H5a-F5 | Info | scripts/qryg_runner.sh:147-148,224-267 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | chmod 777 unconditional on WORKDIR="$OUTDIR/$STAMP.work" (:81,:147-148); verdict-driving markers live in 777 dir: client-done (:265→VERDICT :340-350), harness-reapfail (:333), candidate.pid (:266), netns-ready (:225), logs (:220,:245); WORKDIR mounted into both containers (:204,:243); no escalation path (script runs as invoking user, nothing executed from 777 dir, harness :ro mounts + no-new-privileges + --network none; podman exec sh -c pid interpolation gated by numeric guard :275); published reports in OUTDIR (755, not 777) — verdict tampering only, matches framing; WORKDIR never cleaned up |
```

**Working description (alox-f, H5a):**
F-05 [Info] `qryg_runner.sh:147-148,224-267` world-writable WORKDIR (`chmod 777`) — verdict-driving markers live in the 777 dir; no escalation path (script runs as invoking user, nothing executed from 777 dir, `:ro` mounts + no-new-privileges + `--network none`); published reports in OUTDIR (755) — verdict tampering only, matches framing; WORKDIR never cleaned up.

---

## W5-H5a-F6 — Info — positive-control audit PASS (real binary, no stub)

**Scorecard row:**
```
| W5-H5a-F6 | Info | scripts/e2e_relay.sh/py, e2e_shutdown.sh/py | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | both harnesses exec real release binary target/${E2E_TARGET}/release/alumina (e2e_relay.sh:68,:199-200; e2e_shutdown.py:88,:727-735), Cargo.toml:154-156 single [[bin]] alumina, no stub; built from exact candidate via e2e_build_receipt (verify.sh:1049-1061) + e2e_verify_stable re-hash (:960-985); readelf static-ELF gate on exact executed binary (e2e_relay.sh:141-175); byte-exact assertions (e2e_relay.py:790-806 got!=expected, recv_until_complete_eof :706-739, 4 MiB echo :1088-1094; e2e_shutdown.py:1114 stream!=full); real network I/O in --network none container; fixtures substitute upstreams only, not proxy; minor caveat POS-RELAY-TLS13 reversed-bytes content match (:667) |
```

**Working description (alox-f, H5a):**
F-06 [Info] positive-control audit PASS — `e2e_relay`/`e2e_shutdown` exec the real release binary (`target/${E2E_TARGET}/release/alumina`, single `[[bin]]`, no stub), built from the exact candidate via `e2e_build_receipt` + `e2e_verify_stable` re-hash; readelf static-ELF gate on the exact executed binary; byte-exact assertions; real network I/O in `--network none` container; fixtures substitute upstreams only, not the proxy.
