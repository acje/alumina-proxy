# Verification — instructions and command set

Verification here is **scoped and exact-input**: proofs are recorded for
specific candidates, never blanket, and a completed check at one candidate is
not reused for another unless the inputs are identical. Repository status and
known limitations are the README; qualification gates stay open and are owned
by this file — the verification **instruction / command-set** authority
(relocated from the README "Verification" section; status owner
[docs/qa-package/README.md](qa-package/README.md)).

## Command set

Host-run selectors and gates (all `sh scripts/verify.sh …` selectors and host
Cargo commands):

```
cargo +1.99.0 atest -p alumina --locked --lib --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall --test stdout_closed   # gate-only surface (lib units + 6 gate-only binaries), witness-off — a manual reference; the same surface runs inside `mid union` (boundary dispatches union alone; `mid full` is a standalone selector subsumed by it)
cargo +1.99.0 atest -p alumina --locked --features alloc-witness --lib --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall --test stdout_closed   # gate-only surface, alloc-witness — a manual reference (runs inside `mid union`)
cargo +1.99.0 fmt --check
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh inner check                # INNER tier: cargo check only; host-runnable (compiles on macOS)
sh scripts/verify.sh mid foundations            # MID tier (Linux-only, fail closed off-Linux): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid boot                   # MID tier (Linux-only): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid clippy                 # MID tier (Linux-only): clippy -D warnings (production + alloc-witness harness)
sh scripts/verify.sh mid union                  # MID tier (Linux-only): release + static-ELF + closure metadata + clippy; runs the full test surface (lib + 8 integration targets) witness-off then witness-on
sh scripts/verify.sh mid full                   # MID tier (Linux-only): standalone gate-only selector (lib units + 6 gate-only binaries) witness-off then witness-on; surface subsumed by mid union
sh scripts/verify.sh docs                       # native offline docs gate: links + HTML + physical INTENDED + cfg-parentage + unsafe + spec digest
sh scripts/verify.sh fixtures boot              # host Podman coordinator; Darwin allowed
sh scripts/verify.sh e2e relay                  # host-runnable; auto-dispatches Linux build on Darwin
sh scripts/verify.sh e2e shutdown               # host-runnable via rootful harness
sh scripts/verify.sh boundary phase1-fast       # BOUNDARY fast tier: change-scope classification + cheap host gates (docs/unsafe/whitespace/audit) + identity; no Linux MID, no fixtures, no E2E
sh scripts/verify.sh boundary phase1-slow       # BOUNDARY slow tier: reads scope marker; docs-only => explicit SKIPPED-BY-DESIGN, no MID; full => mid union (alone; subsumes mid full) + fixtures + artifact identity
sh scripts/verify.sh boundary phase1            # BOUNDARY tier (composed): fast tier, then slow tier unless docs-only; never E2E; exit 1 BLOCKED by design
```

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them). Most gate selectors run a filtered scope: their
`verify.sh` `atest` invocations carry `--test foundations` or `--test boot`
(optionally with `--features alloc-witness`). The `mid full` selector is a
standalone gate-only selector: it runs lib unit tests plus the 6 gate-only
integration binaries (eligibility, mio_matrix, main_thread_stack,
monitor_stdout, stdout_stall, stdout_closed), witness-off then witness-on
(alloc-witness, incl. the eligibility witness and the alloc-witness-only
mio_matrix binary); atest-only (no clippy/fmt). `boundary phase1` does not
dispatch it: `mid union` subsumes the whole gate-only surface — one dispatch
runs lib plus all eight integration targets (foundations, boot, and those
same 6) witness-off then witness-on (the `mid foundations` / `mid boot` inner
loops additionally run the two during development).

### Three-tier guarantee contract

Verification is tiered; each tier backs a different claim:

- **INNER** — `sh scripts/verify.sh inner check`: cargo check only (no
  clippy/fmt/whitespace/release). Host-runnable (compiles on macOS). Fast
  per-edit feedback; backs no done-claim.
- **MID** — Linux-only selectors (fail closed off-Linux): `mid foundations`
  and `mid boot` are behavior-proof + fmt/whitespace fast loops (their former
  static-ELF/clippy/release/closure proofs moved to `mid union`); `mid
  clippy` runs clippy `-D warnings` for production and the alloc-witness
  test harness; `mid union` carries release + static-ELF + closure metadata
  - clippy; `mid full` is the standalone gate-only selector (lib units +
  the 6 gate-only binaries) witness-off then witness-on, its surface
  subsumed by `mid union`. MID backs per-sub-mission
  done-claims.
- **BOUNDARY** — split into a fast tier and a slow tier; both exit 1
  `BLOCKED` by design and neither ever executes E2E:
  - `sh scripts/verify.sh boundary phase1-fast`: identity BEFORE snapshot,
    change-scope classification (writes `target/phase1-scope`), then the
    cheap host gates — docs link gate, unsafe-surface gate, `git diff
    --check`, audit/deny — and an identity AFTER/compare. No Linux MID, no
    fixtures. Fails fast so a cheap-gate failure aborts before the ~90-min
    compile-dominated dispatch. The unsafe-surface gate confines the `unsafe`
    keyword to the production surface (`src/alloc.rs`, `src/log/`,
    `tests/*`) plus `#[cfg(test)]` unit-test modules under `src/`
    (`src/*/tests.rs`, `src/*/dot_tests.rs` — test-only, never compiled into
    the production binary); production confinement is unchanged.
  - `sh scripts/verify.sh boundary phase1-slow`: reads the scope marker
    (missing => full, fail-safe). On docs-only it emits an explicit
    `PHASE1-SLOW-SKIPPED-BY-DESIGN` and skips the Linux MID; on full it
    dispatches the Linux MID union once — `mid union` covers the whole
    gate-only test surface (lib + all eight integration targets, witness-off
    then witness-on), so `mid full` is no longer a separate dispatch (`set -e`
    aborts on the first red marker) — plus `fixtures boot` and the artifact
    identity check.
  - `sh scripts/verify.sh boundary phase1` (composed): fast tier, then the
    slow tier unless the scope is docs-only. Preserves the single-invocation
    path used by `docs/qa-package/validate.sh`.
  `FINAL-PHASE1-COMPLETION: BLOCKED` (exit 1) is the honest by-design
  diagnostic when a prerequisite is absent — never converted to a clean
  result. The split is the **scoped and exact-input** doctrine (above)
  applied to execution conditionality: a full-scope candidate still runs the
  full ceremony, and a docs-only candidate skips the MID explicitly, never
  silently. BOUNDARY backs repo-wide candidate done-claims.

### Offline docs gate — the `docs` selector (not just links)

`sh scripts/verify.sh docs` is the full offline docs gate, not a link-only
check. It runs, in sequence: the link/fragment gate over the **8-root
`DOCSLINK_ROOTS`** set (`docs/alumina-proxy.md`,
`docs/trust-telemetry-design.md`, `docs/trust-chain-design.md`,
`docs/deployment.md`, `docs/monitoring.md`, `docs/verification.md`,
`docs/qa-package/README.md`, `README.md` — trust-telemetry native coverage is
exercised here via its root entry); the HTML structure gate over the HTML doc
roots; the physical **INTENDED** inventory (every `src`/`tests` `.rs` listed);
**CFG-TEST-PARENTAGE** (admitted `src/*/tests.rs` and `src/*/dot_tests.rs`
declared `#[cfg(test)]` by their parent); the **UNSAFE-SURFACE** confinement
gate; and the **CANONICAL-DIGEST** pin (frozen spec sha equals the `AGENTS.md`
pin). A docs change reruns this whole selector — the link gate alone is not
the gate.

The full retained Markdown corpus is checked with the explicit, nonempty argv
command, run with `NODE_OPTIONS`/`NODE_PATH` cleared:

```
env -u NODE_OPTIONS -u NODE_PATH node scripts/docs_check/check.mjs AGENTS.md README.md docs/alumina-proxy.md docs/trust-telemetry-design.md docs/trust-chain-design.md docs/deployment.md docs/monitoring.md docs/verification.md docs/qa-package/README.md
```

Manual checker regression fixtures, hand-run (identity-tracked, **not** wired
into any dispatch arm):

```
node scripts/docs_check/test.mjs
node scripts/html_check_test.mjs
```

Selector host context / prerequisites (incl. `mid` Linux-only fail-closed and
`fixtures`/`e2e` host-runnable details, `boundary phase1` never executing E2E):
sole owner is [docs/qa-package/README.md](qa-package/README.md).

## Test suite navigation & ownership

Navigation/ownership instructions, not an architecture narrative (no
findings, verdicts, or issue records here).

- **One Linux `sh scripts/verify.sh mid union` is the whole verified surface:**
  it runs the lib unit suite plus all **eight** integration test targets
  (foundations, boot, eligibility, mio_matrix, main_thread_stack,
  monitor_stdout, stdout_stall, stdout_closed) witness-off then witness-on
  (`--features alloc-witness`); the same union also runs release/static-ELF/
  closure-metadata, clippy, and fmt/whitespace. The 2026-11-08 run on
  `b1ff6909f215b860badec8f519349d7dc85f688c` recorded 1114/1163 lib tests
  witness-off/on; the libtest integration targets recorded boot 28/28,
  eligibility 5/6, foundations 9/13, and mio_matrix 0/8. The four
  process-entry harnesses are separate, not included in those counts. These
  are observed run counts, not fixed future suite totals.
  `boundary phase1` dispatches union once — never `mid full` separately;
  `mid full` remains a standalone gate-only selector.
- **The root `--test boot` suite is the broad boot component/API integration
  target**: it exercises config load and strict-schema rejection (config
  errors → exit 78), bare-IP resolver validation, synthetic preflight
  privilege floors, and inventory/traffic-storage component APIs — not the
  assembled boot runner. The assembled boot path and resolver trust/pin
  preparation live in the boot unit suite `src/boot/tests.rs` (selected by
  `--lib` inside `mid union`), where `run_boot_with_facts` assembles the
  stages. Both suites share the `TempDir` fixture through the private shared
  helper (`tests/support/temp_dir.rs`).
- **Foundations** (`tests/foundations.rs`) is the API/support harness:
  fault and fuzz-style inputs plus the allocation-witness proving surface,
  not just the off/on witness count.
- **Four gate-only targets are `harness=false` process-entry binaries**, not
  libtest tests: `main_thread_stack`, `stdout_stall`, `monitor_stdout`,
  `stdout_closed` (each `[[test]] harness = false` with its own `main()`);
  the lib unit suite plus `foundations`, `boot`, `eligibility`, and
  `mio_matrix` are the libtest-harness targets.
- **Remaining roots are discovery-based and legitimate** (default
  `tests/*.rs`); `tests/support/` is a private helper dir, never an
  auto-discovered Cargo target. There is no catch-all, helper, or hook
  framework.
- **`fixtures boot` is a separate E2E-family selector.** `boundary phase1`
  (native gate) never executes E2E and is not E2E qualification.
- **Owner-local convention for `cfg(test)` suites.** Unit suites live
  colocated at `src/<owner>/tests.rs` (or a dot-named variant such as
  `dot_tests.rs`); genuine topic groups split into child
  `src/<owner>/<mod>/tests/<topic>.rs` files declared by the parent — or inline
  `mod <topic> { .. }` children colocated in the parent's own `tests.rs`. Storage
  startup integration stays a colocated private seam
  (`src/runtime/storage/startup_integration.rs`). `src/config/**` is the one
  module owner using the substantial `*_config_tests.rs` named roots
  (`cname_bailiwick_config_tests.rs`, `enforcement_config_tests.rs`,
  `resolver_config_tests.rs`), all retained whole-file; the enforcement and
  resolver paths are specifically frozen-spec-cited, and the third is a
  legitimate private cfg(test) root.
- **Small inline suites stay inline deliberately; group only genuine
  cohesion.** Moving a suite between these forms MAY change qualified test
  names — adding a topic child module introduces a prefix, while a same-name
  `#[cfg(test)]` module externalization preserves the qualified prefix — so a
  move records its name/identity mapping (renames where they occur, identity
  preservation for same-module externalizations). Shared test-only helpers
  live under `tests/support/` and are included via private `#[path]` modules —
  no Cargo target, no production export.
- **Reactor topic grouping via inline child modules.** `runtime/reactor/tests.rs`
  wraps its tests in 14 inline topic modules (poll_timeout, run_once, serving,
  connect_setup, deadlines, generation_tokens, dialing, relay, visit_budget,
  sigterm_shutdown, enforcement, admission, coalescing, ja4_baseline), with
  helpers/fixtures kept in the parent and the external `tests/refusals.rs`
  child (5 refusal tests) unchanged. `dns/transport/tests.rs` has the
  `shared_armed_cache` topic child (unchanged, 3 tests). `dns/transport/tests.rs`
  now holds 13 inline topic modules (exchange, cooperative, startup, apply,
  cancel, degraded, anomaly, failover, failback, probe_sweep, note_failure,
  corroboration, turn_result) with all helpers kept in the parent;
  `runtime/owner` follows the same
  inline-topic form in ten modules (cooperative_dns, probe_sweep, publishing,
  main_wiring, startup_warning, startup_window, sigterm_shutdown,
  startup_exchange, probe_records, due_refresh) with shared helpers kept in the
  parent; `dns/wire/tests.rs` now holds 16 inline protocol topic modules (positive,
  validation, bailiwick_cname, ttl_flags, workspace, negative_soa, authority_soa,
  policy_rejects, malformed_rdata, cache_schedule, family, wire_names,
  duplicate_cname, robustness, alloc_witness, embedded_dot) with all helper
  fns kept in the parent. `log/tests.rs` now holds 14 inline topic modules
  (record_encoding, startup_records, fatal_grammar, oversize_drops, queue_overflow,
  sink_budget, monitor_queue, monitor_records, monitor_edges, reserved_records,
  shutdown, writev_progress, sink_failure, typed_incidents) with all helper fns
  kept in the parent. The previously whole-file runtime/owner, dns/wire, and
  log suites now expose named inline topic modules.

## Offline docs link checker

`scripts/docs_check/check.mjs` is a zero-network offline AST link checker. It
parses Markdown, builds heading slugs with `github-slugger`, and verifies
every **local** link target exists and its literal fragment matches a generated
slug (`DOCSLINK-MISSING` / `DOCSLINK-MISSING-FRAGMENT`); operational or
unsupported constructs fail `DOCSLINK-OP-FAIL` and are never read as clean.
Limitations (documented, retained as approved — not removed, node deps stay):

- External `http:`/`https:`/`mailto:` links are **out of scope**, not failed.
- Long-form `rustdoc`/`cargo doctests` are **not** part of this gate.
- A zero-argument invocation is an **operational false-clean** — never a pass.
- Fragment verification is AST-literal: a fragment must match the slugger
  output exactly (local paths, GitHub slug rules).

The checker's own behavioral controls run via `node scripts/docs_check/test.mjs`.

## Native proofs (scoped, exact-input)

Native proofs are scoped to exact candidates, never blanket (`mid
foundations`/`mid boot`, `fixtures boot`, `e2e relay`, `e2e shutdown`, and the
alloc-witness matrix are recorded against exact-input identity receipts in bd
beads). `boundary phase1` never executes E2E; exit-zero coordination is not
release qualification. Where a prerequisite is absent or a gate is not
runnable-now, the classification stays an honest `BLOCKED` diagnostic — never
converted to a clean or claimed result.
