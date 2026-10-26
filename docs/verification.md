# Verification — instructions and command set

Verification here is **scoped and exact-input**: proofs are recorded for
specific candidates, never blanket, and a completed check at one candidate is
not reused for another unless the inputs are identical. Repository status and
known limitations are the README; qualification gates stay open and are owned
by [docs/build-plan.md](build-plan.md) (status owner
[docs/qa-package/README.md](qa-package/README.md)). This file is the
verification **instruction / command-set** authority (relocated from the README
"Verification" section).

## Command set

Host-run selectors and gates (all `sh scripts/verify.sh …` selectors and host
Cargo commands):

```
cargo +1.99.0 atest -p alumina --locked --lib --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall   # gate-only suite (lib units + 5 gate-only binaries), witness-off — gated on Linux via `mid full` (reached via `sh scripts/verify.sh boundary phase1`); listed here as a manual reference
cargo +1.99.0 atest -p alumina --locked --features alloc-witness --lib --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall   # gate-only suite, alloc-witness — gated on Linux via `mid full`; listed here as a manual reference
cargo +1.99.0 fmt --check
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh inner check                # INNER tier: cargo check only; host-runnable (compiles on macOS)
sh scripts/verify.sh mid foundations            # MID tier (Linux-only, fail closed off-Linux): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid boot                   # MID tier (Linux-only): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid clippy                 # MID tier (Linux-only): clippy -D warnings (production + alloc-witness harness)
sh scripts/verify.sh mid union                  # MID tier (Linux-only): release + static-ELF + closure metadata + clippy
sh scripts/verify.sh mid full                   # MID tier (Linux-only): gate-only suite (lib units + 5 gate-only binaries) witness-off then witness-on
sh scripts/verify.sh docs                       # native offline docs link gate
sh scripts/verify.sh fixtures boot              # host Podman coordinator; Darwin allowed
sh scripts/verify.sh e2e relay                  # host-runnable; auto-dispatches Linux build on Darwin
sh scripts/verify.sh e2e shutdown               # host-runnable via rootful harness
sh scripts/verify.sh boundary phase1-fast       # BOUNDARY fast tier: change-scope classification + cheap host gates (docs/unsafe/whitespace/audit) + identity; no Linux MID, no fixtures, no E2E
sh scripts/verify.sh boundary phase1-slow       # BOUNDARY slow tier: reads scope marker; docs-only => explicit SKIPPED-BY-DESIGN, no MID; full => mid union + mid full + fixtures + artifact identity
sh scripts/verify.sh boundary phase1            # BOUNDARY tier (composed): fast tier, then slow tier unless docs-only; never E2E; exit 1 BLOCKED by design
```

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them). Most gate selectors run a filtered scope: their
`verify.sh` `atest` invocations carry `--test foundations` or `--test boot`
(optionally with `--features alloc-witness`). The `mid full` selector is the
exception: it runs the gate-only test surface — lib unit tests + the 5
integration binaries that run in no other selector (eligibility, mio_matrix,
main_thread_stack, monitor_stdout, stdout_stall) — witness-off then witness-on
(alloc-witness, incl. the eligibility witness and the alloc-witness-only
mio_matrix binary), on Linux via `sh scripts/verify.sh boundary phase1`.
foundations and boot are deliberately not re-run there: `mid union` already
runs them in the same BOUNDARY dispatch (and the `mid foundations` / `mid boot`
inner loops run them during development).

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
  + clippy; `mid full` runs the gate-only suite (lib units + the 5
  gate-only binaries) witness-off then witness-on. MID backs per-sub-mission
  done-claims.
- **BOUNDARY** — split into a fast tier and a slow tier; both exit 1
  `BLOCKED` by design and neither ever executes E2E:
  - `sh scripts/verify.sh boundary phase1-fast`: identity BEFORE snapshot,
    change-scope classification (writes `target/phase1-scope`), then the
    cheap host gates — docs link gate, unsafe-surface gate, `git diff
    --check`, audit/deny — and an identity AFTER/compare. No Linux MID, no
    fixtures. Fails fast so a cheap-gate failure aborts before the ~90-min
    compile-dominated dispatch.
  - `sh scripts/verify.sh boundary phase1-slow`: reads the scope marker
    (missing => full, fail-safe). On docs-only it emits an explicit
    `PHASE1-SLOW-SKIPPED-BY-DESIGN` and skips the Linux MID; on full it runs
    one Linux dispatch `mid union && mid full` (`set -e` aborts on the first
    red marker) plus `fixtures boot` and the artifact identity check.
  - `sh scripts/verify.sh boundary phase1` (composed): fast tier, then the
    slow tier unless the scope is docs-only. Preserves the single-invocation
    path used by `docs/qa-package/validate.sh`.
  `FINAL-PHASE1-COMPLETION: BLOCKED` (exit 1) is the honest by-design
  diagnostic when a prerequisite is absent — never converted to a clean
  result. The split is the **scoped and exact-input** doctrine (above)
  applied to execution conditionality: a full-scope candidate still runs the
  full ceremony, and a docs-only candidate skips the MID explicitly, never
  silently. BOUNDARY backs repo-wide candidate done-claims.

### Full affected-corpus offline check

`verify.sh docs` runs the offline link gate on the **8-root canonical set**
(`DOCSLINK_ROOTS` in `scripts/verify.sh`): `README.md`, `docs/alumina-proxy.md`,
`docs/architecture.md`, `docs/build-plan.md`, `docs/traceability.md`,
`docs/verification.md`, `docs/qa-package/README.md`,
`docs/future-hardening-vectors.md`. The full retained Markdown
corpus — all **12** docs — is checked with the explicit nonempty
argv command:

```
node scripts/docs_check/check.mjs README.md AGENTS.md docs/alumina-proxy.md docs/architecture.md docs/build-plan.md docs/traceability.md docs/harness-evaluation.md docs/benchmarks/100mbps-comparison.md docs/benchmarks/feature-match-matrix.md docs/verification.md docs/qa-package/README.md docs/future-hardening-vectors.md
```

Selector host context / prerequisites (incl. `mid` Linux-only fail-closed and
`fixtures`/`e2e` host-runnable details, `boundary phase1` never executing E2E):
sole owner is [docs/qa-package/README.md](qa-package/README.md).

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
