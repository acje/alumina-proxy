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
cargo +1.99.0 atest -p alumina --locked                   # full suite, witness-off — gated on Linux via `mid full` (reached via `sh scripts/verify.sh boundary phase1`); listed here as a manual reference
cargo +1.99.0 atest -p alumina --locked --features alloc-witness   # full suite, alloc-witness — gated on Linux via `mid full`; listed here as a manual reference
cargo +1.99.0 fmt --check
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh inner check                # INNER tier: cargo check only; host-runnable (compiles on macOS)
sh scripts/verify.sh mid foundations            # MID tier (Linux-only, fail closed off-Linux): behavior-proof only (fast loop)
sh scripts/verify.sh mid boot                   # MID tier (Linux-only): behavior-proof only (fast loop)
sh scripts/verify.sh mid clippy                 # MID tier (Linux-only): clippy -D warnings (production + alloc-witness harness)
sh scripts/verify.sh mid union                  # MID tier (Linux-only): release + static-ELF + closure metadata + clippy
sh scripts/verify.sh mid full                   # MID tier (Linux-only): full suite witness-off then witness-on
sh scripts/verify.sh docs                       # native offline docs link gate
sh scripts/verify.sh fixtures boot              # host Podman coordinator; Darwin allowed
sh scripts/verify.sh e2e relay                  # host-runnable; auto-dispatches Linux build on Darwin
sh scripts/verify.sh e2e shutdown               # host-runnable via rootful harness
sh scripts/verify.sh boundary phase1            # BOUNDARY tier: mid union + mid full + fixtures + docs + audit/deny + identity; never E2E
```

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them). Most gate selectors run a filtered scope: their
`verify.sh` `atest` invocations carry `--test foundations` or `--test boot`
(optionally with `--features alloc-witness`). The `mid full` selector is the
exception: it runs the UNFILTERED full suite (lib unit tests + all 7
integration test binaries) witness-off then witness-on (alloc-witness, incl.
the eligibility witness and the alloc-witness-only mio_matrix binary), on Linux
via `sh scripts/verify.sh boundary phase1`.

### Three-tier guarantee contract

Verification is tiered; each tier backs a different claim:

- **INNER** — `sh scripts/verify.sh inner check`: cargo check only (no
  clippy/fmt/whitespace/release). Host-runnable (compiles on macOS). Fast
  per-edit feedback; backs no done-claim.
- **MID** — Linux-only selectors (fail closed off-Linux): `mid foundations`
  and `mid boot` are behavior-proof-only fast loops (their former
  static-ELF/clippy/release/closure proofs moved to `mid union`); `mid
  clippy` runs clippy `-D warnings` for production and the alloc-witness
  test harness; `mid union` carries release + static-ELF + closure metadata
  + clippy; `mid full` runs the unfiltered full suite witness-off then
  witness-on. MID backs per-sub-mission done-claims.
- **BOUNDARY** — `sh scripts/verify.sh boundary phase1`: one Linux dispatch
  running `mid union && mid full` (`set -e` aborts on the first red marker)
  plus `fixtures boot`, the docs link gate, audit/deny, the identity
  snapshot, and the git-diff check. Never executes E2E.
  `FINAL-PHASE1-COMPLETION: BLOCKED` (exit 1) is the honest by-design
  diagnostic when a prerequisite is absent — never converted to a clean
  result. BOUNDARY backs repo-wide candidate done-claims.

### Full affected-corpus offline check

`verify.sh docs` runs the offline link gate on the **8-root canonical set**
(`DOCSLINK_ROOTS` in `scripts/verify.sh`): `README.md`, `docs/alumina-proxy.md`,
`docs/architecture.md`, `docs/build-plan.md`, `docs/traceability.md`,
`docs/verification.md`, `docs/qa-package/README.md`,
`docs/future-hardening-vectors.md`. The full retained Markdown
corpus — all **13** docs — is checked with the explicit nonempty
argv command:

```
node scripts/docs_check/check.mjs README.md AGENTS.md alumina-refinement.md docs/alumina-proxy.md docs/architecture.md docs/build-plan.md docs/traceability.md docs/harness-evaluation.md docs/benchmarks/100mbps-comparison.md docs/benchmarks/feature-match-matrix.md docs/verification.md docs/qa-package/README.md docs/future-hardening-vectors.md
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
