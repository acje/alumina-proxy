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
Cargo commands). The repository ships no toolchain pin: host commands resolve
the host's default toolchain, and container-dispatched gates resolve the pinned
base image's default toolchain.

```
RUST_MIN_STACK=16777216 cargo atest -p alumina --locked --lib --test eligibility --test main_thread_serving --test monitor_stdout --test stdout_stall --test stdout_closed   # gate-only surface, witness-off; mio_matrix is alloc-witness-only and appears in the next line
RUST_MIN_STACK=16777216 cargo atest -p alumina --locked --features alloc-witness --lib --test eligibility --test mio_matrix --test main_thread_serving --test monitor_stdout --test stdout_stall --test stdout_closed   # gate-only surface, alloc-witness — a manual reference (runs inside `mid union`)
cargo fmt --check
cargo aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh inner check                # INNER tier: cargo check only; host-runnable (compiles on macOS)
sh scripts/verify.sh mid foundations            # MID tier (Linux-only, fail closed off-Linux): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid boot                   # MID tier (Linux-only): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid clippy                 # MID tier (Linux-only): clippy -D warnings (production + alloc-witness harness)
sh scripts/verify.sh mid union                  # MID tier (Linux-only): release + static-ELF + closure metadata + clippy; runs lib units + foundations/boot + the five both-configuration gate binaries witness-off, then the same surface plus the alloc-witness-only mio_matrix witness-on
sh scripts/verify.sh mid full                   # MID tier (Linux-only): standalone gate-only selector (lib units + the five both-configuration gate binaries witness-off, plus the alloc-witness-only mio_matrix witness-on); surface subsumed by mid union
sh scripts/verify.sh host-mid union             # host Podman dispatch of Linux mid union, including release artifact copy-out
sh scripts/verify.sh host-mid foundations       # host Podman dispatch; also boot, clippy, full
sh scripts/verify.sh docs                       # native offline docs gate: links + physical INTENDED + cfg-parentage + unsafe + spec digest
sh scripts/verify.sh fixtures boot              # host Podman coordinator; Darwin allowed
sh scripts/verify.sh supply-chain audit-deny    # host audit and deny, pinned tool versions
sh scripts/verify.sh identity snapshot target/identity-before
sh scripts/verify.sh identity snapshot target/identity-after
sh scripts/verify.sh identity compare target/identity-before target/identity-after
sh scripts/verify.sh identity artifact target/release/alumina
sh scripts/verify.sh e2e relay                  # host-runnable; auto-dispatches Linux build on Darwin
sh scripts/verify.sh e2e shutdown               # host-runnable via rootful harness
```

The two gate-only `cargo atest` commands above carry `RUST_MIN_STACK=16777216`
(the Linux dispatch sets the same value for the same suite in `scripts/verify.sh`):
the lib surface overflows a smaller host default test-thread stack (observed on
darwin), so a bare host run must carry it too.

These are independent checks, not a required sequence. For an identity-stability
check, take the before snapshot before the chosen work and the after snapshot
after it, then compare; `identity artifact` hashes the named existing file and
does not establish that it was built or executed in the run.

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them). `mid foundations` and `mid boot` run a filtered
scope; `mid full` is the standalone gate-only selector and `mid union` the
whole-surface dispatch. Per-selector semantics and prerequisites are owned by
the [QA package](qa-package/README.md#selector-host-context-sole-owner).

### Offline docs gate — the `docs` selector (not just links)

`sh scripts/verify.sh docs` is the full offline docs gate, not a link-only
check. It runs, in sequence: the **Repowise doc-drift** gate over the tracked
documentation corpus (local paths, links, anchors and commands); the physical
**INTENDED** inventory (every `src`/`tests` `.rs` listed);
**CFG-TEST-PARENTAGE** (admitted `src/*/tests.rs` and `src/*/dot_tests.rs`
declared `#[cfg(test)]` by their parent); the **UNSAFE-SURFACE** confinement
gate; the **CANONICAL-DIGEST** pin (frozen spec sha equals the `AGENTS.md`
pin); and the report-only Rust symbol-reference lint. A docs change reruns this
whole selector — the drift gate alone is not the gate.

The retained Markdown corpus is checked by Repowise:

```sh
repowise doc-drift --check --kind path --kind link --kind anchor --kind command --fail-on-confidence 0.7
```

The Rust symbol-reference lint over the governing specification is report-only:

```sh
python3 scripts/ref_check.py
```

Selector host context / prerequisites (incl. `mid` Linux-only fail-closed and
`host-mid`/`fixtures`/`e2e` host-runnable details):
sole owner is [docs/qa-package/README.md](qa-package/README.md).

## Gate ordering and cost structure

Why the dispatch structure looks the way it does. Nothing here changes a
verdict; it explains the shapes `verify.sh` enforces.

- **One gated test invocation per feature configuration.** The whole-surface
  union runs lib units, `foundations`, `boot`, and the gate-only integration
  binaries together, once witness-off and once witness-on, instead of three
  invocations per configuration re-resolving the unit graph each time. The
  witness-off pass carries only the binaries that assert in both
  configurations; the witness-on pass adds the alloc-witness-only
  `mio_matrix`.
- **One target directory per feature configuration**, so witness-on and
  witness-off artifacts never share a Cargo fingerprint graph.
- **Ordering is binding, not stylistic.** The clippy pair stays adjacent
  (alloc-witness clippy immediately after production clippy, with the
  alloc-witness lib last built by the witness tests), and the alloc-witness
  tests run only *after* the alloc-witness clippy pass. The hazard this avoids
  is an alloc-witness-clippy-after-alloc-witness-test adjacency producing a
  clippy-per-target fingerprint `E0463` (cannot find crate `alumina`) on the
  alloc-witness-only `mio_matrix` target over a shared target directory. That
  is also why the union defers the boot tests until after the clippy block,
  diverging from the standalone `mid boot` order.
- **Container workspaces are separated.** Both Cargo target trees (production
  release and the fixture-facts variant) live in VM-native volumes; the
  variant keeps its own target directory so the production artifact is never
  clobbered. The container Cargo cache and home are volumes, and only consumed
  artifacts are copied out, under a two-sided digest assertion.
- **One derived image.** A single digest-identified image is built once from
  the pinned Rust base (which ships no git, clippy, or rustfmt), so a dispatch
  performs no package or component installation per run.
- **`ALT_` knobs are the A/B surface** for that cost structure.
  `ALT_NO_VOLUME=1` restores host bind-mount behaviour for an
  apples-to-apples baseline measurement; `alt image` / `alt smoke` warm and
  prove the container plumbing and back no claim.

## Test suite navigation & ownership

Navigation/ownership instructions, not an architecture narrative (no findings,
verdicts, or issue records here).

- **Owner-local `cfg(test)` suites.** Unit suites live at
  `src/<owner>/tests.rs` or a dot-named variant such as `dot_tests.rs`; genuine
  topic groups split into child `src/<owner>/<mod>/tests/<topic>.rs` files
  declared by the parent, or inline `mod <topic> { .. }` children in the
  parent's own `tests.rs`. Small inline suites stay inline; group only genuine
  cohesion.
- **Shared test-only helpers** live under `tests/support/` as private `#[path]`
  modules — no Cargo target, no production export.
- **Moving a suite MAY change qualified test names** (a topic child introduces a
  prefix; a same-name `#[cfg(test)]` externalization preserves it), so a move
  records its name/identity mapping.

## Docs drift gate

`sh scripts/verify.sh docs` runs `repowise doc-drift --check` over the tracked
documentation corpus. It verifies every local path, link target, heading
fragment and inline command; external URLs are out of scope and never fetched.
Operational failure (Repowise absent, unreadable corpus) is BLOCKED, never a
pass. Historical `git:<sha>:path` receipts are content-addressed and not
reinterpreted as live paths.

The Rust symbol-reference lint (`scripts/ref_check.py`) is separate and
report-only; it checks only `path.rs::Symbol` references in
`docs/alumina-proxy.md`. Other documents are not mechanically reference-checked.

## Native proofs (scoped, exact-input)

Native proofs are scoped to exact candidates, never blanket (`mid
foundations`/`mid boot`, `fixtures boot`, `e2e relay`, `e2e shutdown`, and the
alloc-witness matrix are recorded against exact-input identity receipts in bd
beads). Fixture smoke is not E2E or release qualification. Where a prerequisite
is absent or a gate is not
runnable-now, the classification stays an honest `BLOCKED` diagnostic — never
converted to a clean or claimed result.
