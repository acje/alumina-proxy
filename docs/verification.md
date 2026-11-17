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
RUST_MIN_STACK=16777216 cargo atest -p alumina --locked --lib --test eligibility --test binary_entry --test main_thread_serving --test monitor_stdout --test stdout_stall --test stdout_closed   # gate-only surface, witness-off; mio_matrix is alloc-witness-only and appears in the next line
RUST_MIN_STACK=16777216 cargo atest -p alumina --locked --features alloc-witness --lib --test eligibility --test binary_entry --test mio_matrix --test main_thread_serving --test monitor_stdout --test stdout_stall --test stdout_closed   # gate-only surface, alloc-witness — a manual reference (runs inside `mid union`)
cargo fmt --check
cargo aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh inner check                # INNER tier: cargo check only; host-runnable (compiles on macOS)
sh scripts/verify.sh mid foundations            # MID tier (Linux-only, fail closed off-Linux): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid boot                   # MID tier (Linux-only): behavior-proof + fmt/whitespace (fast loop)
sh scripts/verify.sh mid clippy                 # MID tier (Linux-only): clippy -D warnings (production + alloc-witness harness)
sh scripts/verify.sh mid union                  # MID tier (Linux-only): release + static-ELF + closure metadata + clippy; runs lib units + foundations/boot + the six both-configuration gate binaries witness-off, then the same surface plus the alloc-witness-only mio_matrix witness-on
sh scripts/verify.sh mid full                   # MID tier (Linux-only): standalone gate-only selector (lib units + the six both-configuration gate binaries witness-off, plus the alloc-witness-only mio_matrix witness-on); surface subsumed by mid union
sh scripts/verify.sh host-mid union             # host Podman dispatch of Linux mid union, including release artifact copy-out
sh scripts/verify.sh host-mid foundations       # host Podman dispatch; also boot, clippy, full
sh scripts/verify.sh gate-children scan         # gate-child leak assertion: no reparented gate child survives under target/debug or $ALT_AW_TARGET_DIR debug build roots
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

## Gate-child leak assertion

`sh scripts/verify.sh gate-children scan` asserts that no gate child survived its
parent. A spawned child that outlives the process that spawned it keeps its
loopback listener open, so a later gate binds or connects against a listener it
does not own and every receipt after it is chain-ambiguous.

The scan reads the process table (the procps form, with a busybox fallback) and
matches only the **executed program** — the first word of the process arguments,
not a path that merely appears among them — of a reparented process (parent pid
1) against every debug build root this gate builds into:

- `target/debug/build/alumina` — the witness-off root;
- `$ALT_AW_TARGET_DIR/debug/build/alumina` — the witness-on root, which holds
  the alloc-witness gate binaries: the default `target/aw`, with a relative knob
  resolved against the checkout and an absolute knob used as given.

Within a root the shape is a hash-named subdirectory, then its `out`
subdirectory, then a gate-binary name carrying the same hash suffix. Both the
logical and the physical checkout spelling are matched, deduped where they
coincide, so a running compiler or linker that writes into that directory is not
a match. The `GATE-CHILD-LEAK-OK` line names every build root the scan covered,
so a root missing from that line is visible rather than implied.

The assertion runs **before and after the `host-mid` dispatch**, before and
after each lib-suite invocation in `mid union` and `mid full`, and standalone as
above. `GATE-CHILD-LEAK-FAIL` names the pid and the command line and exits
non-zero.

### The native lib-suite recipe

A host-native lib run must be **bracketed** by the scan, because a host run has
no dispatch boundary to fail at, and must carry the same 600 s bound the gate
applies (see [the lib-suite budget](#the-lib-suite-budget)):

```bash
sh scripts/verify.sh gate-children scan
RUST_MIN_STACK=16777216 timeout -s KILL 600 cargo atest -p alumina --locked --lib
sh scripts/verify.sh gate-children scan
```

`gtimeout` is the fallback spelling where GNU coreutils is installed under that
name; with neither on `PATH` the run must not proceed.

The **pre-scan** is what makes the bracket load-bearing for a host-native run:
an orphan that already existed before the run owns a loopback listener, so a lib
unit that binds or connects against it *waits* rather than failing — observed as
a host lib run hung for over 30 minutes on a listener it never created. There
the pre-scan converts a stale orphan into a fail instead of a hang, and the
post-scan proves the run left no new one.

The `host-mid` pre-scan is a different claim: it is a **host-state
precondition**, not hang prevention. The dispatch executes in its own process
namespace, where a host orphan is neither visible nor waited on, so the pre-scan
cannot stop a container hang. What it stops is a receipt recorded against an
ambiguous host state: a stale orphan on the host holds a loopback listener no
current gate owns, so the dispatch receipt that follows is chain-ambiguous.

An **unusable observation fails closed**: when `ps` is absent or fails, a build
root contains whitespace (argv[0] is then not separable from the process
arguments), the listing cannot be parsed, or the listing does not contain the
scanning shell, the gate prints `GATE-CHILD-LEAK-UNKNOWN` and exits non-zero. An
operational error is never a clean scan.

Platform limit: the parent-death signal is Linux-only (it is installed in the one
guarded spawn in `tests/support/process_harness.rs`, which also refuses to exec a
gate binary whose parent is already gone). On Darwin the guard reaps a child
while the parent unwinds, but a child that outlives an abrupt parent death
(SIGKILL) is not signalled by the kernel: it stays until the next gate's scan
fails on it.

Negative-control shape — the failure path is exercised, not just the clean path:

1. Plant a panic in the parent between spawn and the bounded wait: unwinding runs
   the guard's drop, so no orphan remains and the scan stays clean.
2. Disable the guard for one run (forget it) and exit the parent: the child is
   reparented and the scan exits non-zero naming its pid.
3. Revert: the suite is green again and the scan is clean.

### The lib-suite budget

Every lib-suite invocation in `mid union` and `mid full` runs under one helper,
`bounded_suite`, with a fixed `GATE_SUITE_BUDGET_SECS` of **600 s**. libtest has
no timeout of its own, so a suite blocked in a read is indistinguishable from a
slow one and consumes the whole window.

The budget's evidence, measured on this repository: a green bracketed lib run
passed 1181 tests in 22.67 s, while a wedged run printed no progress past 60 s
and was still wedged at 9 minutes on a test blocked in `read_until`. 600 s is
about 26x the green run and far below the window the wedge consumed.

The helper resolves `timeout`, then `gtimeout` (the coreutils spelling), and
runs `-s KILL` at the budget: the form GNU and busybox `timeout` both accept, so
the gate never waits past it. One receipt line and two failure markers:

- `GATE-SUITE-BOUND` on every invocation, naming the resolved wrapper, the
  budget and the command, so the receipt records the bound that was applied;
- `GATE-SUITE-TIMEOUT-FAIL` when the wrapper kills the suite, with a non-zero
  exit (124 conventional, or 137 as measured for a KILLed child);
- `GATE-SUITE-TIMEOUT-UNKNOWN` when neither wrapper is on `PATH`: the helper
  refuses to run, because an unavailable bound is never an unbounded pass.

A genuine test failure is not a timeout: libtest's own exit 101 passes through
unchanged with no timeout marker. The bound releases the gate window; it cannot
reap a test binary cargo had already spawned, so the bracket above still owns a
process that outlives its parent.

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
- **`tests/binary_entry.rs` is the only target that executes the real binary**
  (via `CARGO_BIN_EXE_alumina`, in a scratch working directory). It proves the
  boot-failure arm through the real `main()`: `EX_CONFIG` 78 for a missing and
  for a malformed `config.toml`, a stderr diagnostic, and empty stdout, with the
  Linux child dropped to a non-root uid with `no_new_privs` set. It does not
  prove the serving path, and on Linux it does not prove that the config stage
  is reached only after the privilege preflight — with every prerequisite
  satisfied, swapping the two boot steps yields the same exit code and
  diagnostic. The one ordering fact that is observable off Linux: with no
  `config.toml` the preflight rejection is the only diagnostic, which pins that
  the preflight runs first on that platform.
- **Moving a suite MAY change qualified test names** (a topic child introduces a
  prefix; a same-name `#[cfg(test)]` externalization preserves it), so a move
  records its name/identity mapping.

## Property-based tests (Hegel)

The properties (`#[hegel::test]` over `hegel::TestCase`) are the only
generative tests in the tree; each one owns a totality/determinism invariant
for a parser or normaliser. Two things are owned outside the test bodies:
**case-count breadth** by `hegel.toml`, and **exact-input semantics** by the
gates below.

### Profiles own breadth

`hegel.toml` defines exactly three profiles, each stating all three keys
explicitly. There is no top-level `default` key, so profile selection stays
with the environment: a CI server still resolves the shipped `ci` profile and
a local run the `development` block.

| Profile | `test_cases` | Other keys | Selected by |
|---|---|---|---|
| `development` | 64 | `derandomize = true`, `database = "disabled"` | local default |
| `ci` | 256 | `derandomize = true`, `database = "disabled"` | CI environment detection |
| `nightly` | 10_000 | `derandomize = true`, `database = "disabled"` | `HEGEL_DEFAULT_PROFILE=nightly` |

Breadth is therefore a one-flag change per environment, and a property
carries only `derandomize = true` — never `test_cases`.

### Settings layers (hegeltest 0.52.7)

Settings resolve in layers, each overriding the ones below it:

```
base -> profile (hegel.toml) -> environment -> compiled-in attribute -> CLI
```

The compiled-in attribute is **above** the environment: a property declared
`#[hegel::test(test_cases = 64)]` keeps 64 however `HEGEL_TEST_CASES` is set,
so the variable and the profile are both silently defeated. That is why no
attribute in this tree pins a case count (measured: with the attribute
present, `HEGEL_TEST_CASES=1000` still reported 64 cases; with it removed,
the same property reports 1000, and 64 with no variable set).

Gate-relevant environment pins and their 0.52.7 semantics:

| Variable | 0.52.7 semantics |
|---|---|
| `HEGEL_TEST_CASES` | Sets `test_cases`; must be a positive integer. Overrides the profile, not a compiled-in attribute. |
| `HEGEL_SEED` | Sets `seed`: an integer is the seed, `none` clears one the profile set. A fixed seed takes precedence over `derandomize`. |
| `HEGEL_DERANDOMIZE` | Sets `derandomize`: `true`/`1`/`yes`, or `false`/`0`/`no`. On, the seed is derived from the test name, so every run of that test is identical. |
| `HEGEL_PRINT_BLOB` | Sets `print_blob` with the same boolean vocabulary. On (the base default), a failing run prints a copy-pasteable `#[hegel::reproduce_failure("…")]` line. |
| `HEGEL_STATISTICS` | Anything except `0` or the empty string turns `show_statistics` on; the end-of-run report names the number of cases actually executed, which is the direct measurement of the resolved count. |

An empty variable is ignored; any other malformed value is an error raised
when the settings value is created.

Measured-count recipe for one property (the local default profile, then the
`HEGEL_TEST_CASES` override, then a nightly profile):

```bash
RUST_MIN_STACK=16777216 HEGEL_STATISTICS=1 cargo atest -p alumina --locked --lib -- hostname_normalisation_is_total_and_idempotent --nocapture   # "over 64 test cases"
RUST_MIN_STACK=16777216 HEGEL_STATISTICS=1 HEGEL_TEST_CASES=1000 cargo atest -p alumina --locked --lib -- hostname_normalisation_is_total_and_idempotent --nocapture   # "over 1000 test cases"
HEGEL_DEFAULT_PROFILE=nightly RUST_MIN_STACK=16777216 HEGEL_STATISTICS=1 cargo atest -p alumina --locked --lib -- hostname_normalisation_is_total_and_idempotent --nocapture   # "over 10000 test cases"
```

All three run the same single property with statistics on, so the printed
count is the resolved budget; the nightly line is that measurement at
long-soak breadth, not a whole-library run.

### Regression corpus is a literal replay

A durable corpus entry is a plain `#[test]` that replays the minimised inputs
through the same property body on every run (the witness is
`hostname_regression_replays_the_minimised_counterexample` in
`src/names/hostname/tests.rs`), **not** a checked-in
`#[hegel::reproduce_failure("…")]` blob. In 0.52.7 a blob skips generation
entirely — the property stops exercising its generators — and a run in which
no blob reproduces a failure panics with an explanatory message, so a blob
cannot hold a corpus in a green gate once the fault it captures is fixed
(bd alumina-dvgoj). Use the blob only as a transient capture while
minimising, then delete it. Named examples belong in
`#[hegel::explicit_test_case]` / `hegel::ExplicitTestCase`, which draws
pre-defined values by draw name without entering the generation layer.

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
