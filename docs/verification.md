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
sh scripts/verify.sh gate-children scan         # gate-child leak assertion: no reparented gate child survives under the cargo metadata target_directory or $ALT_AW_TARGET_DIR debug build roots
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

`bounded_suite` in `scripts/verify.sh` owns the stack budget: it exports
`RUST_MIN_STACK` at its fixed floor for every lib suite it bounds, so neither a
call site nor the container `-e` flags carry it. The two gate-only commands
above keep their prefix as the instruction for a hand run. The lib surface
overflows a smaller host default test-thread stack (observed on darwin), so a
run outside the helper must carry the same value.

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
1) against the debug build roots this gate builds into. Both roots are derived,
never assumed:

- the **witness-off** root, `<target_directory>/debug/build/alumina`, where
  `target_directory` is what
  `cargo metadata --no-deps --format-version 1 --locked` reports. Cargo's own
  answer is the authority here because it honours `CARGO_TARGET_DIR` and a
  config-file `build.target-dir`; a hardcoded `<checkout>/target` is exactly the
  root such a setting vacates, and a scan of it would report a real orphan
  clean. The scan therefore depends on `cargo` (as well as `awk` and a usable
  `ps`), and there is **no fallback** to `<checkout>/target`: an unavailable,
  missing, empty or unparsable `target_directory` is `GATE-CHILD-LEAK-UNKNOWN`.
- the **witness-on** root, which holds the alloc-witness gate binaries:
  `<checkout>/<ALT_AW_TARGET_DIR>/debug/build/alumina` for a relative knob
  (trailing slashes stripped, since cargo's own path join never repeats a
  separator) or the absolute directory itself.

Both sources are **bound at the source value, before composition, then
normalised or refused, never guessed at**. Each build root is carried as **one
value** end to end — a positional parameter during composition, then a per-root
environment value for the matcher — never as a line in a joined list that is
re-split later. Any whitespace character in a source value — LF, CR, TAB or a
trailing space, whether it comes from a checkout spelling, from cargo's answer or
from `ALT_AW_TARGET_DIR` — is `GATE-CHILD-LEAK-UNKNOWN` naming that source: a
root carrying whitespace cannot be delimited from the process arguments in the
line-oriented listing.

The metadata answer is re-composed under each checkout spelling by an exact,
quoted prefix strip in the shell (`${answer#"$checkout"/}`), so no glob and no
re-parse decides which root is scanned. The whitespace check on each composed
root is a second belt, never the protection itself: it catches a root the
listing cannot represent unambiguously, while the source binding is what stops a
value from being turned into a different root.

A trailing separator is then stripped, because a path join never repeats one. An
empty value, the filesystem root `/` (refused with its own message: it can never
be a build root), or a spelling carrying a `.`, `..` or empty (doubled-slash)
path component is `GATE-CHILD-LEAK-UNKNOWN` naming the offending spelling and
its source: cargo would exec from a path the scan cannot prove it can match. The
metadata answer needs this too — it is reported verbatim, so
`CARGO_TARGET_DIR=target/aw/` and `CARGO_TARGET_DIR=./target` come back with the
separator and the `./` intact (measured) — and an answer carrying
`target_directory` more than once is ambiguous, refused rather than resolved
last-wins (order could otherwise choose a root cargo never uses).

Within a root the shape is a hash-named subdirectory, then its `out`
subdirectory, then a gate-binary name carrying the same hash suffix — matched
against `argv[0]` only, so a running compiler or linker that merely writes into
that directory is not a match. Both the logical and the physical checkout
spelling are scanned where they differ, and deduped by exact string comparison
where they coincide. The `GATE-CHILD-LEAK-OK` line names every build root the
scan covered, read from the same value list the matcher consumes, and annotates
a root that does not exist yet as `(absent)`, so a mis-spelled root is visible in
the receipt instead of silently matchless.

The assertion runs **before and after the `host-mid` dispatch**. In `mid union`
and `mid full` it runs before and after the witness-off lib-suite invocation and
after the alloc-witness one; nothing scans between the alloc-witness clippy pass
and the alloc-witness suite, so a child leaked by that clippy run is caught only
after the suite that follows it. It also runs standalone as above.
`GATE-CHILD-LEAK-FAIL` names the pid and its `argv[0]` and exits non-zero.

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

An **unusable observation fails closed**: when `ps` is absent or fails, `awk` is
absent, the checkout spelling is empty, not absolute or carries any whitespace
(an unqualified `pwd` would otherwise compose `/target/debug/build/alumina`),
`cargo metadata` fails or reports no usable `target_directory`, a
`target_directory` or `ALT_AW_TARGET_DIR` source value carries any whitespace,
the answer reports `target_directory` more than once (ambiguous), a spelling is
empty, `/` (the filesystem root is never a build root), non-absolute where it
must be absolute, or non-canonical, a composed build root carries whitespace
(argv[0] is then not separable from the process arguments; second belt), the
listing cannot be parsed, the listing does not contain the scanning shell, or the
derivation yields no root at all, the gate prints `GATE-CHILD-LEAK-UNKNOWN` and
exits non-zero. An operational error is never a clean scan.

Residual: where no `ps` form this host accepts carries `-ww` (busybox accepts
none portably), a long `argv[0]` may be truncated, and a truncated `argv[0]` can
make a real orphan look matchless. That path still emits a visible
`GATE-CHILD-LEAK-NOTE` rather than failing closed, because refusing the portable
fallback would red every busybox host.

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
`bounded_suite`, with a `GATE_SUITE_BUDGET_SECS` default of **600 s**. libtest has
no timeout of its own, so a suite blocked in a read is indistinguishable from a
slow one and consumes the whole window.

The bound covers the **whole `cargo atest` invocation**, not the test run: the
command fingerprints, may relink and compiles before any test starts, so a cold
build sits inside the same 600 s. The measured warm run reports its test
execution at about 38 s (35.8-39.7 s over the recorded union runs), which 600 s
admits with room; the cold-build cost on the dispatch image is **unmeasured**, so
on a cold target directory the build is charged to the same budget. For scale, a
wedged run printed no progress past 60 s and was still wedged at 9 minutes.

The value is validated, never trusted. It must be a strictly positive decimal
integer: unset takes 600, while empty, `0`, a sign, a decimal point, whitespace or
any other non-digit is **refused** before a wrapper is resolved, so no
`GATE-SUITE-BOUND` line is emitted and no command is executed. Zero is refused in
particular because a duration of 0 means *no limit* to both implementations this
repository resolves (BSD `timeout`, the default on macOS 15+, and GNU
`gtimeout`): a zero budget would remove the bound while the receipt affirmed it.
Leading zeros are stripped, so `0600` is the 600 s bound.

The helper also owns the stack budget the suite runs at. The lib surface
overflows a smaller default test-thread stack (on darwin the suite dies at
libtest exit 101 with no failing test, which reads as a product symptom), so the
helper exports a fixed `RUST_MIN_STACK` floor for the invocation it wraps. A
caller-supplied value below that floor is refused, never run: an under-budgeted
suite is not evidence either.

The helper resolves `timeout`, then `gtimeout` (the coreutils spelling), and
runs `-s KILL` at the budget: the form GNU and busybox `timeout` both accept, so
the bounded suite never waits past it. One receipt line and three failure markers:

- `GATE-SUITE-BOUND` on every invocation, naming the resolved wrapper, the
  budget, the exported stack size and the command, so the receipt records the
  bound that was applied;
- `GATE-SUITE-TIMEOUT-FAIL` when the wrapper kills the suite, with a non-zero
  exit (124 conventional, or 137 as measured for a KILLed child);
- `GATE-SUITE-TIMEOUT-UNKNOWN` for the two refusals that keep a bound real:
  neither wrapper on `PATH` (an unavailable bound is never an unbounded pass),
  and a budget that is not a strictly positive decimal integer (a value that
  cannot bound is refused, never handed to a wrapper that would read it as "no
  limit");
- `GATE-SUITE-STACK-UNKNOWN` when the stack budget is empty, non-numeric, or
  below the floor: the helper refuses before resolving a wrapper, so the suite
  runs neither unbounded nor under-budgeted.

A genuine test failure is not a timeout: libtest's own exit 101 passes through
unchanged with no timeout marker.

The bound releases the gate window; it is not a reaper, and it does not extend
the bracket's reach. On the timeout path `bounded_suite` returns the wrapper's
non-zero status and `set -eu` ends the run, so the post-suite scans of *that* run
never execute: a survivor is left to the next invocation's pre-suite (and
pre-dispatch) scan. What `-s KILL` signals also differs by implementation. BSD
`timeout` and GNU `timeout` signal the whole process group of the command by
default (GNU documents the contrast under `--foreground`), so cargo and the
lib-test binary it spawned are signalled together and leave no lib-test orphan.
busybox `timeout` is direct-child-only -- **Unknown** here, because no busybox
was available to measure it. Under a direct-child-only signal the lib-test binary
survives, and it is `deps/`-shaped: the scan matches only
`<target>/debug/build/alumina/<hash>/out/<name>-<hash>`, the shape cargo execs
this crate's lib and gate binaries from, so a `target/debug/deps/<name>-<hash>`
binary is never matched -- not by the post-suite scan, and not by the next
invocation's pre-scan. A survivor of that shape is met as the wait the pre-scan
note above describes, never as a caught leak.

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
