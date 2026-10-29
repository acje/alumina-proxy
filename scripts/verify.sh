#!/bin/sh
set -eu

# =============================================================================
# verify.sh — native verification entry point (gate coordinator)
#
# This script is the single owner of the scoped gate ceremony: INNER (host
# compile), MID (Linux-only behaviour proofs), BOUNDARY (candidate ceremony) and
# the fixtures/e2e native gates. The governing spec is docs/alumina-proxy.md;
# the verification instruction / command-set authority is docs/verification.md;
# status and prerequisites are docs/qa-package/README.md.
#
# COST STRUCTURE (measured, not assumed). Every gate and every marker line below
# is the same gate the ceremony always ran; what follows changes only where work
# happens and how much of it repeats:
#   I0  per-gate `PHASE1-TIMING: <gate> <ms|NA>` lines and a total, so wall clock
#       claims are measured. `NA` means no millisecond clock was available.
#   I1  ONE Cargo test invocation per feature config (lib units + foundations +
#       boot + the 5 gate-only binaries together) instead of three per config,
#       and one target dir per feature config (`$VERIFY_AW_TARGET_DIR`) so
#       witness-on/off artifacts never share a fingerprint graph. The boundary
#       slow tier therefore dispatches `mid union` alone: union covers the
#       gate-only surface, so `mid full` (still available standalone) is not
#       dispatched twice over the same candidate.
#   I2  both Cargo target trees (production release + the fixture-facts variant)
#       live in a VM-native podman volume. The variant KEEPS its own target dir:
#       sharing the production release dir would clobber target/release/alumina,
#       and "production artifact untouched" is a semantics guarantee.
#   I3  one derived, digest-identified image built once FROM the pinned rust base
#       (which ships no git, no clippy, no rustfmt), so the dispatch path performs
#       no `apk add` and no `rustup component add` per run.
#   I4  container Cargo cache and CARGO_HOME live in named volumes; only consumed
#       artifacts are copied out, with a two-sided digest assertion.
#   I5  the host target/ tree is no longer a container build home; it holds only
#       copied-out artifacts, receipts and temp files.
#   I8  `inner test <target>` host-native iteration path; backs no done-claim.
#
# The `ALT_`-prefixed knobs and `alt` selectors are the A/B surface for this cost
# structure (ALT = alternative cost structure). `ALT_NO_VOLUME=1` restores the
# original host bind-mount behaviour so a run can be measured apples-to-apples
# against the pre-I4 scheme. `alt image` / `alt smoke` warm and prove the
# container plumbing and back no claim.
#
# Do not run two boundary ceremonies concurrently: they share target/release and
# the fixture volumes. Identity snapshots use fixed target/ paths.
# =============================================================================

# Local podman connection names (gitignored; never committed). Sourced when
# present so the harness runs out-of-the-box on a dev machine; an explicit
# environment variable still wins and the fail-closed checks below remain.
if [ -f .ooda/podman-connections.env ]; then
    . ./.ooda/podman-connections.env
fi

TIER="${1:-}"
SCOPE="${2:-}"

usage() {
    echo "usage: verify.sh {inner|mid|boundary|fixtures|e2e} {check|test|foundations|boot|union|full|clippy|phase1|phase1-fast|phase1-slow|relay|shutdown} [target] | verify.sh docs" >&2
    echo "       inner test <target> runs ONE integration target host-natively; backs no done-claim." >&2
    exit 2
}

[ -n "$TIER" ] || usage
[ -n "$SCOPE" ] || [ "$TIER" = "docs" ] || usage
FOCUS="${3:-}"

TOOLCHAIN="1.99.0"

# --- ALT cost-structure knobs (I1-I4) ----------------------------------------
# Named podman volumes keep the container's Cargo caches on VM-native disk,
# persistent across dispatches. Set ALT_TARGET_VOL/ALT_CARGO_HOME_VOL to isolate
# concurrent experiments; set ALT_NO_VOLUME=1 to fall back to verify.sh's
# host bind-mount behaviour for an apples-to-apples baseline measurement.
ALT_TARGET_VOL="${ALT_TARGET_VOL:-alumina-verify-target}"
ALT_CARGO_HOME_VOL="${ALT_CARGO_HOME_VOL:-alumina-verify-cargo-home}"
ALT_NO_VOLUME="${ALT_NO_VOLUME:-0}"
# One target dir per feature config (I1): witness-on and witness-off builds never
# share a fingerprint graph, so the aw-clippy/aw-test adjacency hazard cannot
# arise and no ordering workaround is needed.
ALT_AW_TARGET_DIR="${ALT_AW_TARGET_DIR:-target/aw}"
# I3: one derived, digest-identified image, built once FROM the pinned rust base.
# Evidence for why: the pinned base carries NO git, NO clippy and NO rustfmt
# (`rustup component list --installed` = cargo/rustc/rust-std only; `command -v
# git` empty), so verify.sh re-downloads all three on EVERY dispatch
# (`rustup component add clippy rustfmt` + `apk add git`), and its fresh
# /cargo-home re-downloads all 50 crates every time. Baking the extras once and
# persisting CARGO_HOME in a volume removes three repeated network costs from the
# measured path. The base digest is quoted in the generated Containerfile and
# every dispatch records the derived image ID.
ALT_IMAGE="${ALT_IMAGE:-localhost/alumina-verify:20261029}"
FIXTURE_IMAGE="${FIXTURE_IMAGE:-$ALT_IMAGE}"
FIXTURE_BASE_IMAGE="docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a"

# --- I0: timing instrumentation ---------------------------------------------
# Millisecond timestamps from python3 (an already-required boundary prerequisite,
# see config_observe). A host without it prints `NA` rather than a fabricated
# number: an unmeasured phase must never look measured.
ALT_T0=$(date +%s)
now_ms() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'NA\n'
        return 0
    }
    python3 -c 'import time; print(int(time.time()*1000))'
}

# phase_timed <label> <function> [args...]: run a gate, emit one
# `PHASE1-TIMING: <label> <ms|NA>` line, propagate the gate's own exit status.
# A gate that calls `exit` terminates the run as before (its timing line is then
# absent, which is the honest signal that the phase did not complete).
phase_timed() {
    _pt_label="$1"
    shift
    _pt_t0=$(now_ms)
    _pt_rc=0
    "$@" || _pt_rc=$?
    _pt_t1=$(now_ms)
    case "${_pt_t0}${_pt_t1}" in
        *NA*) printf 'PHASE1-TIMING: %s NA\n' "$_pt_label" ;;
        *) printf 'PHASE1-TIMING: %s %sms\n' "$_pt_label" "$((_pt_t1 - _pt_t0))" ;;
    esac
    return "$_pt_rc"
}

# phase_mark <label> <ms>: emit a timing line for a phase measured inline (the
# Linux dispatch, the fixture run, a copy-out) where no function call brackets it.
phase_mark() {
    printf 'PHASE1-TIMING: %s %s\n' "$1" "$2"
}

# Total elapsed is printed by the boundary marker block only (a global EXIT trap
# would be clobbered by boot_fixtures' own temp-file trap).
alt_total_timing() {
    ALT_TOTAL=$(( $(date +%s) - ALT_T0 ))
    printf 'PHASE1-TIMING: total %ss\n' "$ALT_TOTAL"
}

INTENDED="Cargo.toml Cargo.lock rust-toolchain.toml deny.toml scripts/verify.sh scripts/cargo_config_probe.py scripts/fixture_metadata_probe.py README.md src/lib.rs src/main.rs src/alloc.rs src/bin/parser_bench.rs src/fault.rs src/fuzz.rs src/config.rs src/resolver.rs src/preflight.rs src/inventory.rs src/boot.rs src/cache.rs src/client_hello.rs src/connect.rs src/dns.rs src/eligibility.rs src/enforcement/action.rs src/enforcement/mod.rs src/enforcement/monitor.rs src/enforcement/policy.rs src/enforcement/state.rs src/gate.rs src/incident_report.rs src/log.rs src/runtime.rs src/schedule.rs src/serve.rs src/serving.rs src/startup_dns.rs src/worker.rs src/serving/policy.rs src/serving/reject.rs src/serving/startup.rs src/serving/tests.rs src/runtime/tests.rs src/startup_dns/tests.rs src/startup_dns/dot_tests.rs tests/foundations.rs tests/boot.rs tests/eligibility.rs tests/main_thread_stack.rs tests/mio_matrix.rs tests/monitor_stdout.rs tests/stdout_stall.rs"

# docslink gate roots: the exact nonempty argv docslink_check consumes. Shared
# with the identity snapshot so the boundary content identity covers precisely
# the bytes docslink_check reads (drift-proof by construction).
DOCSLINK_ROOTS="docs/alumina-proxy.md docs/architecture.md docs/verification.md docs/qa-package/README.md README.md"

# html-structure gate roots: structural artefacts docslink_check's Markdown
# parser cannot see (check.mjs answers unsupported-target/html-anchor-unsupported
# for HTML), so they get their own gate rather than a DOCSLINK_ROOTS entry.
HTML_DOC_ROOTS="docs/architecture.html"

# B1: every relevant before/after identity input consumed by the boundary run:
# source/config/lock/toolchain/deny plus the docs and .gitignore that
# docslink_check and the working-tree view consume. Changing build outputs (the
# compiled artifact) are intentionally excluded from this stability set and are
# recorded separately at executed output. README.md is already covered by
# INTENDED; the remaining DOCSLINK_ROOTS are added here so a gate-root edit
# cannot silently drop an identity input.
GATE_ROOT_EXTRAS=""
for root in $DOCSLINK_ROOTS; do
    case " $INTENDED " in
        *" $root "*) ;;
        *) GATE_ROOT_EXTRAS="$GATE_ROOT_EXTRAS $root" ;;
    esac
done
IDENTITY_FILES="$INTENDED .gitignore$GATE_ROOT_EXTRAS scripts/docs_check/check.mjs scripts/docs_check/package.json scripts/docs_check/package-lock.json scripts/docs_check/test.mjs scripts/html_check.mjs scripts/html_check_test.mjs $HTML_DOC_ROOTS"

# Snapshot locations live under target/ (gitignored) so they never alter the
# working-tree scope recorded in the status snapshot. scripts/verify.sh is itself
# an identity input (it is in INTENDED), so a mid-run edit of the coordinator is
# detectable by the same before/after comparison.
IDENTITY_BEFORE="target/identity-before"
IDENTITY_AFTER="target/identity-after"
PHASE1_SCOPE_MARKER="target/phase1-scope"

static_gate() {
    binfile="$1"
    [ -x "$binfile" ] || {
        echo "static-ELF FAIL: release binary missing: $binfile" >&2
        exit 1
    }
    dyn_rc=0
    dyn_out=$(readelf -d "$binfile" 2>&1) || dyn_rc=$?
    [ "$dyn_rc" -eq 0 ] || {
        echo "static-ELF FAIL: readelf -d exit $dyn_rc (probe failure is not PASS)" >&2
        exit 1
    }
    case "$dyn_out" in
        *NEEDED*)
            echo "static-ELF FAIL: dynamic NEEDED entries present" >&2
            exit 1
            ;;
    esac
    interp_rc=0
    interp_out=$(readelf -l "$binfile" 2>&1) || interp_rc=$?
    [ "$interp_rc" -eq 0 ] || {
        echo "static-ELF FAIL: readelf -l exit $interp_rc (probe failure is not PASS)" >&2
        exit 1
    }
    case "$interp_out" in
        *INTERP*)
            echo "static-ELF FAIL: PT_INTERP present" >&2
            exit 1
            ;;
    esac
    echo "STATIC-ELF-CHECKS-OK"
}

whitespace_gate() {
    command -v git >/dev/null 2>&1 || {
        echo "WHITESPACE-GATE-BLOCKED: git required and absent (no host proof receipt consumed)" >&2
        exit 1
    }
    # native git must see the actual mounted repository metadata, not a copy
    [ -f .git/HEAD ] || {
        echo "WHITESPACE-GATE-BLOCKED: .git/HEAD not visible (actual checkout required)" >&2
        exit 1
    }
    rc=0
    head=$(git rev-parse --verify HEAD 2>&1) || rc=$?
    [ "$rc" -eq 0 ] || {
        echo "WHITESPACE-GATE-BLOCKED: git rev-parse exit $rc (repository unreadable)" >&2
        exit 1
    }
    git diff --check || {
        echo "whitespace FAIL: tracked diff contains whitespace errors" >&2
        exit 1
    }
    # Missing-file fail-closed check FIRST (identical to the prior per-file
    # loop): every intended file must exist before any content scan.
    for f in $INTENDED; do
        [ -f "$f" ] || {
            echo "whitespace FAIL: intended file missing: $f" >&2
            exit 1
        }
    done
    # ONE awk pass over ALL intended files, checking every line (tracked and
    # untracked alike) for exactly what `git diff --no-index --check /dev/null
    # <file>` reports under the default core.whitespace: (a) trailing
    # whitespace, (b) space-before-tab in leading indent, (c) a new blank line
    # at EOF. Per-file/per-line diagnostics; any match fails the gate. awk is
    # required (busybox awk in the podman container).
    command -v awk >/dev/null 2>&1 || {
        echo "WHITESPACE-GATE-BLOCKED: awk required and absent (no host proof receipt consumed)" >&2
        exit 1
    }
    # The trailing/indent/blank classes carry CR (`\r`) exactly as git's
    # default core.whitespace set {space, tab, CR} does; `[[:space:]]` is NOT
    # used because it over-matches VT/FF/NEL/NBSP beyond git's set. Blank-at-EOF
    # matches git's exact semantics: a file of only blank lines is clean up to
    # two blank lines (dirty at three or more), and any trailing blank line
    # after a non-blank line is dirty. The blank-at-EOF state is flushed per
    # file: the FNR==1 block (guarded by NR>1) evaluates the PREVIOUS file's
    # EOF state when a new file starts, and END handles the final file — so
    # every intended file is checked, not just the last. The space-before-tab
    # indent class is `^[ \t]* \t` (no `\r`): git's indent scan stops at the
    # first non-space/tab char, so a leading CR ends the scan before any
    # space-before-tab can fire; CR is kept in the trailing class (CR-at-EOL is
    # dirty for git) and in the blank-line class (CR-only lines are blank).
    wsrc=0
    # shellcheck disable=SC2016
    wsprog='
        FNR == 1 {
            if (NR > 1 && (trailing_blank >= 3 || (seen_nonblank && trailing_blank >= 1))) { printf "whitespace FAIL: %s:%d: new blank line at EOF\n", f, lastnum; bad = 1 }
            f = FILENAME; lastnum = 0; seen_nonblank = 0; trailing_blank = 0
        }
        {
            if ($0 ~ /[ \t\r]+$/) { printf "whitespace FAIL: %s:%d: trailing whitespace\n", f, FNR; bad = 1 }
            if ($0 ~ /^[ \t]* \t/) { printf "whitespace FAIL: %s:%d: space before tab in indent\n", f, FNR; bad = 1 }
            if ($0 ~ /^[ \t\r]*$/) { trailing_blank++ } else { seen_nonblank = 1; trailing_blank = 0 }
            lastnum = FNR
        }
        END {
            if (trailing_blank >= 3 || (seen_nonblank && trailing_blank >= 1)) { printf "whitespace FAIL: %s:%d: new blank line at EOF\n", f, lastnum; bad = 1 }
            exit (bad ? 1 : 0)
        }
    '
    # shellcheck disable=SC2086
    wsout=$(awk "$wsprog" $INTENDED 2>&1) || wsrc=$?
    if [ "$wsrc" -ne 0 ]; then
        printf '%s\n' "$wsout" >&2
        echo "whitespace FAIL: intended files contain whitespace errors" >&2
        exit 1
    fi
    echo "WHITESPACE-GATE-OK (native git, HEAD=$head)"
}

# Reverse-dependent closure derivation: single-crate repo, cargo metadata
# names every package that links `alumina`; the closure is `alumina` itself.
closure_metadata() {
    cargo metadata --format-version 1 --locked >/dev/null
    echo "CLOSURE-OK (single-crate closure = alumina)"
}

mid_foundations() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "F0 static-Linux proof requires Linux execution" >&2
        exit 1
    }
    echo "WITNESS-TESTS (--features alloc-witness):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test foundations
    echo "WITNESS-OFF-TESTS (F2/F4 subset):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo +${TOOLCHAIN} fmt --check
    whitespace_gate
    echo "FOUNDATIONS-MID-OK"
}

mid_boot() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "boot mid requires Linux execution" >&2
        exit 1
    }
    echo "BOOT-TESTS (strict parser + validated types + storage inventory):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test boot
    echo "BOOT-TESTS-WITNESS (alloc retention bound):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test boot
    echo "FOUNDATIONS-REGRESSION:"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo +${TOOLCHAIN} fmt --check
    whitespace_gate
    echo "BOOT-MID-OK"
}

# Boundary-only union of the `mid foundations` and `mid boot` command sets
# (same input union), executed once each so the boundary never runs the
# highest-value native common commands twice (release build, static gate,
# foundations+boot tests with and without alloc-witness, fmt, clippy both
# variants, whitespace gate). The standalone `mid foundations` / `mid boot`
# selectors are the fast path (tests/fmt/whitespace only): clippy, the release
# build, and the static gate are deferred to this union and to the dedicated
# `mid clippy` selector; closure metadata runs only in this union. A quick
# per-sub-mission mid run skips the slow native common commands.
#
# Ordering: the clippy pair keeps the exact adjacency proven green by this
# union's clippy block (alloc-witness clippy immediately after production
# clippy, with the alloc-witness lib last built by the witness tests). The
# boot tests are intentionally deferred until AFTER the clippy
# block (diverging from `mid boot`, which runs them before clippy) so the
# alloc-witness boot tests never precede the alloc-witness clippy phase. That
# deliberate reorder avoids an aw-clippy-after-aw-boot-test adjacency in one
# cargo invocation, which can otherwise trip a clippy-per-target fingerprint
# E0463 (can't find crate for `alumina`) on the alloc-witness-only mio_matrix
# test over the shared persistent target dir.
# I1: the union now owns the WHOLE test surface for the candidate, once per
# feature config. previously: 4 `atest` invocations in this union (foundations
# and boot, each witness-off then witness-on) plus 2 more in `mid full`
# (gate-only suite), i.e. three invocations per feature config with cargo
# re-resolving the unit graph each time and the witness-on/off graphs competing
# for one target dir. now: one invocation per config covering lib units +
# foundations + boot + the 5 gate-only binaries, with a dedicated target dir per
# config.
#
# Ordering is NOT free-form. The documented hazard (E0463 "can't find crate for
# `alumina`" on an alloc-witness-only test target) is an aw-clippy-after-aw-test
# adjacency. The proven-green sequence in verify.sh is: clippy pair adjacent,
# with the aw test runs AFTER the aw clippy pass. That sequence is preserved
# here (non-aw clippy -> aw clippy -> aw tests), and the dedicated
# ${ALT_AW_TARGET_DIR} removes the shared-dir interference entirely.
ALT_TEST_TARGETS="--test foundations --test boot --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall"

mid_union() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "mid union requires Linux execution" >&2
        exit 1
    }
    closure_metadata
    echo "PRODUCTION-RELEASE-BUILD (boundary union, no alloc-witness):"
    cargo +${TOOLCHAIN} build --locked --release
    static_gate "target/release/alumina"
    echo "FMT:"
    cargo +${TOOLCHAIN} fmt --check
    echo "COMBINED-SUITE-WITNESS-OFF (lib units + foundations + boot + 5 gate-only binaries):"
    # shellcheck disable=SC2086
    cargo +${TOOLCHAIN} atest -p alumina --locked --lib $ALT_TEST_TARGETS
    echo "GATE-ONLY-SUITE-WITNESS-OFF-OK"
    echo "CLIPPY (production, no alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets -- -D warnings
    echo "CLIPPY (test-harness with alloc-witness; target dir ${ALT_AW_TARGET_DIR}):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --target-dir "$ALT_AW_TARGET_DIR" --all-targets --features alloc-witness -- -D warnings
    echo "COMBINED-SUITE-WITNESS-ON (lib units + foundations + boot + 5 gate-only binaries, alloc-witness):"
    # shellcheck disable=SC2086
    cargo +${TOOLCHAIN} atest -p alumina --locked --target-dir "$ALT_AW_TARGET_DIR" --features alloc-witness --lib $ALT_TEST_TARGETS
    echo "GATE-ONLY-SUITE-WITNESS-ON-OK"
    echo "GATE-ONLY-SUITE-MID-OK"
    whitespace_gate
    echo "UNION-MID-OK"
}

# Dedicated clippy selector: runs the alloc-witness foundations tests first so
# the alloc-witness lib is the last aw build, then the production clippy pass
# immediately followed by the alloc-witness clippy pass — the exact adjacency
# proven green by the `mid union` clippy block. No boot tests here: the
# aw boot tests are deferred to `mid union` AFTER the clippy block, keeping the
# aw-clippy-after-aw-boot-test adjacency (E0463 hazard) out of this selector.
mid_clippy() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "clippy mid requires Linux execution" >&2
        exit 1
    }
    echo "WITNESS-TESTS (--features alloc-witness, aw lib last build):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test foundations
    echo "CLIPPY (production, no alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets -- -D warnings
    echo "CLIPPY (test-harness with alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets --features alloc-witness -- -D warnings
    echo "CLIPPY-MID-OK"
}

# G8-C02 test-coverage closure: runs the gate-only test surface — lib unit tests
# + the 5 integration binaries that run in NO other selector (eligibility,
# mio_matrix, main_thread_stack, monitor_stdout, stdout_stall) — witness-off
# then witness-on, closing the gate coverage hole where lib units and these 5
# binaries never ran in any gate selector (all prior atest invocations carried
# --test foundations|boot). foundations and boot are NOT re-run here: they
# already run in mid union within the same BOUNDARY dispatch (and in the mid
# foundations / mid boot inner loops), so re-running them here would duplicate
# work without adding coverage.
# atest-only — no clippy/fmt/whitespace (those are mid_union's job) — so there
# is no E0463 hazard within this selector itself. The cross-run interaction is
# with a LATER mid_union's alloc-witness clippy over the shared target dir:
# mid_full's witness-on run builds the aw gate-only test binaries, whose
# fingerprints could meet mid_union's aw-clippy adjacency. Disposition
# (cross-run-safe verified or isolated via --target-dir) recorded in the
# sub-mission back-brief.
# I1: kept as a STANDALONE selector (the gate-only suite on its own). The
# boundary slow tier no longer dispatches it: `mid union` now covers this exact
# surface for the same candidate, so dispatching both would re-run 2 of 2 test
# invocations for zero extra coverage.
mid_full() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "mid full requires Linux execution" >&2
        exit 1
    }
    echo "GATE-ONLY-SUITE (lib units + 5 gate-only binaries, witness-off):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --lib --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall
    echo "GATE-ONLY-SUITE-WITNESS-OFF-OK"
    echo "GATE-ONLY-SUITE-WITNESS (lib units + 5 gate-only binaries incl. mio_matrix + eligibility witness, alloc-witness):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --target-dir "$ALT_AW_TARGET_DIR" --features alloc-witness --lib --test eligibility --test mio_matrix --test main_thread_stack --test monitor_stdout --test stdout_stall
    echo "GATE-ONLY-SUITE-WITNESS-ON-OK"
    echo "GATE-ONLY-SUITE-MID-OK"
}

# Linux kernel privilege fixtures. The proof-only `fixture-facts` feature build
# is executed (a clearly-separate variant artifact under target/fixture-facts;
# the production target/release artifact is left untouched, with before/after
# digest equality enforced) so the fixture binary prints its own kernel facts
# to stderr at actual entry. Each fixture runs that variant from the ro-mounted
# actual checkout (never a copy) from cwd=/work holding the fixed documented
# config/resolver inputs, under a different kernel-grounded process-attribute
# profile. Fixture stdout and stderr are captured as separate streams: a
# negative fixture requires EMPTY stdout and byte-exact stderr (exact facts line
# plus exact diagnostic); the positive fixture requires the exact banner line on
# stdout (legitimate inventory retained) and byte-exact stderr facts; each
# asserts the integer exit (0 / EX_CONFIG 78). A metadata probe rejects a setid
# mode, proves security.capability absence + variant digest match on the
# executed variant via the xattr filesystem API, with probe errors kept
# distinct from verified absence.
# Quick reference:
#   PODMAN_CONNECTION       rootless builder (required)
#   PODMAN_ROOT_CONNECTION  rootful builder for --cap-add probes (required)
boot_fixtures() {
    command -v podman >/dev/null 2>&1 || {
        echo "BOOT-FIXTURES-BLOCKED: podman required on the host" >&2
        exit 1
    }
    CONN="${PODMAN_CONNECTION:?PODMAN_CONNECTION must be set to your rootless podman connection}"
    ROOTCONN="${PODMAN_ROOT_CONNECTION:?PODMAN_ROOT_CONNECTION must be set to your rootful podman connection}"
    ROOT="$(pwd)"
    podman --connection "$CONN" info >/dev/null 2>&1 || {
        echo "BOOT-FIXTURES-BLOCKED: cannot reach podman connection $CONN" >&2
        exit 1
    }
    IMAGE="docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a"
    # Fail closed: a missing image or rootful connection is a BLOCKER, never a
    # silent SKIP->0. The capability-set axes below are kernel fixtures that
    # require the actual container privileges.
    podman --connection "$CONN" image exists "$IMAGE" || {
        echo "BOOT-FIXTURES-BLOCKED: builder image absent on $CONN; pull required" >&2
        exit 1
    }
    podman --connection "$ROOTCONN" info >/dev/null 2>&1 || {
        echo "BOOT-FIXTURES-BLOCKED: cannot reach rootful connection $ROOTCONN" >&2
        exit 1
    }
    podman --connection "$ROOTCONN" image exists "$IMAGE" || {
        echo "BOOT-FIXTURES-BLOCKED: builder image absent on $ROOTCONN; pull required" >&2
        exit 1
    }
    # I3: fixtures run on a digest-pinned image that already carries util-linux,
    # python3 and git, so no fixture performs an `apk add` (network) inside the
    # measured path. The image is built once FROM the same pinned rust base used
    # by the build dispatch, so its provenance is a strict superset of the base
    # the fixture proofs were accepted against.
    ensure_fixture_image "$CONN"
    ensure_fixture_image "$ROOTCONN"
    fixture_id=$(podman --connection "$CONN" image inspect --format '{{.Id}}' "$FIXTURE_IMAGE" 2>/dev/null) || fixture_id=""
    [ -n "$fixture_id" ] || {
        echo "BOOT-FIXTURES-BLOCKED: fixture image '$FIXTURE_IMAGE' id unresolvable on $CONN (probe failure is not PASS)" >&2
        exit 1
    }
    echo "  fixture image $FIXTURE_IMAGE id=$fixture_id (base $FIXTURE_BASE_IMAGE)"
    BIN="target/release/alumina"
    [ -x "$ROOT/$BIN" ] || {
        echo "BOOT-FIXTURES-BLOCKED: static binary missing ($BIN); run 'verify.sh mid union' first" >&2
        exit 1
    }
    release_sha_before=$(sha256_digest file "$ROOT/$BIN") || exit 1
    echo "BUILD fixture-facts variant (proof-only feature; separate target dir; production artifact untouched):"
    _bf_t0=$(now_ms)
    linux_dispatch 'cargo +${TOOLCHAIN} build --release --locked --features fixture-facts --target-dir target/fixture-facts'
    # I2/I4: the variant target dir lives in the VM-native volume, so only the
    # built artifact is copied out. Its digest is asserted on both sides of the
    # copy: the executed variant is the identified variant.
    copy_out_artifact "fixture-facts/release/alumina" "target/fixture-facts/release/alumina" || exit 1
    _bf_t1=$(now_ms)
    case "${_bf_t0}${_bf_t1}" in
        *NA*) phase_mark "fixtures.variant-build" NA ;;
        *) phase_mark "fixtures.variant-build" "$((_bf_t1 - _bf_t0))ms" ;;
    esac
    VARBIN="$ROOT/target/fixture-facts/release/alumina"
    [ -x "$VARBIN" ] || {
        echo "BOOT-FIXTURES-BLOCKED: fixture-facts variant binary missing after build" >&2
        exit 1
    }
    variant_sha=$(sha256_digest file "$VARBIN") || exit 1
    release_sha_after=$(sha256_digest file "$ROOT/$BIN") || exit 1
    # In-run fresh-variant marker: record the exact variant this run built next
    # to the artifact so docs/qa-package/validate.sh can prove the exercised binary
    # has current-run provenance (never a stale by-existing pass). Written every
    # run, unconditionally, after the rebuild.
    printf '%s\n' "$variant_sha" > "$ROOT/target/fixture-facts/release/variant.sha256"
    echo "  fresh-variant marker (in-run build): $ROOT/target/fixture-facts/release/variant.sha256 = $variant_sha"
    echo "  fixture-facts variant sha256 $variant_sha"
    # Production before/after equality is an explicit gate, never a printed
    # observation: the proof-only variant build must not touch the production
    # artifact (unr B4).
    if [ "$release_sha_before" = "$release_sha_after" ]; then
        echo "  production release sha256 $release_sha_after (before build $release_sha_before; unchanged)"
    else
        echo "BOOT-FIXTURES FAIL: production artifact digest changed across variant build ($release_sha_before -> $release_sha_after)" >&2
        exit 1
    fi

    # write the fixed documented inputs into a disposable container /work dir
    # (cwd-relative contract: main.rs reads config.toml, incl. the resolver
    # set, from the working directory), then drop privileges inside that dir.
    # I3: no package install here any more. util-linux (setpriv), python3 and git
    # are baked into the digest-pinned fixture image, so a fixture case performs
    # no network I/O and cannot fail on a flaky mirror.
    stage() {
        printf '%s\n' \
            'set -eu' \
            'mkdir -p /work' \
            "printf '%s\\n' 'listen = \"0.0.0.0:8080\"' 'startup_unresolved_allowance = 0' 'resolver = [\"127.0.0.1\"]' '[any_illegal]' 'connect_parse = { action = \"notify\", scope = \"connection\" }' 'host_not_allowlisted = { action = \"notify\", scope = \"connection\" }' 'tls_profile = { action = \"notify\", scope = \"connection\" }' 'ech = { action = \"notify\", scope = \"connection\" }' '[allowed_fqdn.\"example.com:443\"]' 'early_data = { action = \"notify\", scope = \"connection\" }' 'ja4 = { action = \"notify\", scope = \"connection\" }' > /work/config.toml" \
            'chown -R 65534:65534 /work'
        true
    }

    outf=$(mktemp) || exit 1
    errf=$(mktemp) || exit 1
    trap 'rm -f "$outf" "$errf"' EXIT

    run_fixture() {
        label="$1"
        expected="$2"
        conn="$3"
        shift 3
        run_cmd="$1"
        shift
        FIXTURE_LABEL="$label"
        > "$outf"
        > "$errf"
        set +e
        podman --connection "$conn" run --rm --pull=never \
            -v "$ROOT:/app:ro,Z" \
            $(target_volume_mount) \
            "$@" "$FIXTURE_IMAGE" sh -c "$(stage) && $run_cmd" >"$outf" 2>"$errf"
        rc=$?
        set -e
        FIXTURE_OUTF="$outf"
        FIXTURE_ERRF="$errf"
        echo "FIXTURE $label: exit=$rc"
        sed 's/^/  out>/' "$outf"
        sed 's/^/  err>/' "$errf"
        case "$rc" in
            "$expected") ;;
            *) echo "FIXTURE $label FAIL: expected exit $expected, got $rc" >&2; exit 1 ;;
        esac
    }

    # Stream-discipline predicates (unr B3): stdout and stderr are retained as
    # raw files (never command substitution, which strips trailing newline
    # bytes). Negative stdout must be an EMPTY file - any captured byte, even
    # newline-only, fails. Exact-line checks use grep -Fx whole-line match on
    # the retained stdout; byte-exact stderr is a cmp against an explicitly
    # newline-terminated expected file, so an extra or missing trailing newline
    # fails.
    fixture_require_stdout_empty() {
        if [ -s "$FIXTURE_OUTF" ]; then
            echo "FIXTURE $FIXTURE_LABEL FAIL: expected empty stdout, got:" >&2
            sed 's/^/  /' "$FIXTURE_OUTF" >&2
            exit 1
        fi
    }

    fixture_require_stdout_exact() {
        line="$1"
        grep -Fx -- "$line" "$FIXTURE_OUTF" >/dev/null || {
            echo "FIXTURE $FIXTURE_LABEL FAIL: stdout lacks exact line: $line" >&2
            exit 1
        }
    }

    fixture_require_stderr_exact() {
        expected="$1"
        expectf=$(mktemp) || exit 1
        printf '%s\n' "$expected" > "$expectf"
        cmp -s "$FIXTURE_ERRF" "$expectf" || {
            echo "FIXTURE $FIXTURE_LABEL FAIL: stderr not byte-exact." >&2
            echo "  expected:" >&2
            sed 's/^/    /' "$expectf" >&2
            echo "  got:" >&2
            sed 's/^/    /' "$FIXTURE_ERRF" >&2
            rm -f "$expectf"
            exit 1
        }
        rm -f "$expectf"
    }

    # Fixed-string stdout probes against the captured fixture stdout. The
    # script runs under `set -eu`, and `$?` is only reliably observed through
    # an if/else guard (a bare `grep; rc=$?` is killed by set -e the instant
    # grep is nonzero -- no-match for not_contains is the REQUIRED outcome, so
    # it must never die silently). Probe error stays distinct from absence:
    # contains passes only on a match and diagnoses a probe error;
    # not_contains passes only on the documented no-match exit (1), and a
    # probe error (2) is a FAIL -- absence is never inferred from an
    # unreadable or failed probe stream.
    fixture_require_stdout_contains() {
        fragment="$1"
        if grep -Fq -- "$fragment" "$FIXTURE_OUTF"; then
            rc=0
        else
            rc=$?
        fi
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
        if [ "$rc" -eq 2 ]; then
            echo "FIXTURE $FIXTURE_LABEL ERROR: stdout probe failed (exit 2); required fragment unverifiable: $fragment" >&2
        else
            echo "FIXTURE $FIXTURE_LABEL FAIL: stdout lacks fixed-string fragment: $fragment" >&2
        fi
        exit 1
    }

    fixture_require_stdout_not_contains() {
        fragment="$1"
        if grep -Fq -- "$fragment" "$FIXTURE_OUTF"; then
            rc=0
        else
            rc=$?
        fi
        case "$rc" in
            1)
                return 0
                ;;
            0)
                echo "FIXTURE $FIXTURE_LABEL FAIL: stdout must not contain fixed-string fragment: $fragment" >&2
                exit 1
                ;;
            *)
                echo "FIXTURE $FIXTURE_LABEL ERROR: stdout probe failed (exit $rc); absence not established: $fragment" >&2
                exit 1
                ;;
        esac
    }

    # 1) POSITIVE: NoNewPrivs=1, process dropped to uid 65534 with empty cap
    #    sets. The fixture-facts variant runs the CURRENT serving startup under
    #    the approved privilege profile. The resolver points at loopback where
    #    nothing listens (deterministic connection-refused; no environment
    #    network dependency), so the 90 s window cannot short-close on an early
    #    serve decision. A supervisor then signals the mid-window process with
    #    a real SIGTERM and bounded-waits for its exit: the startup window
    #    settles the typed terminated outcome (startup_final status="terminated",
    #    no listener bound), a clean shutdown drain emits shutdown_final
    #    status="drained", and the child exits 0 -- never the obsolete
    #    non-serving scaffold banner, never a hung serve (a child still alive
    #    after signal + 10 s fails the fixture; a supervised-child deadline is
    #    a FAIL, never a pass). The binary's own entry facts (all four sets
    #    empty, NNP set) then the boot-time resolver trust warning (W7-H7a-F2)
    #    must be the exact stderr.
    pos_script=$(cat <<'POSPOS'
cd /work
/app/target/fixture-facts/release/alumina &
pid=$!
sleep 3
kill -TERM "$pid" 2>/dev/null || true
i=0
while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 10 ]; do i=$((i+1)); sleep 1; done
if kill -0 "$pid" 2>/dev/null; then
    echo "FIXTURE-POSITIVE-FAIL: supervised serving child alive after SIGTERM + 10s"
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    exit 2
fi
if wait "$pid"; then rc=0; else rc=$?; fi
printf "FIXTURE-POSITIVE-SUPERVISED: reaped child rc=%s\n" "$rc"
exit "$rc"
POSPOS
)
    run_fixture "positive" 0 "$CONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c '$pos_script'" \
        --security-opt no-new-privileges --user 0:0
    # The typed records prove the actual startup-serving/typed-terminal path:
    # the window ended on the terminated decision and the drain was clean. The
    # obsolete non-serving scaffold banner is barred: its presence would be the
    # false-clean this migration removes.
    fixture_require_stdout_contains "level=info kind=startup_final"
    fixture_require_stdout_contains 'status="terminated"'
    fixture_require_stdout_contains "level=info kind=shutdown_final"
    fixture_require_stdout_contains 'status="drained"'
    fixture_require_stdout_contains "FIXTURE-POSITIVE-SUPERVISED: reaped child rc=0"
    fixture_require_stdout_not_contains "PHASE1-BOOT-OK"
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=0 cap_prm=0 cap_amb=0 no_new_privs=1" \
        "alumina: warning: resolver 127.0.0.1 has no FQDN (IP#fqdn) metadata; plain DNS over port 53 only — the DoT (853) SNI/SAN identity surface is unavailable")"

    # 2) ROOT: euid 0 -> EX_CONFIG 78 (root-UID diagnostic); all four UID axes
    #    reported zero at entry. Negative fixtures must have EMPTY stdout and
    #    byte-exact stderr: exactly the facts line then the diagnostic.
    run_fixture "root-rejected" 78 "$CONN" \
        "cd /work && /app/target/fixture-facts/release/alumina" \
        --security-opt no-new-privileges --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=0 euid=0 suid=0 fsuid=0 cap_eff=800405fb cap_prm=800405fb cap_amb=0 no_new_privs=1" \
        "alumina: prerequisite failure: process has a root UID (real/effective/saved/filesystem)")"

    # 3) NNP-MISSING: no no_new_privs flag -> EX_CONFIG 78 (missing-flag
    #    diagnostic); caps empty, uid dropped.
    run_fixture "no-new-privs-missing" 78 "$CONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c 'cd /work && /app/target/fixture-facts/release/alumina'" \
        --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=0 cap_prm=0 cap_amb=0 no_new_privs=0" \
        "alumina: prerequisite failure: no_new_privs not set")"

    # 4) CAPS-EFFECTIVE: rootful container grants cap_net_admin into the
    #    bounding set; setpriv raises it into inheritable+ambient so the
    #    dropped uid 65534 process execs with CapEff/CapPrm/CapAmb non-empty.
    #    Preflight checks effective first -> EX_CONFIG 78 with the
    #    non-empty-effective-capability-set diagnostic. The binary's own entry
    #    facts observe all three capability sets non-empty (0x1000 each),
    #    asserting effective-first refusal rather than per-axis isolation.
    run_fixture "caps-effective" 78 "$ROOTCONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups --inh-caps=+net_admin --ambient-caps=+net_admin /bin/sh -c 'cd /work && /app/target/fixture-facts/release/alumina'" \
        --security-opt no-new-privileges --cap-add NET_ADMIN --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=1000 cap_prm=1000 cap_amb=1000 no_new_privs=1" \
        "alumina: prerequisite failure: non-empty effective capability set")"

    # 5) PERMITTED-ONLY APPLICABILITY (corrects the earlier KEEP_CAPS/capsh
    #    VM rationale per authoritative evidence alumina-5zn + orientation
    #    alumina-mlb): for a non-root exec of an ordinary non-setid executable
    #    WITHOUT file capabilities, the kernel execve rule gives
    #    P'(permitted) = P'(effective) = P(ambient) (capabilities(7);
    #    commoncap.c v6.6). A non-root exec clears pre-existing
    #    permitted/effective, so CapEff=0 with CapPrm non-zero is NOT reachable
    #    at this binary entry; with empty ambient all sets are empty, with
    #    non-empty ambient all three are non-empty together (fixture 4
    #    observes exactly this). Ambient-only is likewise unreachable because
    #    ambient always feeds both permitted and effective (no independent
    #    isolation axis exists for this executable). SECBIT_KEEP_CAPS is
    #    cleared on execve and is not a permitted-retention mechanism. The
    #    kernel nonempty-permitted and nonempty-ambient refusal policy is
    #    UNCHANGED; each synthetic axis is asserted independently below by the
    #    unchanged decision-table unit test.
    echo "FIXTURE permitted-only: APPLICABILITY (alumina-5zn) - ordinary non-setid no-file-cap exec gives P'=E'=ambient; isolated CapEff=0/CapPrm!=0 not reachable; ambient-only not reachable"
    echo "FIXTURE permitted-only: kernel nonempty-permitted and nonempty-ambient refusal policy UNCHANGED; decision-table unit test preflight_rejects_each_unmet_prerequisite_independently asserts each axis"

    # 6) METADATA: authoritative Linux xattr proof on the executed variant
    #    (same inode the fixtures ran) that security.capability is absent -
    #    via the xattr filesystem API, never getcap-output-absence - plus file
    #    mode and artifact sha256. The probe also rejects a setid mode (the
    #    ordinary-nonsetid applicability is void for a setid executable) and a
    #    digest differing from the identified variant sha. Probe errors
    #    (stat/listxattr/getxattr failure, non-regular file) are BLOCKERS,
    #    never verified absence.
    echo "METADATA (setid-reject + security.capability absence + mode + variant sha256 match on executed variant):"
    metar=0
    metaout=$(podman --connection "$CONN" run --rm --pull=never \
        -v "$ROOT:/app:ro,Z" \
        $(target_volume_mount) \
        --user 0:0 "$FIXTURE_IMAGE" \
        sh -c 'python3 /app/scripts/fixture_metadata_probe.py /app/target/fixture-facts/release/alumina "$1"' -- "$variant_sha" 2>&1) || metar=$?
    printf '%s\n' "$metaout" | sed 's/^/  /'
    [ "$metar" -eq 0 ] || {
        echo "BOOT-FIXTURES FAIL: metadata probe exit $metar (probe error / setid / digest mismatch is not verified absence)" >&2
        exit 1
    }
    printf '%s\n' "$metaout" | grep -qF "security.capability=absent" || {
        echo "BOOT-FIXTURES FAIL: executed variant carries security.capability (or record missing)" >&2
        exit 1
    }
    echo "METADATA-OK: executed variant ordinary non-setid, security.capability absent, sha256 matches $variant_sha"

    echo "BOOT-FIXTURES-RAN (separate-stream capture; negative stdout empty + stderr byte-exact facts+diagnostic; positive supervised typed-terminated startup record (startup_final status=terminated + shutdown_final status=drained, reaped exit 0) with retained stdout; integer exit 0/78; all cap sets observed non-empty in caps-effective; permitted-only applicability disposition; production digest unchanged; setid-reject + security.capability absence + variant sha256 match proven)"
}

# One effective Node environment preflight: refuse ANY set NODE_OPTIONS/NODE_PATH
# -- non-empty or empty alike -- before ANY Node invocation (the docs adapter and
# the boundary identity version probe), because a set option is an explicit
# execution-affecting override even when empty. An unset variable is the only
# accepted state.
node_env_preflight() {
    if [ -n "${NODE_OPTIONS+x}" ]; then
        echo "NODE-REFUSED: NODE_OPTIONS is set (${NODE_OPTIONS}); execution-affecting Node options not covered by default-condition intake" >&2
        exit 1
    fi
    if [ -n "${NODE_PATH+x}" ]; then
        echo "NODE-REFUSED: NODE_PATH is set (${NODE_PATH}); execution-affecting module resolution not covered by default-condition intake" >&2
        exit 1
    fi
}

docslink_check() {
    # Offline AST + authoritative slugger adapter (scripts/docs_check/check.mjs):
    # fixed argv, literal fragment lookup, distinct operational failure. Document
    # bytes are filesystem data passed to node; they never reach a shell here.
    command -v node >/dev/null 2>&1 || {
        echo "DOCSLINK-BLOCKED: node required for offline AST docs check (absent)" >&2
        exit 1
    }
    [ -f scripts/docs_check/check.mjs ] || {
        echo "DOCSLINK-BLOCKED: scripts/docs_check/check.mjs missing (no docs check)" >&2
        exit 1
    }
    node_env_preflight
    drc=0
    docs_out="$(node scripts/docs_check/check.mjs $DOCSLINK_ROOTS)" || drc=$?
    [ -n "$docs_out" ] && printf '%s\n' "$docs_out"
    case "$drc" in
        0) ;;
        1)
            echo "DOCSLINK-CHECK-FAIL or CITATION-CHECK-FAIL (missing file/fragment or unresolvable/out-of-range citation)" >&2
            exit 1
            ;;
        2)
            echo "DOCSLINK-CHECK-OP-FAIL or CITATION-CHECK-OP-FAIL (operational or unsupported construct)" >&2
            exit 2
            ;;
        *)
            echo "DOCSLINK-CHECK-FAIL (adapter exit $drc)" >&2
            exit 1
            ;;
    esac
    # Fail closed on the citation marker: a green adapter must have proven the
    # corpus citations resolve and are in range (the marker line is the proof).
    if ! printf '%s\n' "$docs_out" | grep -q '^CITATION-CHECK-OK '; then
        echo "CITATION-CHECK-BLOCKED: adapter exit 0 but no CITATION-CHECK-OK marker" >&2
        exit 2
    fi
    echo "DOCSLINK-CHECK-OK"
    echo "CITATION-CHECK-OK"
}

html_structure_check() {
    # Offline Node-builtins structural gate for HTML artefacts
    # (scripts/html_check.mjs): tag balance, duplicate ids, internal fragment
    # closure, figure <desc> presence, and table cell-count consistency. The
    # adapter's exit is captured unmasked (one-way split: operational failures
    # never fold into 0/1); its output is printed verbatim.
    command -v node >/dev/null 2>&1 || {
        echo "HTML-STRUCTURE-BLOCKED: node required for HTML structure check (absent)" >&2
        exit 1
    }
    [ -f scripts/html_check.mjs ] || {
        echo "HTML-STRUCTURE-BLOCKED: scripts/html_check.mjs missing (no HTML structure check)" >&2
        exit 1
    }
    node_env_preflight
    hrc=0
    html_out="$(node scripts/html_check.mjs $HTML_DOC_ROOTS)" || hrc=$?
    [ -n "$html_out" ] && printf '%s\n' "$html_out"
    case "$hrc" in
        0)
            # fail closed on the marker: a green adapter that checked nothing
            # (no HTML-CHECK-OK line per root) is a blocked gate, not a pass.
            for _html_root in $HTML_DOC_ROOTS; do
                if ! printf '%s\n' "$html_out" | grep -q "^HTML-CHECK-OK $_html_root "; then
                    echo "HTML-STRUCTURE-BLOCKED: adapter exit 0 but no HTML-CHECK-OK for $_html_root" >&2
                    exit 2
                fi
            done
            ;;
        1)
            # The adapter emits HTML-CHECK-RESULT on every non-crash path, so on
            # exit 1 the marker must be present before this is a structural
            # defect. A missing marker means the adapter crashed (uncaught
            # throw, syntax error): an operational failure, not a domain-negative
            # verdict (error != negative finding).
            if printf '%s\n' "$html_out" | grep -q '^HTML-CHECK-RESULT '; then
                echo "HTML-STRUCTURE-FAIL (structural HTML defect: tag imbalance, duplicate id, dangling fragment, missing desc, or table cell-count mismatch)" >&2
                exit 1
            fi
            echo "HTML-STRUCTURE-OP-FAIL (adapter exit 1 without an HTML-CHECK-RESULT marker)" >&2
            exit 2
            ;;
        2)
            echo "HTML-STRUCTURE-OP-FAIL (operational or unsupported construct: unreadable file or unsupported HTML markup)" >&2
            exit 2
            ;;
        *)
            echo "HTML-STRUCTURE-FAIL (adapter exit $hrc)" >&2
            exit 1
            ;;
    esac
    echo "HTML-CHECK-OK"
}

unsafe_surface_gate() {
    # F3 (08-tooling-ci-scripts): file-level unsafe-surface confinement. The
    # `unsafe` keyword is allowed ONLY in the production surface — src/alloc.rs
    # and files under tests/ — and in #[cfg(test)] unit-test modules
    # under src/ (src/*/tests.rs, src/*/dot_tests.rs), whose test-only `unsafe`
    # never compiles into the production binary. Any other *.rs file containing
    # the keyword fails closed, naming the offender(s). Read-only host-side
    # check; no builds. rg is preferred; a grep -R fallback covers hosts without
    # rg. target/ and .git are excluded (gitignored for rg, explicit for grep);
    # the grep fallback also excludes .ooda/ so gitignored scratch never trips
    # the gate.
    # Producer exit is captured (cf. sha256_digest): rg/grep exit 1 = no match
    # (clean); any exit >= 2 is a tooling error and fails closed, never passing
    # on an empty offender list.
    offenders=""
    scan_rc=0
    if command -v rg >/dev/null 2>&1; then
        offenders="$(rg -l '\bunsafe\b' --glob '*.rs' --glob '!target/**' 2>/dev/null)" || scan_rc=$?
    else
        offenders="$(grep -Rl --include='*.rs' --exclude-dir=target --exclude-dir=.git --exclude-dir=.ooda -E '\bunsafe\b' . 2>/dev/null)" || scan_rc=$?
        offenders=$(printf '%s\n' "$offenders" | sed 's#^\./##')
    fi
    [ "$scan_rc" -lt 2 ] || {
        echo "UNSAFE-SURFACE-SCAN-FAIL: unsafe scan producer exit $scan_rc (tooling error, not PASS)" >&2
        exit 1
    }
    bad=""
    for f in $offenders; do
        case "$f" in
            src/alloc.rs|tests/*|src/*/tests.rs|src/*/dot_tests.rs) ;;
            *) bad="$bad $f" ;;
        esac
    done
    if [ -n "$bad" ]; then
        echo "UNSAFE-SURFACE-FAIL: 'unsafe' outside allowlist (prod surface: src/alloc.rs, tests/*; cfg(test) unit modules: src/*/tests.rs, src/*/dot_tests.rs):$bad" >&2
        exit 1
    fi
    echo "UNSAFE-SURFACE-OK: unsafe confined to prod surface src/alloc.rs, tests/* and cfg(test) unit modules src/*/tests.rs, src/*/dot_tests.rs"
}

# F-new (gate-surface-truth M1): the reviewed identity set (INTENDED) must cover
# EVERY tracked src/**/*.rs and tests/*.rs file. A tracked file absent from
# INTENDED sits outside every identity snapshot and can drift (accumulate
# unsafe, behaviour, …) while the boundary identity checks stay green. Producer
# is git ls-files with its exit captured: a tooling failure (exit >= 2) fails
# closed and can never read as a PASS on an empty offender list.
intended_coverage_gate() {
    lsrc=0
    tracked_rs="$(git ls-files 'src/**/*.rs' 'src/*.rs' 'tests/*.rs' 2>&1)" || lsrc=$?
    [ "$lsrc" -lt 2 ] || {
        echo "INTENDED-COVERAGE-FAIL: git ls-files exit $lsrc (tooling error, not PASS)" >&2
        exit 1
    }
    missing=""
    for f in $tracked_rs; do
        case " $INTENDED " in
            *" $f "*) ;;
            *) missing="$missing $f" ;;
        esac
    done
    if [ -n "$missing" ]; then
        echo "INTENDED-COVERAGE-FAIL: tracked src/tests .rs absent from INTENDED (drifts outside every identity snapshot):$missing" >&2
        exit 1
    fi
    echo "INTENDED-COVERAGE-OK: every tracked src/**/*.rs and tests/*.rs is listed in INTENDED"
}

# F-new (gate-surface-truth M1, closes assurance alumina-ajyok): an admitted
# src/*/tests.rs or src/*/dot_tests.rs is trusted as test-only unsafe surface
# ONLY if the parent module (resolved <dir>.rs, else <dir>/mod.rs) declares the
# module under #[cfg(test)]. A filename-only admission would let a production
# `mod tests;` (whose unsafe compiles into the binary) pass the unsafe gate.
# This is not a filename-only rule: it asserts the actual cfg(test) attribute
# adjacent to the mod declaration in the parent. Enumerated via find over the
# working tree (same universe as the unsafe scan, untracked included), exit
# captured so a scan failure fails closed and never reads as PASS.
cfg_test_parentage_gate() {
    fsrc=0
    umods="$(find src -mindepth 2 -maxdepth 2 -type f \( -name 'tests.rs' -o -name 'dot_tests.rs' \) 2>/dev/null)" || fsrc=$?
    [ "$fsrc" -eq 0 ] || {
        echo "CFG-TEST-PARENTAGE-SCAN-FAIL: unit-module scan producer exit $fsrc (tooling error, not PASS)" >&2
        exit 1
    }
    pg_bad=""
    for m in $umods; do
        dir=$(printf '%s' "$m" | sed 's#^src/\([^/]*\)/.*#\1#')
        stem=$(basename "$m" .rs)
        if [ -f "src/$dir.rs" ]; then
            parent="src/$dir.rs"
        elif [ -f "src/$dir/mod.rs" ]; then
            parent="src/$dir/mod.rs"
        else
            pg_bad="$pg_bad $m(no parent module)"
            continue
        fi
        # Assert the parent carries a #[cfg(test)] attribute immediately (modulo
        # blank lines) preceding `mod <stem>;`. A bare production `mod <stem>;`
        # without the attribute must NOT satisfy this rule. Single-line
        # `#[cfg(test)] mod <stem>;` and two-line forms are both recognised.
        prc=0
        decl=$(awk -v stem="$stem" '
            {
                if (!found && $0 ~ ("^[[:space:]]*#\\[cfg\\(test\\)\\][[:space:]]*mod[[:space:]]+" stem "[[:space:]]*;")) { found = 1; next }
                if (!found && $0 ~ /^[[:space:]]*#\[cfg\(test\)\]/) { pending = 1; next }
                if (pending && $0 ~ /^[[:space:]]*$/) next
                if (pending && $0 ~ ("^[[:space:]]*mod[[:space:]]+" stem "[[:space:]]*;")) found = 1
                pending = 0
            }
            END { print (found ? "ok" : "missing") }
        ' "$parent" 2>&1) || prc=$?
        [ "$prc" -eq 0 ] || {
            echo "CFG-TEST-PARENTAGE-FAIL: awk producer exit $prc on $parent (tooling error, not PASS)" >&2
            exit 1
        }
        [ "$decl" = "ok" ] || pg_bad="$pg_bad $m(parent:$parent not #[cfg(test)]-declared)"
    done
    if [ -n "$pg_bad" ]; then
        echo "CFG-TEST-PARENTAGE-FAIL: admitted unit-test modules not declared under #[cfg(test)] by parent:$pg_bad" >&2
        exit 1
    fi
    echo "CFG-TEST-PARENTAGE-OK: every admitted src/*/tests.rs and src/*/dot_tests.rs is #[cfg(test)]-declared by its parent"
}

# Canonical-spec digest control (gate-surface-truth M2, canonical-digest-20261028).
# The governing spec must be pinned, not asserted: AGENTS.md is the single
# doctrine surface that carries the pin (the spec file is never edited), so the
# gate READS the pin out of AGENTS.md and fails closed if it cannot parse it
# (CANONICAL-DIGEST-PIN-MISSING) — exactly one full 64-hex token on the line
# marked "sha256". The actual digest is computed by the single authoritative
# hasher (sha256_digest: hasher exit captured, empty digest rejected), so a
# broken or missing hasher can never read as PASS. On mismatch BOTH digests and
# the re-pin protocol are printed: a control that never recomputes is prose, and
# the message must state its own maintenance.
canonical_digest_gate() {
    cg_prc=0
    pins="$(sed -n 's/.*sha256[[:space:]]\{1,\}[^0-9a-f]*\([0-9a-f]\{64\}\).*/\1/p' AGENTS.md 2>&1)" || cg_prc=$?
    [ "$cg_prc" -eq 0 ] || {
        echo "CANONICAL-DIGEST-PIN-MISSING: AGENTS.md pin extraction failed (producer exit $cg_prc, not PASS)" >&2
        exit 1
    }
    npin=0
    for _p in $pins; do npin=$((npin + 1)); done
    [ "$npin" -eq 1 ] || {
        echo "CANONICAL-DIGEST-PIN-MISSING: expected exactly one 64-hex sha256 pin in AGENTS.md, found ${npin}; re-pin AGENTS.md with the spec's real digest in the same commit as the authorised spec change (not PASS)" >&2
        exit 1
    }
    pin=$pins
    actual="$(sha256_digest file "docs/alumina-proxy.md")" || {
        echo "CANONICAL-DIGEST-GATE-FAIL: spec digest could not be computed (hasher failure, not PASS)" >&2
        exit 1
    }
    if [ "$pin" != "$actual" ]; then
        echo "CANONICAL-DIGEST-FAIL: docs/alumina-proxy.md sha256 does not match the AGENTS.md pin" >&2
        echo "  expected: $pin  (pin in AGENTS.md)" >&2
        echo "  actual:   $actual  (docs/alumina-proxy.md)" >&2
        echo "  update protocol: an authorised spec change re-pins AGENTS.md in the same commit" >&2
        exit 1
    fi
    echo "CANONICAL-DIGEST-OK: docs/alumina-proxy.md sha256 matches the AGENTS.md pin ($pin)"
}

# One authoritative SHA256 operation for every identity input. Selection:
# sha256sum preferred, else shasum -a 256 (a SHA256 field must carry real
# SHA256, never shasum's default SHA1). The producer exit and a non-empty
# digest are both checked inside this function; callers see only the bare hex
# digest or a non-zero status, so a missing or failed hasher can never become
# an empty string carried by a masking pipeline. mode=file hashes the path in
# $2; mode=stdin hashes stdin. The selected hasher name is exposed in
# IDENTITY_HASHER for the env record.
sha256_digest() {
    mode="$1"
    path="${2:-}"
    IDENTITY_HASHER=""
    r=0
    out=""
    if command -v sha256sum >/dev/null 2>&1; then
        IDENTITY_HASHER="sha256sum"
        if [ "$mode" = "file" ]; then out=$(sha256sum "$path" 2>&1) || r=$?
        else out=$(sha256sum 2>&1) || r=$?; fi
    elif command -v shasum >/dev/null 2>&1; then
        IDENTITY_HASHER="shasum"
        if [ "$mode" = "file" ]; then out=$(shasum -a 256 "$path" 2>&1) || r=$?
        else out=$(shasum -a 256 2>&1) || r=$?; fi
    else
        echo "SOURCE-IDENTITY FAIL: neither sha256sum nor shasum present (identity impossible, not PASS)" >&2
        return 1
    fi
    [ "$r" -eq 0 ] || {
        echo "SOURCE-IDENTITY FAIL: hash producer exit $r for ${path:-stdin} (read failure, not PASS)" >&2
        printf '%s\n' "$out" >&2
        return 1
    }
    digest=$(printf '%s\n' "$out" | cut -d' ' -f1)
    [ -n "$digest" ] || {
        echo "SOURCE-IDENTITY FAIL: empty digest for ${path:-stdin} (not PASS)" >&2
        return 1
    }
    printf '%s\n' "$digest"
}

# The executed artifact is a mandatory postbuild identity input: its absence is
# a fail-closed condition (never a silently dropped identity field).
artifact_identity() {
    bin="$1"
    [ -f "$bin" ] || {
        echo "ARTIFACT-IDENTITY FAIL: executed artifact missing: $bin (identity impossible, not PASS)" >&2
        return 1
    }
    ah=$(sha256_digest file "$bin") || return 1
    echo "  executed artifact sha256 $ah  $bin"
}

# Authoritative filesystem observation for the config-candidate inventory
# (qkl option B): one standard-library stat boundary decides whether a
# candidate is present/absent, with EACCES/traversal, dangling-symlink and
# non-regular outcomes kept distinct from verified absence. Python3 is the
# permitted operational interpreter (host stdlib, no deps); its absence
# fails closed, exactly like the other boundary prerequisites.
config_observe() {
    path="$1"
    command -v python3 >/dev/null 2>&1 || {
        echo "SOURCE-IDENTITY FAIL: python3 required for cargo-config observation, not found" >&2
        exit 1
    }
    status=$(python3 scripts/cargo_config_probe.py "$path" 2>&1) || {
        echo "SOURCE-IDENTITY FAIL: cargo-config observation failed for: $path ($status)" >&2
        exit 1
    }
    printf '%s\n' "$status"
}

identity_snapshot() {
    dir="$1"
    rc=0
    head=$(git rev-parse --verify HEAD 2>&1) || rc=$?
    [ "$rc" -eq 0 ] || {
        echo "SOURCE-IDENTITY FAIL: git rev-parse HEAD exit $rc (head unreadable, not PASS)" >&2
        exit 1
    }
    mkdir -p "$dir"
    printf '%s\n' "$head" >"$dir/head"
    git status --porcelain >"$dir/status" 2>&1 || {
        echo "SOURCE-IDENTITY FAIL: git status exit $? (dirty scope unreadable, not PASS)" >&2
        exit 1
    }
    # Record which hasher the batch uses, then hash ALL identity inputs in ONE
    # producer invocation (single exec over ~49 files) instead of one
    # subprocess per file. The hasher is selected in this same shell, so the
    # global propagates to the env record below. Missing inputs fail closed
    # BEFORE any hashing; the batch's own exit code and stderr are checked
    # (never masked), and the temp stderr file is always removed.
    IDENTITY_HASHER=""
    if command -v sha256sum >/dev/null 2>&1; then IDENTITY_HASHER="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then IDENTITY_HASHER="shasum"; fi
    [ -n "$IDENTITY_HASHER" ] || {
        echo "SOURCE-IDENTITY FAIL: neither sha256sum nor shasum present (identity impossible, not PASS)" >&2
        exit 1
    }
    for f in $IDENTITY_FILES; do
        [ -f "$f" ] || {
            echo "SOURCE-IDENTITY FAIL: identity input missing: $f" >&2
            exit 1
        }
    done
    rc=0
    errf="$dir/inputs.sha256.err"
    : >"$dir/inputs.sha256"
    # The batch expansion is intentionally unquoted: IDENTITY_FILES is a fixed,
    # space-free set (INTENDED plus .gitignore and the docs-arm gate inputs).
    # The appended inputs are identity-carried, not gate roots: the docslink/
    # citation gate files (scripts/docs_check/*), the structural HTML gate and
    # its regression fixture (scripts/html_check.mjs and
    # scripts/html_check_test.mjs), and the html_check root
    # (docs/architecture.html via $HTML_DOC_ROOTS, expanded here to exactly one
    # path). Word-splitting thus yields exactly the intended
    # paths. The hasher's stderr is
    # retained so a failed hash names the failing input; it is surfaced before
    # removal, never masked.
    if [ "$IDENTITY_HASHER" = "sha256sum" ]; then
        # shellcheck disable=SC2086
        sha256sum $IDENTITY_FILES >"$dir/inputs.sha256" 2>"$errf" || rc=$?
    else
        # shellcheck disable=SC2086
        shasum -a 256 $IDENTITY_FILES >"$dir/inputs.sha256" 2>"$errf" || rc=$?
    fi
    [ "$rc" -eq 0 ] || {
        echo "SOURCE-IDENTITY FAIL: hash batch exit $rc (read failure, not PASS)" >&2
        if [ -s "$errf" ]; then
            echo "  hasher stderr:" >&2
            sed 's/^/    /' "$errf" >&2
        fi
        rm -f "$errf"
        exit 1
    }
    rm -f "$errf"
    # Effective Cargo config inventory (finite ancestor closure, qkl seam A):
    # Cargo's hierarchical search consults the cwd ancestry -- EVERY parent up
    # to the filesystem root -- plus the selected Cargo home
    # ${CARGO_HOME:-$HOME/.cargo}. Both spellings are inventoried at every stop
    # (config, config.toml); where both exist at one path Cargo prefers the
    # extensionless `config` spelling (Cargo Book, hierarchical structure). We
    # record candidates only: no TOML precedence/merge interpreter, no claim
    # either spelling is necessarily consumed. Path/name plus a SHA256 digest
    # or a verified-absence marker; any unreadable or non-regular candidate
    # fails closed. Replaces the prior four hardcoded fields with one
    # traversal, so a candidate above the checkout now changes this record.
    config_home="${CARGO_HOME:-$HOME/.cargo}"
    alihash=$(printf '%s\n' '[alias]' 'atest = ["test", "--quiet", "--no-fail-fast"]' 'aclippy = ["clippy", "--quiet", "--message-format=short"]' | sha256_digest stdin) || exit 1
    {
        printf 'toolchain=%s\n' "$TOOLCHAIN"
        printf 'hasher=%s\n' "${IDENTITY_HASHER:-<none>}"
        printf 'cargo_home=%s\n' "${CARGO_HOME:-<unset>}"
        printf 'cargo_target_dir=%s\n' "${CARGO_TARGET_DIR:-<unset>}"
        printf 'rustflags=%s\n' "${RUSTFLAGS:-<unset>}"
        printf 'rustc=%s\n' "${RUSTC:-<unset>}"
        printf 'rustc_wrapper=%s\n' "${RUSTC_WRAPPER:-<unset>}"
        printf 'rustc_workspace_wrapper=%s\n' "${RUSTC_WORKSPACE_WRAPPER:-<unset>}"
        printf 'cargo_incremental=%s\n' "${CARGO_INCREMENTAL:-<unset>}"
        printf 'cargo_term_progress_when=%s\n' "${CARGO_TERM_PROGRESS_WHEN:-<unset>}"
        printf 'podman_connection=%s\n' "${PODMAN_CONNECTION:-<unset>}"
        printf 'podman_root_connection=%s\n' "${PODMAN_ROOT_CONNECTION:-<unset>}"
        printf 'cargo_home_effective=%s\n' "$config_home"
        # G8-C10: supply-chain tool versions + advisory-DB freshness. Absent
        # tools/DB record <absent> (never a hard fail); the before/after env
        # diff surfaces any host tool/DB change between snapshots.
        if command -v cargo-audit >/dev/null 2>&1; then
            cav=$(cargo-audit --version 2>&1) || cav="<unreadable>"
            printf 'cargo_audit_version=%s\n' "$cav"
        else
            printf 'cargo_audit_version=<absent>\n'
        fi
        if command -v cargo-deny >/dev/null 2>&1; then
            cdv=$(cargo-deny --version 2>&1) || cdv="<unreadable>"
            printf 'cargo_deny_version=%s\n' "$cdv"
        else
            printf 'cargo_deny_version=<absent>\n'
        fi
        adb="$config_home/advisory-db"
        printf 'advisory_db_path=%s\n' "$adb"
        if [ -d "$adb/.git" ]; then
            adf=$(git -C "$adb" log -1 --format=%H 2>&1) || adf="<unreadable>"
            printf 'advisory_db_head_date=%s\n' "$adf"
        else
            printf 'advisory_db_head_date=<absent>\n'
        fi
        node_env_preflight
        command -v node >/dev/null 2>&1 || {
            echo "SOURCE-IDENTITY FAIL: node path producer failed (node absent; identity impossible, not PASS)" >&2
            exit 1
        }
        nodepath=$(command -v node 2>&1)
        nv=$(node --version 2>&1) || {
            echo "SOURCE-IDENTITY FAIL: node --version exit $? (version unobservable, not PASS)" >&2
            exit 1
        }
        [ -n "$nv" ] || {
            echo "SOURCE-IDENTITY FAIL: node --version empty output (version unobservable, not PASS)" >&2
            exit 1
        }
        nvh=$(printf '%s\n' "$nv" | sha256_digest stdin) || exit 1
        printf 'node_executable=%s\n' "$nodepath"
        printf 'node_version=%s\n' "$nv"
        printf 'node_version_sha256=%s\n' "$nvh"
        if [ -z "${NODE_OPTIONS+x}" ]; then printf 'node_options=<unset>\n'
        elif [ -n "$NODE_OPTIONS" ]; then printf 'node_options=%s\n' "$NODE_OPTIONS"
        else printf 'node_options=<empty>\n'; fi
        if [ -z "${NODE_PATH+x}" ]; then printf 'node_path=<unset>\n'
        elif [ -n "$NODE_PATH" ]; then printf 'node_path=%s\n' "$NODE_PATH"
        else printf 'node_path=<empty>\n'; fi
        if [ -z "${NODE_ENV+x}" ]; then printf 'node_env=<unset>\n'
        elif [ -n "$NODE_ENV" ]; then printf 'node_env=%s\n' "$NODE_ENV"
        else printf 'node_env=<empty>\n'; fi
        printf 'installed_closure_vs_lock=package-lock.json identity-covered; node_modules installed closure reconciled at commander intake (1gx.15 default-condition 67-file ledger)\n'
        printf 'cargo_config_namespace=host: cwd ancestry through filesystem root plus selected Cargo home\n'
        d="$(pwd)"
        while :; do
            for n in config config.toml; do
                if [ "$d" = "/" ]; then p="/.cargo/$n"; else p="$d/.cargo/$n"; fi
                st=$(config_observe "$p")
                case "$st" in
                    absent) printf 'cargo_config absent    %s\n' "$p" ;;
                    present)
                        h=$(sha256_digest file "$p") || { echo "SOURCE-IDENTITY FAIL: unreadable cargo config candidate: $p" >&2; exit 1; }
                        printf 'cargo_config present   %s  %s\n' "$h" "$p"
                        ;;
                    denied|dangling|nonregular|error)
                        echo "SOURCE-IDENTITY FAIL: cargo config candidate not observable ($st): $p" >&2
                        exit 1
                        ;;
                    *)
                        echo "SOURCE-IDENTITY FAIL: cargo config observation unknown status '$st' for: $p" >&2
                        exit 1
                        ;;
                esac
            done
            [ "$d" = "/" ] && break
            d="${d%/*}"
            [ -n "$d" ] || d="/"
        done
        for n in config config.toml; do
            p="$config_home/$n"
            st=$(config_observe "$p")
            case "$st" in
                absent) printf 'cargo_config selected absent    %s\n' "$p" ;;
                present)
                    h=$(sha256_digest file "$p") || { echo "SOURCE-IDENTITY FAIL: unreadable selected cargo config: $p" >&2; exit 1; }
                    printf 'cargo_config selected present   %s  %s\n' "$h" "$p"
                    ;;
                denied|dangling|nonregular|error)
                    echo "SOURCE-IDENTITY FAIL: selected cargo config not observable ($st): $p" >&2
                    exit 1
                    ;;
                *)
                    echo "SOURCE-IDENTITY FAIL: cargo config observation unknown status '$st' for: $p" >&2
                    exit 1
                    ;;
            esac
        done
        printf 'container_cargo_config_namespace=/app/.cargo mirrors repo cwd (inventoried above); fixed fresh /cargo-home provisioned alias block\n'
        printf 'container_alias_block_sha256=%s\n' "$alihash"
    } >"$dir/env"
    echo "SOURCE-IDENTITY: snapshot $dir (HEAD=$head, inputs $(wc -l <"$dir/inputs.sha256"))"
}

identity_compare() {
    before="$1"
    after="$2"
    ok=1
    cmp -s "$before/head" "$after/head" || { echo "SOURCE-IDENTITY-CHANGED FAIL: HEAD differs before/after" >&2; ok=0; }
    cmp -s "$before/status" "$after/status" || { echo "SOURCE-IDENTITY-CHANGED FAIL: working-tree status differs before/after" >&2; ok=0; }
    cmp -s "$before/inputs.sha256" "$after/inputs.sha256" || { echo "SOURCE-IDENTITY-CHANGED FAIL: input hashes differ before/after" >&2; ok=0; }
    cmp -s "$before/env" "$after/env" || { echo "SOURCE-IDENTITY-CHANGED FAIL: build env differs before/after" >&2; ok=0; }
    [ "$ok" -eq 1 ] || {
        echo "SOURCE-IDENTITY-CHANGED FAIL: boundary inputs not stable; refusing completion markers" >&2
        exit 1
    }
    echo "SOURCE-IDENTITY-STABLE-OK (HEAD, status, inputs and env identical before/after)"
}

audit_deny_owner() {
    have=1
    command -v cargo-audit >/dev/null 2>&1 || have=0
    command -v cargo-deny >/dev/null 2>&1 || have=0
    if [ "$have" -eq 1 ]; then
        echo "AUDIT-DENY (hard gate, boundary host):"
        # G8-C22: pin supply-chain tool versions; a drift from the accepted
        # versions fails closed (a different audit/deny version can change the
        # gate verdict, so the intake gate must be host-reproducible).
        AUDIT_VERSION="0.22.1"
        DENY_VERSION="0.19.4"
        av=$(cargo-audit --version 2>&1) || av="<unreadable>"
        [ "${av##* }" = "$AUDIT_VERSION" ] || { echo "AUDIT-DENY FAIL: cargo-audit version '$av' != pinned $AUDIT_VERSION" >&2; exit 1; }
        dv=$(cargo-deny --version 2>&1) || dv="<unreadable>"
        [ "${dv##* }" = "$DENY_VERSION" ] || { echo "AUDIT-DENY FAIL: cargo-deny version '$dv' != pinned $DENY_VERSION" >&2; exit 1; }
        ar=0
        cargo +${TOOLCHAIN} audit --no-fetch || ar=$?
        [ "$ar" -eq 0 ] || { echo "AUDIT-DENY FAIL: cargo audit exit $ar" >&2; exit 1; }
        dr=0
        cargo +${TOOLCHAIN} deny check || dr=$?
        [ "$dr" -eq 0 ] || { echo "AUDIT-DENY FAIL: cargo deny exit $dr" >&2; exit 1; }
        echo "AUDIT-DENY-OK (audit $AUDIT_VERSION exit $ar; deny $DENY_VERSION exit $dr)"
    else
        echo "AUDIT-DENY-BLOCKED: cargo audit or cargo deny absent on this boundary host; applicable phase1 audit/deny cannot complete" >&2
        exit 1
    fi
}

# --- I3/I4 container plumbing: derived image, named volumes, artifact copy-out --

# ensure_alt_image <connection>: make the derived image available once. This is
# the ONLY networked step in the dispatch path, and it runs at most once per
# connection; every consumer afterwards is `--pull=never`.
ensure_alt_image() {
    _conn="$1"
    command -v podman >/dev/null 2>&1 || {
        echo "ALT-IMAGE-BLOCKED: podman required on the host" >&2
        exit 1
    }
    if podman --connection "$_conn" image exists "$ALT_IMAGE" >/dev/null 2>&1; then
        return 0
    fi
    echo "ALT-IMAGE-BUILD: '$ALT_IMAGE' absent on $_conn; building once FROM the pinned base (network required ONCE)" >&2
    _ctx="$(pwd)/target/alt-image"
    mkdir -p "$_ctx"
    cat >"$_ctx/Containerfile" <<ALTCF
FROM $FIXTURE_BASE_IMAGE
RUN apk add --no-cache git util-linux python3 \\
 && rustup component add clippy rustfmt
ALTCF
    podman --connection "$_conn" build -t "$ALT_IMAGE" -f "$_ctx/Containerfile" "$_ctx" >&2 || {
        echo "ALT-IMAGE-BLOCKED: derived image build failed on $_conn (network/prereq)" >&2
        exit 1
    }
    podman --connection "$_conn" image exists "$ALT_IMAGE" >/dev/null 2>&1 || {
        echo "ALT-IMAGE-BLOCKED: '$ALT_IMAGE' still absent after build on $_conn" >&2
        exit 1
    }
}

# Fixtures share the derived image (it also carries the setpriv/python3 the
# fixture cases need), so the fixture path and the build path cannot diverge.
ensure_fixture_image() {
    ensure_alt_image "$1"
}

# ensure_volume <connection> <volume>: create the named volume once. The host
# target/ tree is ~64k files; crossing virtiofs on every Cargo unit is the
# dominant wall clock. Volumes are per-VM, so every call names its connection.
ensure_volume() {
    _vconn="$1"
    _vol="$2"
    if podman --connection "$_vconn" volume inspect "$_vol" >/dev/null 2>&1; then
        return 0
    fi
    podman --connection "$_vconn" volume create "$_vol" >/dev/null || {
        echo "ALT-VOLUME-BLOCKED: cannot create volume '$_vol' on $_vconn" >&2
        exit 1
    }
}

# target_volume_mount: read-only target-volume mount for fixture-side consumers
# (they only read the built variant). Emits two words, or nothing under the
# host bind-mount baseline (ALT_NO_VOLUME=1). The string is fixed and internal,
# so the unquoted expansion at each call site is intentional and safe.
target_volume_mount() {
    if [ "$ALT_NO_VOLUME" = "1" ]; then
        return 0
    fi
    printf '%s\n' "-v" "$ALT_TARGET_VOL:/app/target:ro"
}

# copy_out_artifact <volume-relative-path> <host-relative-path> (I4): copy one
# built artifact out of the build volume and assert the digest is identical on
# both sides. A one-sided copy would let a host-side gate identify bytes that
# were never the bytes built, so the two-sided assertion is the identity proof.
copy_out_artifact() {
    _rel="$1"
    _dest="$2"
    if [ "$ALT_NO_VOLUME" = "1" ]; then
        echo "ALT-COPY-SKIPPED: host bind-mount baseline (ALT_NO_VOLUME=1) keeps $_dest in place" >&2
        return 0
    fi
    case "$_dest" in
        target/*) ;;
        *)
            echo "ALT-COPY-FAIL: destination '$_dest' must be relative to target/ (the mounted copy root)" >&2
            return 1
            ;;
    esac
    # Copy root is the host target/ tree, so the container path drops the leading
    # "target/" that every caller uses for the host-relative destination.
    _host_rel="${_dest#target/}"
    CONN="${PODMAN_CONNECTION:?PODMAN_CONNECTION must be set to your rootless podman connection}"
    ROOT="$(pwd)"
    ensure_alt_image "$CONN"
    mkdir -p "$(dirname "$ROOT/$_dest")"
    _copy_out=$(podman --connection "$CONN" run --rm --pull=never \
        --user 0:0 \
        -e REL="$_rel" \
        -e DEST="$_host_rel" \
        -v "$ALT_TARGET_VOL:/t:ro" \
        -v "$ROOT/target:/out:Z" \
        "$ALT_IMAGE" sh -c 'mkdir -p "/out/$(dirname "$DEST")" && cp "/t/$REL" "/out/$DEST" && sha256sum "/t/$REL" | cut -d" " -f1' 2>&1) || {
        echo "ALT-COPY-FAIL: copy-out of $_rel failed:" >&2
        printf '%s\n' "$_copy_out" >&2
        return 1
    }
    _vol_sha=$(printf '%s\n' "$_copy_out" | tail -n 1)
    [ -n "$_vol_sha" ] || {
        echo "ALT-COPY-FAIL: empty volume-side digest for $_rel (not PASS)" >&2
        return 1
    }
    _host_sha=$(sha256_digest file "$ROOT/$_dest") || return 1
    [ "$_vol_sha" = "$_host_sha" ] || {
        echo "ALT-COPY-FAIL: digest mismatch for $_rel (volume $_vol_sha != host $_host_sha)" >&2
        return 1
    }
    echo "ALT-COPY-OK: $_dest sha256 $_host_sha (volume-side and host-side agree)"
}

# Host -> existing Linux dispatch: boundary children that must run on Linux are
# executed inside the derived image, never by calling Linux-only functions
# directly on a Darwin host. I4: the Cargo cache is a named volume mounted at
# /app/target, so container-internal paths (/app/target/release/alumina,
# /app/target/fixture-facts/release/alumina) keep their exact meaning while the
# host target/ is no longer a build home.
# G8-C17 preserved: the source stays mounted read-only (:ro,Z, matching the
# fixture convention), so the checkout itself is never a build output location;
# only the target path is writable, now via a volume rather than a host bind.
linux_dispatch() {
    inner="$1"
    CONN="${PODMAN_CONNECTION:?PODMAN_CONNECTION must be set to your rootless podman connection}"
    command -v podman >/dev/null 2>&1 || {
        echo "LINUX-DISPATCH-BLOCKED: podman required on the host" >&2
        exit 1
    }
    podman --connection "$CONN" info >/dev/null 2>&1 || {
        echo "LINUX-DISPATCH-BLOCKED: podman connection $CONN unreachable (probe, not PASS)" >&2
        exit 1
    }
    ROOT="$(pwd)"
    ensure_alt_image "$CONN"
    IMAGE="$ALT_IMAGE"
    _img_id=$(podman --connection "$CONN" image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null) || _img_id=""
    [ -n "$_img_id" ] || {
        echo "LINUX-DISPATCH-BLOCKED: dispatch image id unresolvable for $IMAGE" >&2
        exit 1
    }
    echo "  dispatch image $IMAGE id=$_img_id"
    # Only the alias block is written now: clippy/rustfmt/git are baked into the
    # derived image and the crate cache persists in $ALT_CARGO_HOME_VOL, so the
    # dispatch performs no network provisioning. The two presence checks fail
    # closed rather than silently installing -- a missing tool means the image is
    # wrong, and installing it would reintroduce the network dependency.
    prov='mkdir -p /cargo-home
printf "%s\n" "[alias]" "atest = [\"test\", \"--quiet\", \"--no-fail-fast\"]" "aclippy = [\"clippy\", \"--quiet\", \"--message-format=short\"]" > /cargo-home/config.toml
command -v git >/dev/null 2>&1 || { echo "LINUX-DISPATCH-BLOCKED: git absent from dispatch image (whitespace gate requires it)" >&2; exit 1; }
rustup component list --installed 2>/dev/null | grep -q clippy || { echo "LINUX-DISPATCH-BLOCKED: clippy component absent from dispatch image" >&2; exit 1; }
'
    _ld_t0=$(now_ms)
    drc=0
    if [ "$ALT_NO_VOLUME" = "1" ]; then
        # Baseline mode only: verify.sh's original host bind-mount of target/, so
        # the alt can be measured apples-to-apples against verify.sh.
        podman --connection "$CONN" run --rm --pull=never \
            -v "$ROOT:/app:ro,Z" \
            -v "$ROOT/target:/app/target:Z" \
            --user 0:0 \
            -e CARGO_HOME=/cargo-home \
            -e CARGO_INCREMENTAL=0 \
            -e CARGO_TERM_PROGRESS_WHEN=never \
            -e TOOLCHAIN="$TOOLCHAIN" \
            -e RUST_MIN_STACK=16777216 \
            -w /app \
            "$IMAGE" sh -c "$prov$inner" || drc=$?
    else
        ensure_volume "$CONN" "$ALT_TARGET_VOL"
        ensure_volume "$CONN" "$ALT_CARGO_HOME_VOL"
        # The target path must exist inside the read-only source mount before the
        # volume is mounted over it.
        mkdir -p "$ROOT/target"
        podman --connection "$CONN" run --rm --pull=never \
            -v "$ROOT:/app:ro,Z" \
            -v "$ALT_TARGET_VOL:/app/target" \
            -v "$ALT_CARGO_HOME_VOL:/cargo-home" \
            --user 0:0 \
            -e CARGO_HOME=/cargo-home \
            -e CARGO_INCREMENTAL=0 \
            -e CARGO_TERM_PROGRESS_WHEN=never \
            -e TOOLCHAIN="$TOOLCHAIN" \
            -e RUST_MIN_STACK=16777216 \
            -w /app \
            "$IMAGE" sh -c "$prov$inner" || drc=$?
    fi
    _ld_t1=$(now_ms)
    case "${_ld_t0}${_ld_t1}" in
        *NA*) phase_mark "dispatch" NA ;;
        *) phase_mark "dispatch" "$((_ld_t1 - _ld_t0))ms" ;;
    esac
    [ "$drc" -eq 0 ] || {
        echo "LINUX-MID FAIL: '$inner' exit $drc" >&2
        exit 1
    }
}

# Pure change-scope classifier (B): reads a path list on stdin (one per line),
# echoes `docs-only` when every path is allowlisted (under docs/, or exactly
# README.md / AGENTS.md), else `full`. Empty stdin =>
# full (fail-safe toward more verification, never less). This is the TDD seam:
# unit-testable with synthetic path lists and no git.
phase1_scope_classify() {
    scope="docs-only"
    seen=0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        seen=1
        case "$p" in
            *".."*) scope="full"; break ;;
            docs/*|README.md|AGENTS.md) ;;
            *) scope="full"; break ;;
        esac
    done
    [ "$seen" -eq 1 ] || scope="full"
    printf '%s\n' "$scope"
}

# Real change-scope detector (B): unions the committed (HEAD~1..HEAD),
# uncommitted (HEAD..worktree) and untracked path lists, classifies the union
# via phase1_scope_classify, echoes the scope, and writes the scope marker to
# $PHASE1_SCOPE_MARKER (gitignored) so the slow tier can be a separate
# invocation. Conservative by construction: any git-producer failure, a missing
# HEAD~1 (root commit), an empty union, or any non-allowlisted path => full
# (more verification, never less). The PHASE1_SCOPE env override forces
# full/docs-only; any other value => full (fail-safe).
phase1_change_scope() {
    scope="${PHASE1_SCOPE:-}"
    if [ -n "$scope" ]; then
        case "$scope" in
            full|docs-only) ;;
            *) scope="full" ;;
        esac
    else
        rc=0
        committed=$(git diff --name-only HEAD~1 HEAD 2>&1) || rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "PHASE1-SCOPE-FAIL: git diff HEAD~1..HEAD exit $rc (root commit or unreadable; full ceremony)" >&2
            scope="full"
        fi
        if [ "$scope" != "full" ]; then
            rc=0
            uncommitted=$(git diff --name-only HEAD 2>&1) || rc=$?
            if [ "$rc" -ne 0 ]; then
                echo "PHASE1-SCOPE-FAIL: git diff HEAD exit $rc (unreadable diff; full ceremony)" >&2
                scope="full"
            fi
        fi
        if [ "$scope" != "full" ]; then
            rc=0
            untracked=$(git ls-files --others --exclude-standard 2>&1) || rc=$?
            if [ "$rc" -ne 0 ]; then
                echo "PHASE1-SCOPE-FAIL: git ls-files --others exit $rc (unreadable untracked list; full ceremony)" >&2
                scope="full"
            fi
        fi
        if [ "$scope" != "full" ]; then
            paths=$(printf '%s\n%s\n%s\n' "$committed" "$uncommitted" "$untracked")
            scope=$(printf '%s\n' "$paths" | phase1_scope_classify)
        fi
    fi
    printf '%s\n' "$scope"
    mkdir -p target
    printf '%s\n' "$scope" > "$PHASE1_SCOPE_MARKER"
}

boundary_phase1_fast() {
    # Fast tier (C): cheap host gates only — identity BEFORE/AFTER stability
    # self-check, change-scope classification (B), then docs/unsafe/whitespace/
    # audit gates. NO linux_dispatch, NO MID, NO fixtures. Runs before the
    # expensive Linux MID so a failing cheap gate aborts before the
    # compile-dominated dispatch. None of these mutate identity inputs, so the
    # BEFORE snapshot stays valid across them.
    # I0: every gate is individually timed so the fast tier's own contribution to
    # wall clock is measured rather than assumed.
    phase_timed "fast.identity-before" identity_snapshot "$IDENTITY_BEFORE"
    _scope_t0=$(now_ms)
    phase1_scope=$(phase1_change_scope)
    _scope_t1=$(now_ms)
    case "${_scope_t0}${_scope_t1}" in
        *NA*) phase_mark "fast.scope-classify" NA ;;
        *) phase_mark "fast.scope-classify" "$((_scope_t1 - _scope_t0))ms" ;;
    esac
    phase_timed "fast.docslink" docslink_check
    phase_timed "fast.intended-coverage" intended_coverage_gate
    phase_timed "fast.cfg-test-parentage" cfg_test_parentage_gate
    phase_timed "fast.unsafe-surface" unsafe_surface_gate
    phase_timed "fast.canonical-digest" canonical_digest_gate
    phase_timed "fast.git-diff-check" git_diff_check
    phase_timed "fast.audit-deny" audit_deny_owner
    phase_timed "fast.identity-after" identity_snapshot "$IDENTITY_AFTER"
    phase_timed "fast.identity-compare" identity_compare "$IDENTITY_BEFORE" "$IDENTITY_AFTER"
    echo "PHASE1-SCOPE-CLASSIFIED: $phase1_scope"
}

# `git diff --check` wrapped as a gate so it can be timed like its neighbours
# without changing its semantics (non-zero exits fail the run as before).
git_diff_check() {
    git diff --check
    echo "GIT-DIFF-CHECK-OK"
}

boundary_phase1_slow() {
    # Slow tier (C): Linux MID + fixtures + artifact identity. Reads the scope
    # marker written by the fast tier (missing => full, fail-safe); on docs-only
    # it self-skips with an explicit classification and no MID. The AFTER
    # snapshot is re-taken here (after boot_fixtures) and compared to the
    # BEFORE captured by the fast tier, so a separate slow invocation still
    # proves identity stability across the MID+fixtures.
    #
    # I1: this dispatches `mid union` ONLY. verify.sh dispatched
    # `mid union && mid full`, and union now covers the gate-only surface for the
    # same candidate, so the second selector would re-run 2 of 2 test
    # invocations for zero extra coverage. `mid full` remains available
    # standalone.
    # I4: the built artifact is copied out of the build volume with a two-sided
    # digest assertion before any host-side gate consumes it.
    scope="full"
    if [ -f "$PHASE1_SCOPE_MARKER" ]; then
        scope=$(cat "$PHASE1_SCOPE_MARKER" 2>/dev/null) || scope="full"
    fi
    case "$scope" in
        docs-only)
            echo "PHASE1-SLOW-SKIPPED-BY-DESIGN: docs-only scope; Linux MID skipped (no Rust/fixture-facts change to verify)"
            return 0
            ;;
        full) ;;
        *) scope="full" ;;
    esac
    linux_dispatch 'sh scripts/verify.sh mid union'
    copy_out_artifact "release/alumina" "target/release/alumina" || exit 1
    phase_timed "fixtures" boot_fixtures
    phase_timed "identity-after" identity_snapshot "$IDENTITY_AFTER"
    phase_timed "identity-compare" identity_compare "$IDENTITY_BEFORE" "$IDENTITY_AFTER"
    phase_timed "artifact-identity" artifact_identity target/release/alumina || exit 1
}

boundary_phase1() {
    echo "phase1 boundary (owner seam H1): host sole coordinator; Linux MID via existing podman dispatch"
    boundary_phase1_fast
    boundary_phase1_slow
}

boundary_phase1_markers() {
    echo "F3 mio operation matrix: IMPLEMENTED (tests/mio_matrix.rs: 8 tests incl. linux_epoll_operation_matrix with poll/register/reregister/deregister + alloc-witness controls; recorded native release evidence docs/verification.md#native-proofs-scoped-exact-input, z9m0/po3c); current-serving completeness witness still OPEN (cnrd T3) - not 'unbuilt matrix', not 'complete'"
    echo "NotImplemented: DNS wire parser fuzz (Slice 2)"
    echo "NotImplemented: CONNECT/ClientHello parser fuzz (Slices 3-4)"
    echo "NotImplemented: log-record encoding fuzz (Slice 6)"
    echo "NotImplemented: deployment confinement + E2E release gates (Slice 7)"
    echo "RELEASE-NOT-READY: later-slice and release gates remain NotImplemented, not green"
    echo "BOUNDARY-OWNER-COORD-OK: all applicable phase1 children coordinated and exited 0 on this host"
    echo "ALT-PARITY: every gate and marker of the pre-I0 ceremony is still present; only cost structure changed (see PHASE1-TIMING lines)"
    echo "ALT-MODE: target_vol=$ALT_TARGET_VOL cargo_home_vol=$ALT_CARGO_HOME_VOL aw_target_dir=$ALT_AW_TARGET_DIR image=$ALT_IMAGE no_volume=$ALT_NO_VOLUME"
    alt_total_timing
    echo "FINAL-PHASE1-COMPLETION: BLOCKED — pending fixture/doc/Rust repairs and review approval before any phase1 done-claim (no E2E equivalence claimed)"
}

# Real-IO CONNECT/SNI opaque-relay and native SIGTERM shutdown gates against the
# ACTUAL production binary rebuilt from the exact current source (never a stale
# artifact): native Linux release build (or container dispatch on a non-Linux
# host), then the gate's harness script runs it in a fully network-isolated
# container. The source/binary identity receipt is mandatory so the executed
# artifact is tied to the reviewed candidate, and every e2e case must exit hard
# zero.
#
# e2e_build_receipt is the single shared build/receipt owner for BOTH gates. It
# rebuilds the exact candidate ONCE per invocation, checks producer exits and
# source/artifact correspondence through execution (never a masked pipeline,
# never a framework), and prints the identity line; each standalone selector
# (e2e/relay, e2e/shutdown) stays independently dispatchable and runs only its
# own harness after the shared receipt.
# Exact-candidate input digest record (pre/post-build and after the executed
# harness): HEAD + dirty diff + untracked harness py/sh + gate script. The diff
# producer exit is checked SEPARATELY (never a masked pipeline); the untracked
# harness scripts are hashed explicitly (git diff excludes them). Requires $TGT.
e2e_receipt_fields() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    rcd=0
    git diff HEAD >"$TGT/$_gate-diff.$$" 2>&1 || rcd=$?
    [ "$rcd" -eq 0 ] || {
        echo "E2E-$_gate-BLOCKED: git diff HEAD exit $rcd (unreadable diff, not a receipt)" >&2
        exit 1
    }
    rgh=0
    head=$(git rev-parse --verify HEAD 2>&1) || rgh=$?
    [ "$rgh" -eq 0 ] && [ -n "$head" ] || {
        echo "E2E-$_gate-BLOCKED: git rev-parse --verify HEAD exit $rgh (unreadable HEAD, not a receipt)" >&2
        exit 1
    }
    diffhash=$(sha256_digest file "$TGT/$_gate-diff.$$") || exit 1
    harness1=$(sha256_digest file "$_harness_py") || exit 1
    harness2=$(sha256_digest file "$_harness_sh") || exit 1
    shellhash=$(sha256_digest file "scripts/verify.sh") || exit 1
    printf '%s %s %s %s %s\n' "$head" "$diffhash" "$harness1" "$harness2" "$shellhash"
}

# B3 through-execution correspondence: after the harness has consumed the
# binary from the live read-only checkout mount, re-derive the exact same input
# digest record plus the binary digest and refuse certification if either
# changed. Endpoint-stability assurance is scoped to the serial, actual-checkout
# owner: a durable source or artifact change observed before the post-execution
# re-hash is attributed to this invocation and refuses certification; this does
# not claim to detect a transient replacement that is restored before the final
# hash. The verdict therefore remains tied to the stable candidate this run
# actually executed.
e2e_verify_stable() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    prev_inputs=$(cat "$TGT/.e2e-$_gate-inputs" 2>/dev/null) || {
        echo "E2E-$_gate-BLOCKED: e2e receipt inputs file missing ($TGT/.e2e-$_gate-inputs); certification impossible" >&2
        exit 1
    }
    prev_bin=$(cat "$TGT/.e2e-$_gate-binhash" 2>/dev/null) || {
        echo "E2E-$_gate-BLOCKED: e2e receipt binhash file missing ($TGT/.e2e-$_gate-binhash); certification impossible" >&2
        exit 1
    }
    now_inputs=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    now_bin=$(sha256_digest file "$ROOT/$BIN") || exit 1
    if [ "$now_inputs" != "$prev_inputs" ]; then
        echo "E2E-$_gate-BLOCKED: source inputs changed across harness execution (receipt no longer corresponds); refusing certification" >&2
        echo "  before=$prev_inputs" >&2
        echo "  now   =$now_inputs" >&2
        exit 1
    fi
    if [ "$now_bin" != "$prev_bin" ]; then
        echo "E2E-$_gate-BLOCKED: executed binary changed across harness execution ($prev_bin -> $now_bin); refusing certification" >&2
        exit 1
    fi
    echo "E2E-$_gate-CORRESPONDENCE-OK: inputs+binary unchanged across harness execution"
}

e2e_build_receipt() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    ROOT="$(pwd)"
    # B3: observation and build must share one actual connection. Both the
    # build dispatch (linux_dispatch) and the probe below resolve the SAME
    # PODMAN_CONNECTION, so a probe/build owner mismatch is impossible by
    # construction; the variable is required (fail-closed) on the non-Linux
    # dispatch route.
    if [ "$(uname -s)" = "Linux" ]; then
        _builder="native-host"
    else
        _builder="podman-dispatch"
        : "${PODMAN_CONNECTION:?PODMAN_CONNECTION must be set to your rootless podman connection}"
    fi
    # R1: the artifact PROFILE is explicitly observed from the build owner (the
    # native host triple under which the release build actually runs), not
    # guessed from --target-dir. The identical triple is carried into the cargo
    # build AND into the artifact consumer path, so the executed binary is the
    # one Cargo just produced - a stale default-path artifact can never be
    # consumed. On the non-Linux dispatch route the triple is observed inside
    # the same rust image that performs the build.
    # N1: observe the build-owner native profile with the PRODUCER's own exit
    # checked before any parsing. stdout/stderr are captured together so a
    # failing producer (even one that wrote a plausible host line) is never
    # masked by a later filter's exit 0, and the reason is not swallowed by
    # 2>/dev/null. Parsing (`sed 's/^host: //p'`) runs only on the captured
    # buffer of an exit-0 producer.
    observe_build_target() {
        _probe_out="$("$@" 2>&1)" || _probe_rc=$?
        if [ "${_probe_rc:-0}" -ne 0 ]; then
            printf 'E2E-%s-BLOCKED: build target probe failed before parse (exit %s):\n%s\n' \
                "$_gate" "$_probe_rc" "$_probe_out" >&2
            exit 1
        fi
        printf '%s\n' "$_probe_out"
    }
    if [ "$(uname -s)" = "Linux" ]; then
        _probe_buf=$(observe_build_target rustc +${TOOLCHAIN} -vV) || exit 1
    else
        _probe_buf=$(observe_build_target \
            podman --connection "${PODMAN_CONNECTION}" run --rm --pull=never \
            docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a \
            sh -c 'rustc -vV') || exit 1
    fi
    # parse only from the successfully captured buffer (producer exit already 0)
    E2E_TARGET=$(printf '%s\n' "$_probe_buf" | sed -n 's/^host: //p')
    case "$E2E_TARGET" in
        "" | *$'\n'* | *" "*)
            echo "E2E-$_gate-BLOCKED: could not observe native build target profile ('${E2E_TARGET}')" >&2
            exit 1
            ;;
    esac
    export E2E_TARGET
    TGT="$ROOT/target"
    BIN="target/${E2E_TARGET}/release/alumina"
    closure_metadata
    # Pre-build source-input stability record (exact-candidate inputs hashed by
    # the shared owner; explicitly includes the untracked harness scripts).
    mkdir -p "$TGT"
    before=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    if [ "$(uname -s)" = "Linux" ]; then
        echo "PRODUCTION-RELEASE-BUILD (native Linux, exact current source, target=${E2E_TARGET}):"
        cargo +${TOOLCHAIN} build --locked --release --target "$E2E_TARGET" --target-dir "$TGT"
    else
        echo "PRODUCTION-RELEASE-BUILD (native Linux via container dispatch; host $(uname -s), target=${E2E_TARGET}):"
        linux_dispatch "cargo +${TOOLCHAIN} build --locked --release --target ${E2E_TARGET} --target-dir /app/target"
        # I4: the build volume is VM-native, so the executed binary must be
        # copied out (two-sided digest asserted) before the receipt is taken.
        copy_out_artifact "${E2E_TARGET}/release/alumina" "${BIN}" || exit 1
    fi
    after=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    # Pre/post build source-input stability: the candidate inputs (HEAD +
    # dirty diff + untracked harness + gate script) must be unchanged across
    # the build, or a mid-build source change would detach the receipt from the
    # executed binary.
    if [ "$before" != "$after" ]; then
        echo "E2E-$_gate-BLOCKED: source inputs changed during the build (receipt would not correspond)" >&2
        echo "  before=$before" >&2
        echo "  after =$after" >&2
        exit 1
    fi
    [ -x "$ROOT/$BIN" ] || {
        echo "E2E-$_gate-BLOCKED: production static binary missing after rebuild ($BIN for target $E2E_TARGET)" >&2
        exit 1
    }
    echo "e2e/$_gate identity (executed binary tied to exact candidate):"
    head=$(git rev-parse --verify HEAD 2>&1) || {
        echo "E2E-$_gate-BLOCKED: git rev-parse HEAD failed" >&2
        exit 1
    }
    binhash=$(sha256_digest file "$ROOT/$BIN") || exit 1
    # B3/R1: resolve the ACTUAL harness-image tag + immutable ID from the
    # rootful connection the harness consumers open (e2e_relay.sh/e2e_shutdown.sh
    # use ${PODMAN_ROOT_CONNECTION}). An unresolvable ID is a
    # blocker. The immutable ID is EXPORTED to the consumers, which must
    # re-check that the tag still resolves to this ID on their connection and
    # then run the ID itself (R1: the receipt's image is the image executed).
    E2E_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
    E2E_ROOT_CONN="${PODMAN_ROOT_CONNECTION:?PODMAN_ROOT_CONNECTION must be set to your rootful podman connection}"
    harness_id=$(podman --connection "$E2E_ROOT_CONN" image inspect --format '{{.Id}}' "$E2E_IMAGE" 2>/dev/null) \
        || harness_id=""
    if [ -z "$harness_id" ]; then
        echo "E2E-$_gate-BLOCKED: harness image '$E2E_IMAGE' id unresolvable on ${E2E_ROOT_CONN}: ${E2E_ROOT_CONN}" >&2
        exit 1
    fi
    export E2E_IMAGE E2E_IMAGE_ID="$harness_id" E2E_ROOT_CONN
    # Durable through-execution receipt (consumed by e2e_verify_stable after
    # the harness runs): exact-candidate inputs + executed binary digest.
    printf '%s\n' "$after" >"$TGT/.e2e-$_gate-inputs"
    printf '%s\n' "$binhash" >"$TGT/.e2e-$_gate-binhash"
    printf '  HEAD=%s target=%s dirty-diff-sha256=%s harness-py-sha256=%s harness-sh-sha256=%s binary-sha256=%s\n' \
        "$head" "$E2E_TARGET" "$(printf '%s' "$after" | cut -d' ' -f2)" \
        "$(printf '%s' "$after" | cut -d' ' -f3)" "$(printf '%s' "$after" | cut -d' ' -f4)" "$binhash"
    printf '  builder=%s builder-image=%s harness-image=%s harness-image-id=%s harness-conn=%s\n' \
        "$_builder" "docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a" \
        "$E2E_IMAGE" "$harness_id" "$E2E_ROOT_CONN"
}

e2e_relay() {
    e2e_build_receipt relay scripts/e2e_relay.py scripts/e2e_relay.sh
    sh scripts/e2e_relay.sh
    e2e_verify_stable relay scripts/e2e_relay.py scripts/e2e_relay.sh
}

# Native SIGTERM shutdown gate against the ACTUAL production binary, rebuilt
# from the exact current source behind the same identity receipt as the relay
# gate via the shared e2e_build_receipt owner (source/binary correspondence is
# mandatory so the executed artifact is tied to the reviewed candidate). The
# gate drives real SIGTERM into the served binary: idle wake, no-self-exit,
# pre-serving observation, early drain, deadline-forced closure (repeat-signal
# no-extension), stalled stdout and silent DNS cooperation. Every case child is
# supervised foreground.
e2e_shutdown() {
    e2e_build_receipt shutdown scripts/e2e_shutdown.py scripts/e2e_shutdown.sh
    sh scripts/e2e_shutdown.sh
    e2e_verify_stable shutdown scripts/e2e_shutdown.py scripts/e2e_shutdown.sh
}

# inner/check: fastest host-runnable compile gate — `cargo check` on the crate
# only (no clippy/fmt/whitespace/release). Host-runnable by design (no Linux
# guard): the crate compiles off-Linux (preflight carries a
# cfg(not(target_os="linux")) fallback). For a raw-cargo single-test-target
# check (sub-mission C's per-test selector), use:
#   cargo +$TOOLCHAIN atest -p alumina --locked --test <target>
inner_check() {
    echo "INNER-CHECK (cargo check, no clippy/fmt/whitespace/release):"
    cargo +${TOOLCHAIN} check --locked -p alumina --all-targets
    echo "INNER-CHECK-OK"
}

# --- ALT-only operator helpers (no claim, prove/warm the cost plumbing) -------
# `alt image` materialises the derived digest-identified image, `alt smoke`
# exercises one dispatch + copy-out. They exist so the new plumbing can be
# verified and its caches warmed without paying for a full boundary run.
alt_image() {
    CONN="${PODMAN_CONNECTION:?PODMAN_CONNECTION must be set to your rootless podman connection}"
    ensure_alt_image "$CONN"
    _aid=$(podman --connection "$CONN" image inspect --format '{{.Id}}' "$ALT_IMAGE" 2>/dev/null) || _aid=""
    [ -n "$_aid" ] || {
        echo "ALT-IMAGE-BLOCKED: id unresolvable for $ALT_IMAGE (probe failure is not PASS)" >&2
        exit 1
    }
    echo "ALT-IMAGE-OK: $ALT_IMAGE id=$_aid base=$FIXTURE_BASE_IMAGE"
}

alt_smoke() {
    echo "ALT-SMOKE: plumbing proof only (volume-mounted target, read-only source, two-sided copy-out digest); backs no claim"
    linux_dispatch 'cargo +${TOOLCHAIN} build --locked -p alumina --bin alumina'
    copy_out_artifact "debug/alumina" "target/alt-smoke/alumina" || exit 1
    echo "ALT-SMOKE-OK"
}

# I8: host-native single-target test run for iteration speed — the inner loop for
# someone working on one test, without a container round-trip. It backs NO
# done-claim: MID and BOUNDARY own that. Host incompatibility is reported
# honestly: a Linux-only assertion (epoll matrix, main-thread rlimit, stdout
# stall) may fail on macOS/darwin, and that surfaces as
# INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL with a pointer to the MID tier — never as
# a pass and never as a silent skip.
inner_test() {
    _target="$1"
    case "$_target" in
        foundations|boot|eligibility|mio_matrix|main_thread_stack|monitor_stdout|stdout_stall) ;;
        "")
            echo "INNER-TEST usage: verify.sh inner test <target>" >&2
            exit 2
            ;;
        *)
            echo "INNER-TEST-UNKNOWN-TARGET: '$_target' is not a test target of this crate (whitelist: foundations boot eligibility mio_matrix main_thread_stack monitor_stdout stdout_stall)" >&2
            exit 2
            ;;
    esac
    echo "INNER-NO-CLAIM: host-native run of --test $_target backs no done-claim (MID/BOUNDARY own that)"
    if cargo +${TOOLCHAIN} atest -p alumina --locked --test "$_target"; then
        echo "INNER-TEST-OK: $_target"
    else
        _itr=$?
        echo "INNER-TEST-HOST-INCOMPATIBLE-OR-FAIL: $_target exit $_itr — if this is a Linux-only assertion, run the MID tier (verify.sh mid foundations|boot|union|full) instead; this is not a pass" >&2
        exit "$_itr"
    fi
}

case "$TIER/$SCOPE" in
    inner/check) inner_check ;;
    inner/test) inner_test "$FOCUS" ;;
    alt/image) alt_image ;;
    alt/smoke) alt_smoke ;;
    mid/foundations) mid_foundations ;;
    mid/boot) mid_boot ;;
    mid/clippy) mid_clippy ;;
    mid/union) mid_union ;;
    mid/full) mid_full ;;
    fixtures/boot) boot_fixtures ;;
    boundary/phase1-fast) boundary_phase1_fast; boundary_phase1_markers; exit 1 ;;
    boundary/phase1-slow) boundary_phase1_slow; boundary_phase1_markers; exit 1 ;;
    boundary/phase1) boundary_phase1; boundary_phase1_markers; exit 1 ;;
    e2e/relay) e2e_relay ;;
    e2e/shutdown) e2e_shutdown ;;
    docs/*) docslink_check; html_structure_check; intended_coverage_gate; cfg_test_parentage_gate; unsafe_surface_gate; canonical_digest_gate ;;
    *) usage ;;
esac
