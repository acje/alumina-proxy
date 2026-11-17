#!/bin/sh
set -eu

# =============================================================================
# verify.sh — native verification entry point (gate coordinator)
#
# Single owner of the gate ceremony: INNER (host compile), MID (Linux-only
# behaviour proofs), BOUNDARY (candidate ceremony), and the fixtures/e2e native
# gates. Governing spec: docs/alumina-proxy.md. Command set and gate ordering:
# docs/verification.md. Status and prerequisites: docs/qa-package/README.md.
#
# Do not run build or fixture checks concurrently: they share target/release
# and the fixture volumes.
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
    echo "usage: verify.sh {inner|mid|host-mid|fixtures|e2e|supply-chain|identity|gate-children} <scope> [args] | verify.sh docs" >&2
    echo "       inner test <target> runs ONE integration target host-natively; backs no done-claim." >&2
    echo "       host-mid {foundations|boot|union|full|clippy}; supply-chain audit-deny" >&2
    echo "       gate-children scan asserts no reparented gate child survives under the debug build roots this gate builds into (cargo metadata target_directory and ALT_AW_TARGET_DIR)" >&2
    echo "       identity snapshot <directory> | identity compare <before> <after> | identity artifact <path>" >&2
    exit 2
}

[ -n "$TIER" ] || usage
[ -n "$SCOPE" ] || [ "$TIER" = "docs" ] || usage
FOCUS="${3:-}"

# There is no toolchain pin: host commands resolve the host's default toolchain
# and container dispatches resolve the base image's default toolchain.

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
# arise and no ordering workaround is needed. `-` not `:-`: an explicitly empty
# knob is a typo the leak scan refuses (it cannot derive an argv[0] from it),
# never a silent request for the default.
ALT_AW_TARGET_DIR="${ALT_AW_TARGET_DIR-target/aw}"
# I3: one derived, digest-identified image, built once FROM the pinned rust base.
# Evidence for why: the pinned base carries NO git, NO clippy and NO rustfmt
# (`rustup component list --installed` = cargo/rustc/rust-std only; `command -v
# git` empty), so verify.sh re-downloads all three on EVERY dispatch
# (`rustup component add clippy rustfmt` + `apk add git`), and its fresh
# /cargo-home re-downloads all 50 crates every time. Baking the extras once and
# persisting CARGO_HOME in a volume removes three repeated network costs from the
# measured path. The base digest is quoted in the generated Containerfile and
# every dispatch records the derived image ID.
ALT_IMAGE="${ALT_IMAGE:-localhost/alumina-verify:20261114}"
FIXTURE_IMAGE="${FIXTURE_IMAGE:-$ALT_IMAGE}"
FIXTURE_BASE_IMAGE="docker.io/library/rust@sha256:18b6dc7bc111bde4e2fccf6c4ec95cc4a3486b41e4b090e9b0202eba9540023e"

# --- I0: timing instrumentation ---------------------------------------------
# Millisecond timestamps from python3 (an already-required boundary prerequisite,
# see config_observe). A host without it prints `NA` rather than a fabricated
# number: an unmeasured phase must never look measured.
now_ms() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'NA\n'
        return 0
    }
    python3 -c 'import time; print(int(time.time()*1000))'
}

# phase_mark <label> <ms>: emit a timing line for a phase measured inline (the
# Linux dispatch, the fixture run, a copy-out) where no function call brackets it.
phase_mark() {
    printf 'PHASE1-TIMING: %s %s\n' "$1" "$2"
}

INTENDED="Cargo.toml Cargo.lock deny.toml scripts/verify.sh scripts/cargo_config_probe.py scripts/fixture_metadata_probe.py README.md src/lib.rs src/main.rs src/alloc.rs src/bin/parser_bench.rs src/qa/mod.rs src/qa/fuzz.rs src/config/fqdn_tests.rs src/config/mod.rs src/config/cname_bailiwick_config_tests.rs src/config/enforcement_config_tests.rs src/config/resolver_config_tests.rs src/dns/resolver.rs src/dns/resolver/tests.rs src/boot/preflight.rs src/inventory.rs src/boot/mod.rs src/boot/tests.rs src/dns/cache.rs src/dns/cache/grade_key.rs src/dns/cache/grade_key/tests.rs src/dns/cache/tests.rs src/inspection/mod.rs src/inspection/connect.rs src/inspection/connect/tests.rs src/inspection/client_hello.rs src/inspection/client_hello/ja4.rs src/inspection/client_hello/tests.rs src/dns/mod.rs src/dns/outcome.rs src/dns/publication.rs src/dns/wire.rs src/dns/wire/tests.rs src/eligibility.rs src/enforcement/action.rs src/enforcement/mod.rs src/enforcement/monitor.rs src/enforcement/monitor/tests.rs src/enforcement/policy.rs src/enforcement/policy/tests.rs src/enforcement/state.rs src/enforcement/state/tests.rs src/dns/incident_report.rs src/dns/incident_report/tests.rs src/names/mod.rs src/names/hostname.rs src/names/hostname/tests.rs src/names/rules.rs src/log/mod.rs src/log/queue.rs src/log/sink.rs src/log/encoding.rs src/log/tests.rs src/runtime/gate.rs src/runtime/mod.rs src/runtime/owner.rs src/runtime/owner/tests.rs src/runtime/reactor.rs src/runtime/reactor/policy.rs src/runtime/reactor/reject.rs src/runtime/reactor/startup.rs src/runtime/reactor/tests.rs src/runtime/reactor/tests/refusals.rs src/runtime/storage.rs src/runtime/storage/startup_integration.rs src/runtime/storage/tests.rs src/runtime/tunnel.rs src/runtime/tunnel/tests.rs src/dns/schedule.rs src/dns/schedule/tests.rs src/dns/transport.rs src/dns/transport/registration.rs src/dns/transport/tests.rs src/dns/transport/tests/shared_armed_cache.rs src/dns/transport/dot_tests.rs tests/foundations.rs tests/boot.rs tests/support/temp_dir.rs tests/support/enforcement_tables.rs tests/support/dns_responder.rs tests/support/process_harness.rs tests/eligibility.rs tests/binary_entry.rs tests/main_thread_serving.rs tests/mio_matrix.rs tests/monitor_stdout.rs tests/stdout_stall.rs tests/stdout_closed.rs"

# Doc-gate roots: the primary docs the identity snapshot covers. The Repowise
# drift gate scans the full tracked corpus; this list keeps the boundary
# content identity stable for the docs that gate reads most.
DOC_GATE_ROOTS="docs/alumina-proxy.md docs/trust-chain-design.md docs/deployment.md docs/monitoring.md docs/verification.md docs/qa-package/README.md README.md"

# B1: every relevant before/after identity input consumed by the boundary run:
# source/config/lock/deny plus the docs and .gitignore that the docs gate and
# the working-tree view consume. Changing build outputs (the compiled artifact)
# are intentionally excluded from this stability set and are recorded separately
# at executed output. README.md is already covered by INTENDED; the remaining
# DOC_GATE_ROOTS are added here so a gate-root edit cannot silently drop an
# identity input.
GATE_ROOT_EXTRAS=""
for root in $DOC_GATE_ROOTS; do
    case " $INTENDED " in
        *" $root "*) ;;
        *) GATE_ROOT_EXTRAS="$GATE_ROOT_EXTRAS $root" ;;
    esac
done
IDENTITY_FILES="$INTENDED .gitignore AGENTS.md$GATE_ROOT_EXTRAS scripts/verify_test.py docs/qa-package/validate.sh docs/qa-package/validate_test.py"

# Keep snapshot locations under target/ so they do not alter working-tree status.
# scripts/verify.sh is itself an identity input in INTENDED.

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

# The repository proof: native git must answer, see the actual checkout and
# report no whitespace error in the tracked diff. Sets `head` for the marker.
whitespace_gate_git() {
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
}

# Missing-file fail-closed check FIRST (identical to the prior per-file loop):
# every intended file must exist before any content scan.
whitespace_gate_intended_present() {
    for f in $INTENDED; do
        [ -f "$f" ] || {
            echo "whitespace FAIL: intended file missing: $f" >&2
            exit 1
        }
    done
}

whitespace_gate_scan() {
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
}

# The whitespace gate: git proof, intended-file presence, then the content scan.
whitespace_gate() {
    whitespace_gate_git
    whitespace_gate_intended_present
    whitespace_gate_scan
    echo "WHITESPACE-GATE-OK (native git, HEAD=$head)"
}

# --- gate-child leak assertion ----------------------------------------------
# A gate-spawned child, or a cargo lib-test child, that outlives its parent
# keeps a loopback listener alive, so every later gate receipt is
# chain-ambiguous. The scan matches the EXECUTED program (argv[0]) of a
# reparented process (ppid 1) against every debug build root this gate builds
# into. The roots are derived, never assumed:
#
#   witness-off  <target_directory>/debug/build/alumina, where target_directory
#                is what `cargo metadata --no-deps --format-version 1 --locked`
#                reports. Cargo's own answer is the authority because it honours
#                CARGO_TARGET_DIR and a config-file build.target-dir; a
#                hardcoded <checkout>/target is exactly the root such a setting
#                vacates, so a real orphan there would report clean.
#   witness-on   <checkout>/<ALT_AW_TARGET_DIR>/debug/build/alumina for a
#                relative knob, with trailing slashes stripped, or the absolute
#                directory itself.
#
# Every SOURCE value — each checkout spelling, cargo's target_directory answer,
# and ALT_AW_TARGET_DIR — is bound BEFORE composition: any whitespace in it (LF,
# CR, TAB, space) is refused, because a root carrying whitespace cannot be
# delimited from the process arguments in the line-oriented listing. Each root is
# then carried as ONE value (positional parameter, then a per-root environment
# value for the matcher), never as a line in a joined list that is re-split
# later. The per-root whitespace check after composition stays as a second belt,
# never as the protection itself.
#
# The sources are then normalised or refused: a trailing separator is provably
# harmless, while an empty value, the filesystem root '/', or one carrying a
# '.'/'..'/empty component is refused (cargo would exec from a path the scan
# cannot derive from it). The metadata answer needs the same treatment — cargo
# reports it verbatim, so CARGO_TARGET_DIR=target/aw/ and ./target survive into
# it (measured) — and an answer carrying the key more than once is ambiguous,
# refused rather than resolved last-wins. Both the logical and physical checkout
# spelling are covered where they differ, deduped.
# Within a root the shape is <hash>/out/<gate-binary>-<hash>. A path that
# merely appears among a process's arguments (a compiler writing into that
# directory, `ld -o .../out/...`) is not a match. Both the procps and busybox
# `ps` forms are tried; when only a form without -ww answers, a visible
# GATE-CHILD-LEAK-NOTE records that argv[0] may be truncated, because busybox
# has no portable unbounded form and refusing the fallback would red every
# busybox host (residual, docs/verification.md).
# An operational failure - no usable `ps`, no `awk`, an empty, whitespace-bearing
# or non-absolute checkout spelling, an ambiguous, empty, whitespace-bearing or
# otherwise unprovable build root, an unparsable listing, a listing that cannot
# see this shell, or no root at all - is GATE-CHILD-LEAK-UNKNOWN and fails: an
# observation failure is never a clean gate.
#
# _gl_component_check <value> <label>: refuse a directory spelling that carries
# an empty, '.' or '..' component. cargo resolves such a spelling to a path the
# scan cannot derive (only a trailing separator is provably irrelevant), so the
# scan names the offending spelling and fails closed instead of composing a root
# that cannot match what cargo execs.
_gl_component_check() {
    _gc_value="$1"
    _gc_label="$2"
    _gc_rest="${_gc_value#/}"
    while :; do
        case "$_gc_rest" in
            */*) _gc_comp="${_gc_rest%%/*}" ; _gc_rest="${_gc_rest#*/}" ;;
            *) _gc_comp="$_gc_rest" ; _gc_rest="" ;;
        esac
        case "$_gc_comp" in
            "" | . | ..)
                echo "GATE-CHILD-LEAK-UNKNOWN: $_gc_label='$_gc_value' contains an empty, '.' or '..' path component; the scan cannot prove which argv[0] cargo execs from a non-canonical spelling" >&2
                return 1
                ;;
        esac
        [ -n "$_gc_rest" ] || break
    done
}

# _gl_source_bind <value> <label>: bind a build-root SOURCE value before it is
# composed. Each root is carried as ONE value — a positional parameter from
# composition, then a per-root environment value for the matcher — never as a
# line in a joined list, so any whitespace in a source value would still leave a
# root the line-oriented listing cannot delimit unambiguously. The refusal
# therefore binds the value itself, and it covers every whitespace class — LF,
# CR, TAB and space — not only the space a composed root would carry.
# `[[:space:]]` in `case` matches CR here (measured, POSIX sh).
_gl_source_bind() {
    case "$1" in
        *[[:space:]]*)
            echo "GATE-CHILD-LEAK-UNKNOWN: $2 contains whitespace (LF, CR, TAB or space); the scan binds each source value before composition, and a root carrying whitespace cannot be delimited from the process arguments" >&2
            return 1
            ;;
    esac
}

# _gl_build_root_source_check <value> <label>: '/' is a real value refused for
# its real reason — the filesystem root can never be a build root. The
# empty-component text would name a cause that is not the case.
_gl_build_root_source_check() {
    case "$1" in
        /)
            echo "GATE-CHILD-LEAK-UNKNOWN: $2='/' is the filesystem root, which cannot be a build root; the scan would look for /debug/build/alumina where nothing is built" >&2
            return 1
            ;;
    esac
}

assert_no_leaked_gate_children() {
    _gl_ps=""
    _gl_wide=0
    for _gl_form in "-ww -eo pid=,ppid=,args=" "-eo pid=,ppid=,args=" "-o pid=,ppid=,args=" "-ww -o pid=,ppid=,args="; do
        # shellcheck disable=SC2086
        if _gl_ps=$(COLUMNS=4096 ps $_gl_form 2>/dev/null); then
            case " $_gl_form " in
                *" -ww "*) _gl_wide=1 ;;
            esac
            break
        fi
        _gl_ps=""
    done
    if [ -z "$_gl_ps" ]; then
        echo "GATE-CHILD-LEAK-UNKNOWN: ps produced no process listing (procps and busybox forms both failed; operational error is never clean)" >&2
        return 1
    fi
    command -v awk >/dev/null 2>&1 || {
        echo "GATE-CHILD-LEAK-UNKNOWN: awk required for the scan and absent (operational error is never clean)" >&2
        return 1
    }
    if [ "$_gl_wide" -ne 1 ]; then
        echo "GATE-CHILD-LEAK-NOTE: no ps form this host accepts carries -ww, so a long argv[0] may be truncated and a real leak can look matchless (residual, see docs/verification.md)" >&2
    fi
    # Checkout spellings, validated BEFORE composition: an empty or relative
    # `pwd` would otherwise compose /target/debug/build/alumina — a root that is
    # not this checkout at all. The two spellings are carried as two values, not
    # as a joined list.
    _gl_cwd_logical=$(pwd)
    _gl_cwd_physical=$(pwd -P)
    for _gl_checkout in "$_gl_cwd_logical" "$_gl_cwd_physical"; do
        _gl_source_bind "$_gl_checkout" "checkout spelling" || return 1
        case "$_gl_checkout" in
            /*) ;;
            *)
                echo "GATE-CHILD-LEAK-UNKNOWN: checkout spelling is not an absolute path: '$_gl_checkout' (the scan cannot compose a build root under it)" >&2
                return 1
                ;;
        esac
    done
    # The witness-off root: cargo's own answer, or nothing. A fallback to
    # <checkout>/target would rebuild the fail-open this derivation removes.
    _gl_meta_rc=0
    _gl_meta_out=$(cargo metadata --no-deps --format-version 1 --locked 2>/dev/null) || _gl_meta_rc=$?
    [ "$_gl_meta_rc" -eq 0 ] || {
        echo "GATE-CHILD-LEAK-UNKNOWN: cargo metadata --no-deps exit $_gl_meta_rc; no target_directory to derive the witness-off build root from, and there is no fallback (operational error is never clean)" >&2
        return 1
    }
    # The field is read as an exact JSON string value: the value must close on an
    # unescaped quote and carry no backslash, so a JSON-escaped path yields no
    # value at all and fails closed below rather than being guessed at. A key
    # that appears more than once is ambiguous, not last-wins: choosing by order
    # could scan a root cargo never uses.
    _gl_meta_awk_rc=0
    _gl_meta=$(printf '%s\n' "$_gl_meta_out" | awk -v key='"target_directory":"' '
        {
            line = $0
            while ((i = index(line, key)) > 0) {
                hits++
                rest = substr(line, i + length(key))
                j = index(rest, "\"")
                if (j == 0) break
                val = substr(rest, 1, j - 1)
                if (val != "" && val !~ /\\/) found = val
                line = substr(rest, j + 1)
            }
        }
        END {
            if (hits > 1) exit 4
            if (found != "") printf "%s", found
        }
    ') || _gl_meta_awk_rc=$?
    case "$_gl_meta_awk_rc" in
        0) ;;
        4)
            echo "GATE-CHILD-LEAK-UNKNOWN: cargo metadata reports target_directory more than once; the answer is ambiguous and the scan will not resolve it by order (last-wins could scan a root cargo never uses)" >&2
            return 1
            ;;
        *)
            echo "GATE-CHILD-LEAK-UNKNOWN: target_directory extraction exit $_gl_meta_awk_rc (operational error is never clean)" >&2
            return 1
            ;;
    esac
    # Bind the answer BEFORE it is normalised or composed: a root carrying
    # whitespace cannot be delimited from the arguments (see _gl_source_bind).
    _gl_source_bind "$_gl_meta" "cargo metadata target_directory" || return 1
    _gl_build_root_source_check "$_gl_meta" "cargo metadata target_directory" || return 1
    # The metadata answer is normalised the same way as the knob, because it is
    # the same hazard from the other entrance: it comes from CARGO_TARGET_DIR or
    # a config build.target-dir, and cargo reports such a value verbatim (a
    # trailing separator and a './' component are both preserved — measured).
    # A trailing separator is provably harmless (a path join never repeats one);
    # anything else is refused rather than composed into an unmatchable root.
    while [ "${_gl_meta%/}" != "$_gl_meta" ]; do
        _gl_meta="${_gl_meta%/}"
    done
    [ -n "$_gl_meta" ] || {
        echo "GATE-CHILD-LEAK-UNKNOWN: cargo metadata reported an empty target_directory; the witness-off build root cannot be derived (operational error is never clean)" >&2
        return 1
    }
    case "$_gl_meta" in
        /*) ;;
        *)
            echo "GATE-CHILD-LEAK-UNKNOWN: cargo metadata target_directory is not absolute: '$_gl_meta' (the scan cannot compose a build root under it)" >&2
            return 1
            ;;
    esac
    _gl_component_check "$_gl_meta" "cargo metadata target_directory" || return 1
    # The witness-on knob: bind the SOURCE value first, then strip trailing
    # slashes (cargo's own Path join never repeats a separator, so "target/aw/"
    # and "target/aw" are one root), then refuse every spelling whose argv[0] the
    # scan cannot derive.
    _gl_source_bind "$ALT_AW_TARGET_DIR" "ALT_AW_TARGET_DIR" || return 1
    _gl_build_root_source_check "$ALT_AW_TARGET_DIR" "ALT_AW_TARGET_DIR" || return 1
    _gl_aw="$ALT_AW_TARGET_DIR"
    while [ "${_gl_aw%/}" != "$_gl_aw" ]; do
        _gl_aw="${_gl_aw%/}"
    done
    [ -n "$_gl_aw" ] || {
        echo "GATE-CHILD-LEAK-UNKNOWN: ALT_AW_TARGET_DIR='$ALT_AW_TARGET_DIR' is empty; the witness-on build root cannot be derived" >&2
        return 1
    }
    case "$_gl_aw" in
        /*) _gl_aw_abs=1 ;;
        *) _gl_aw_abs=0 ;;
    esac
    _gl_component_check "$_gl_aw" "ALT_AW_TARGET_DIR" || return 1
    # Candidate roots, composed in the shell into POSITIONAL PARAMETERS: each
    # root is one value from composition to matching, so no representation step
    # can re-split it. The metadata answer lies under one checkout spelling; the
    # same path is then composed under every spelling, because a child argv[0]
    # carries whichever spelling the build owner resolved. An answer outside the
    # checkout (CARGO_TARGET_DIR elsewhere) is used as given. The prefix strip is
    # exact and quoted (`${_gl_meta#"$_gl_checkout"/}`), so no glob is active.
    set --
    _gl_tail=""
    for _gl_checkout in "$_gl_cwd_logical" "$_gl_cwd_physical"; do
        case "$_gl_meta" in
            "$_gl_checkout"/*)
                _gl_tail=${_gl_meta#"$_gl_checkout"/}
                break
                ;;
        esac
    done
    for _gl_checkout in "$_gl_cwd_logical" "$_gl_cwd_physical"; do
        if [ -n "$_gl_tail" ]; then
            _gl_off="$_gl_checkout/$_gl_tail"
        else
            _gl_off=$_gl_meta
        fi
        if [ "$_gl_aw_abs" -eq 1 ]; then
            _gl_aw_base=$_gl_aw
        else
            _gl_aw_base="$_gl_checkout/$_gl_aw"
        fi
        for _gl_candidate in "$_gl_off/debug/build/alumina" \
            "$_gl_aw_base/debug/build/alumina"; do
            _gl_dup=0
            for _gl_root in "$@"; do
                if [ "$_gl_root" = "$_gl_candidate" ]; then
                    _gl_dup=1
                    break
                fi
            done
            if [ "$_gl_dup" -eq 0 ]; then
                set -- "$@" "$_gl_candidate"
            fi
        done
    done
    # A root that the line-oriented listing cannot represent unambiguously is
    # refused before the scan. This is a second belt, never the protection: a
    # source value carrying whitespace is already refused before composition.
    for _gl_root in "$@"; do
        case "$_gl_root" in
            *[[:space:]]*)
                echo "GATE-CHILD-LEAK-UNKNOWN: build root contains whitespace, argv[0] is not separable from the arguments: $_gl_root" >&2
                return 1
                ;;
        esac
    done
    [ "$#" -gt 0 ] || {
        echo "GATE-CHILD-LEAK-UNKNOWN: the scan built no build root to match (operational error is never clean)" >&2
        return 1
    }
    # The OK line must name every root the scan covered, read from the same value
    # list the matcher consumes, and annotate a root that does not exist yet so a
    # mis-spelling is visible in the receipt rather than silently matchless.
    # (Absence is legitimate before a first build, so it cannot be fatal.)
    _gl_named=""
    for _gl_root in "$@"; do
        if [ -d "$_gl_root" ]; then
            _gl_named="$_gl_named${_gl_named:+, }$_gl_root"
        else
            _gl_named="$_gl_named${_gl_named:+, }$_gl_root (absent)"
        fi
    done
    # One matcher pass per root, each root handed to awk as a SINGLE value via
    # the environment (not `-v`, which rewrites escape sequences in its value),
    # so no joined word list is ever re-parsed.
    _gl_bad=0
    _gl_unlisted=0
    _gl_parse_rc=0
    _gl_out=""
    for _gl_root in "$@"; do
        _gl_rc=0
        _gl_root_out=$(printf '%s\n' "$_gl_ps" | GL_ROOT="$_gl_root" awk -v self="$$" '
            NF >= 3 {
                pid = $1 + 0
                if (pid == self) seen_self = 1
                if ($2 + 0 != 1) next
                rest = $0
                sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest)
                argv0 = rest
                sub(/[ \t].*$/, "", argv0)
                prefix = ENVIRON["GL_ROOT"] "/"
                if (index(argv0, prefix) != 1) next
                tail = substr(argv0, length(prefix) + 1)
                if (tail ~ /^[0-9a-f]+\/out\/[A-Za-z0-9_]+-[0-9a-f]+$/) {
                    printf "pid=%s ppid=1 argv0=%s\n", pid, argv0
                    bad = 1
                }
            }
            END {
                if (!seen_self) { print "SELF-NOT-LISTED"; exit 2 }
                exit (bad ? 1 : 0)
            }
        ') || _gl_rc=$?
        case "$_gl_rc" in
            0) ;;
            1) _gl_bad=1 ;;
            2) _gl_unlisted=1 ;;
            *) _gl_parse_rc=$_gl_rc ;;
        esac
        _gl_out="$_gl_out$_gl_root_out"
    done
    if [ "$_gl_unlisted" -ne 0 ]; then
        echo "GATE-CHILD-LEAK-UNKNOWN: ps listing does not contain this shell (pid $$); the observation is unusable" >&2
        return 1
    fi
    if [ "$_gl_parse_rc" -ne 0 ]; then
        echo "GATE-CHILD-LEAK-UNKNOWN: listing parse exit $_gl_parse_rc (operational error is never clean)" >&2
        return 1
    fi
    if [ "$_gl_bad" -ne 0 ]; then
        printf '%s' "$_gl_out" | sed 's/^/  /' >&2
        echo "GATE-CHILD-LEAK-FAIL: a gate child outlived its parent (ppid 1); it keeps a loopback listener alive and makes every later gate receipt chain-ambiguous" >&2
        return 1
    fi
    echo "GATE-CHILD-LEAK-OK: no reparented gate child under $_gl_named"
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
    cargo atest -p alumina --locked --features alloc-witness --test foundations
    echo "WITNESS-OFF-TESTS (checked-in parser corpus + deterministic campaign/ownership + public-API availability; the F5/F4 remainder):"
    cargo atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo fmt --check
    whitespace_gate
    echo "FOUNDATIONS-MID-OK"
}

mid_boot() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "boot mid requires Linux execution" >&2
        exit 1
    }
    echo "BOOT-TESTS (strict parser + validated types + storage inventory):"
    cargo atest -p alumina --locked --test boot
    echo "BOOT-TESTS-WITNESS (alloc retention bound):"
    cargo atest -p alumina --locked --features alloc-witness --test boot
    echo "FOUNDATIONS-REGRESSION:"
    cargo atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo fmt --check
    whitespace_gate
    echo "BOOT-MID-OK"
}

# Boundary-only union of the `mid foundations` and `mid boot` command sets,
# executed once each so the boundary never runs the same native command twice.
# `GATE_ONLY_TESTS` and `ALLOC_WITNESS_ONLY_TESTS` are the single source for the
# gate-only integration binaries, so `mid union` and `mid full` stay in lockstep.
# The ordering below is binding (clippy pair adjacent; alloc-witness tests only
# after the alloc-witness clippy pass) — rationale and cost structure:
# docs/verification.md § Gate ordering and cost structure.
# These binaries compile and assert in BOTH feature configurations, so each one
# is a real proof in a witness-off run and in a witness-on run alike.
GATE_ONLY_TESTS="--test eligibility --test binary_entry --test main_thread_serving --test monitor_stdout --test stdout_stall --test stdout_closed"

# Witness-on only. `mio_matrix`'s crate root is `#![cfg(feature =
# "alloc-witness")]`, so a witness-off build compiles an EMPTY binary whose
# "pass" proves nothing — it is never evidence in a witness-off invocation and
# is listed only in the alloc-witness one.
ALLOC_WITNESS_ONLY_TESTS="--test mio_matrix"

# The whole-surface union: lib units + foundations + boot + the both-configuration
# gate-only binaries; the witness-on pass adds ALLOC_WITNESS_ONLY_TESTS.
ALT_TEST_TARGETS="--test foundations --test boot $GATE_ONLY_TESTS"

# --- lib-suite budget --------------------------------------------------------
# libtest has no timeout of its own, so a suite that deadlocks on a read is
# indistinguishable from a slow one and consumes the whole gate window.
# Measured here: the green bracketed lib run reports its test execution at ~38 s
# (35.8-39.7 s over the recorded union runs), while the wedged one showed no
# progress past 60 s and was still wedged at 9 minutes. The bound covers the
# WHOLE `cargo atest` invocation, so a cold build sits inside the same 600 s
# (that cost is unmeasured). The environment knob exists so the bound can be
# proven behaviourally (a 1 s budget against `sleep 30`), not to be tuned day to
# day. 600 is a default, never a switch: a value that cannot bound anything --
# empty, zero, signed, fractional, or otherwise non-decimal -- is refused by the
# helper below, because both wrappers this repo resolves read a duration of 0 as
# "no limit" and a receipt line must never name a bound that is not enforced.
# The `${VAR-default}` spelling (no colon) is deliberate -- unset takes 600,
# while an explicitly empty value stays empty and fails closed below.
GATE_SUITE_BUDGET_SECS="${GATE_SUITE_BUDGET_SECS-600}"

# The stack budget is this helper's to own, not its callers'. The lib surface
# overflows a smaller default test-thread stack (observed on darwin, where the
# suite dies at libtest exit 101 with no failing test and reads as a product
# symptom), so a suite run without it is not evidence. It used to be supplied
# only by the Linux dispatch `-e` flags and by hand-written command prefixes, so
# a call that omitted it turned a healthy suite into that exit 101 -- exactly
# what happened at 22144 and was nearly filed as a bug. 16777216 is therefore a
# FLOOR as well as the default: a smaller caller value is refused, never run.
# The `${VAR-default}` spelling (no colon) is deliberate -- unset takes the
# floor, while an explicitly empty value stays empty and fails closed below.
GATE_SUITE_MIN_STACK_FLOOR=16777216
GATE_SUITE_MIN_STACK="${GATE_SUITE_MIN_STACK-$GATE_SUITE_MIN_STACK_FLOOR}"

# bounded_suite <command...>: run one lib suite under that budget. Both knobs are
# validated first, so neither an unbounded, unknown-length nor under-budgeted run
# reaches a wrapper: the stack value is exported as RUST_MIN_STACK for the
# invocation this helper wraps, and the budget is normalised to a strictly
# positive decimal integer. A budget is a bound or it is a refusal -- a duration
# of 0 is "no limit" to both wrappers, so zero is refused rather than passed on,
# and leading zeros are stripped so no parser can read `0600` as octal or as 0.
# `timeout` is resolved next, then `gtimeout` (the coreutils spelling); with
# neither on PATH the run is refused, because an unavailable bound is not an
# unbounded pass. The budget is enforced with SIGKILL in the portable `-s KILL`
# form that both GNU and busybox timeout accept, so a suite cannot ignore the
# bound. Timeout statuses are 124 (conventional) and 137 (measured for a KILLed
# child under GNU coreutils); libtest's own failure exit 101 passes through
# unchanged and is never labelled a timeout.
bounded_suite() {
    case "$GATE_SUITE_MIN_STACK" in
        "" | *[!0-9]*)
            echo "GATE-SUITE-STACK-UNKNOWN: GATE_SUITE_MIN_STACK is '${GATE_SUITE_MIN_STACK}' -- not a byte count; refusing to run a lib suite at an unknown test-thread stack" >&2
            return 1
            ;;
    esac
    if [ "$GATE_SUITE_MIN_STACK" -lt "$GATE_SUITE_MIN_STACK_FLOOR" ]; then
        echo "GATE-SUITE-STACK-UNKNOWN: GATE_SUITE_MIN_STACK=${GATE_SUITE_MIN_STACK} is below the ${GATE_SUITE_MIN_STACK_FLOOR}-byte floor; refusing to run an under-budgeted lib suite" >&2
        return 1
    fi
    case "$GATE_SUITE_BUDGET_SECS" in
        "" | *[!0-9]*)
            echo "GATE-SUITE-TIMEOUT-UNKNOWN: GATE_SUITE_BUDGET_SECS is '${GATE_SUITE_BUDGET_SECS}' -- not a decimal integer; refusing to run a lib suite under a budget that cannot bound it" >&2
            return 1
            ;;
    esac
    _bs_budget_secs="$GATE_SUITE_BUDGET_SECS"
    while :; do
        case "$_bs_budget_secs" in
            0?*) _bs_budget_secs="${_bs_budget_secs#0}" ;;
            *) break ;;
        esac
    done
    if [ "$_bs_budget_secs" = 0 ]; then
        echo "GATE-SUITE-TIMEOUT-UNKNOWN: GATE_SUITE_BUDGET_SECS=0 is a duration of zero, which both timeout and gtimeout read as 'no limit'; refusing to run a lib suite under a bound of zero" >&2
        return 1
    fi
    export RUST_MIN_STACK="$GATE_SUITE_MIN_STACK"
    _bs_wrapper=""
    for _bs_candidate in timeout gtimeout; do
        if command -v "$_bs_candidate" >/dev/null 2>&1; then
            _bs_wrapper="$_bs_candidate"
            break
        fi
    done
    if [ -z "$_bs_wrapper" ]; then
        echo "GATE-SUITE-TIMEOUT-UNKNOWN: neither timeout nor gtimeout is on PATH; refusing to run a lib suite unbounded (operational absence is never a pass)" >&2
        return 1
    fi
    echo "GATE-SUITE-BOUND: $_bs_wrapper -s KILL ${_bs_budget_secs}s RUST_MIN_STACK=${RUST_MIN_STACK}: $*"
    _bs_rc=0
    "$_bs_wrapper" -s KILL "$_bs_budget_secs" "$@" || _bs_rc=$?
    case "$_bs_rc" in
        0) ;;
        124 | 137)
            echo "GATE-SUITE-TIMEOUT-FAIL: lib suite exceeded the ${_bs_budget_secs}s budget and was killed ($_bs_wrapper exit $_bs_rc); a wedged suite is a failure, not a slow run" >&2
            ;;
    esac
    return "$_bs_rc"
}

mid_union() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "mid union requires Linux execution" >&2
        exit 1
    }
    closure_metadata
    echo "PRODUCTION-RELEASE-BUILD (boundary union, no alloc-witness):"
    cargo build --locked --release
    static_gate "target/release/alumina"
    echo "FMT:"
    cargo fmt --check
    echo "COMBINED-SUITE-WITNESS-OFF (lib units + foundations + boot + both-configuration gate-only binaries):"
    assert_no_leaked_gate_children
    # shellcheck disable=SC2086
    bounded_suite cargo atest -p alumina --locked --lib $ALT_TEST_TARGETS
    assert_no_leaked_gate_children
    echo "GATE-ONLY-SUITE-WITNESS-OFF-OK"
    echo "CLIPPY (production, no alloc-witness):"
    cargo aclippy -p alumina --locked --all-targets -- -D warnings
    echo "CLIPPY (test-harness with alloc-witness; target dir ${ALT_AW_TARGET_DIR}):"
    cargo aclippy -p alumina --locked --target-dir "$ALT_AW_TARGET_DIR" --all-targets --features alloc-witness -- -D warnings
    echo "COMBINED-SUITE-WITNESS-ON (same surface + alloc-witness-only mio_matrix, alloc-witness):"
    # shellcheck disable=SC2086
    bounded_suite cargo atest -p alumina --locked --target-dir "$ALT_AW_TARGET_DIR" --features alloc-witness --lib $ALT_TEST_TARGETS $ALLOC_WITNESS_ONLY_TESTS
    assert_no_leaked_gate_children
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
    cargo atest -p alumina --locked --features alloc-witness --test foundations
    echo "CLIPPY (production, no alloc-witness):"
    cargo aclippy -p alumina --locked --all-targets -- -D warnings
    echo "CLIPPY (test-harness with alloc-witness):"
    cargo aclippy -p alumina --locked --all-targets --features alloc-witness -- -D warnings
    echo "CLIPPY-MID-OK"
}

# G8-C02 test-coverage closure: runs the gate-only test surface — lib unit tests
# + the both-configuration gate-only integration binaries (GATE_ONLY_TESTS:
# eligibility, binary_entry, main_thread_serving, monitor_stdout, stdout_stall,
# stdout_closed; binary_entry is the only one that executes the real binary)
# witness-off, then witness-on (which adds the alloc-witness-only mio_matrix) —
# closing the gate coverage hole where lib units and these binaries never ran in
# any gate selector (all prior atest invocations carried --test
# foundations|boot). foundations and boot are NOT re-run here: they already run
# in mid union within the same BOUNDARY dispatch
# (and in the mid foundations / mid boot inner loops), so re-running them here
# would duplicate work without adding coverage.
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
    echo "GATE-ONLY-SUITE (lib units + both-configuration gate-only binaries, witness-off):"
    assert_no_leaked_gate_children
    # shellcheck disable=SC2086
    bounded_suite cargo atest -p alumina --locked --lib $GATE_ONLY_TESTS
    assert_no_leaked_gate_children
    echo "GATE-ONLY-SUITE-WITNESS-OFF-OK"
    echo "GATE-ONLY-SUITE-WITNESS (the same surface + alloc-witness-only mio_matrix, alloc-witness):"
    # shellcheck disable=SC2086
    bounded_suite cargo atest -p alumina --locked --target-dir "$ALT_AW_TARGET_DIR" --features alloc-witness --lib $GATE_ONLY_TESTS $ALLOC_WITNESS_ONLY_TESTS
    assert_no_leaked_gate_children
    echo "GATE-ONLY-SUITE-WITNESS-ON-OK"
    echo "GATE-ONLY-SUITE-MID-OK"
}

# --- boot fixture capture and assertion owners ------------------------------
# One fixture case = one podman run of the digest-pinned variant plus assertions
# over the RAW captured streams. These owners are deliberately top-level: the
# capture initialisation and the case sequence stay in boot_fixtures, every
# reusable piece lives here.
#
# The staged inputs are written into a disposable container /work dir
# (cwd-relative contract: main.rs reads config.toml, incl. the resolver set,
# from the working directory), then privileges are dropped inside that dir.
# I3: no package install here any more. util-linux (setpriv), python3 and git
# are baked into the digest-pinned fixture image, so a fixture case performs
# no network I/O and cannot fail on a flaky mirror.
fixture_stage_script() {
    printf '%s\n' \
        'set -eu' \
        'python3 /app/scripts/fixture_metadata_probe.py /fixture-alumina "$1" >/dev/null' \
        'setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c "test -x /fixture-alumina" || { echo "FIXTURE-BLOCKED: variant not executable by uid 65534" >&2; exit 1; }' \
        'mkdir -p /work' \
        "printf '%s\\n' 'listen = \"0.0.0.0:8080\"' 'startup_unresolved_allowance = 0' 'resolver = [\"127.0.0.1\"]' '[any_illegal]' 'connect_parse = { action = \"notify\", scope = \"connection\" }' 'host_not_allowlisted = { action = \"notify\", scope = \"connection\" }' 'tls_profile = { action = \"notify\", scope = \"connection\" }' 'ech = { action = \"notify\", scope = \"connection\" }' '[allowed_fqdn.\"example.com:443\"]' 'early_data = { action = \"notify\", scope = \"connection\" }' 'ja4 = { action = \"notify\", scope = \"connection\" }' 'dns_assurance = \"resolver_trusted\"' > /work/config.toml" \
        'chown -R 65534:65534 /work'
    true
}

fixture_run_case() {
    _frc_label="$1"
    _frc_expected="$2"
    conn="$3"
    shift 3
    run_cmd="$1"
    shift
    FIXTURE_LABEL="$_frc_label"
    > "$outf"
    > "$errf"
    set +e
    podman --connection "$conn" run --rm --pull=never \
        -v "$ROOT:/app:ro,Z" \
        -v "$VARBIN:/fixture-alumina:ro,Z" \
        "$@" "$FIXTURE_IMAGE" sh -c "$(fixture_stage_script) && $run_cmd" -- "$variant_sha" >"$outf" 2>"$errf"
    rc=$?
    set -e
    FIXTURE_OUTF="$outf"
    FIXTURE_ERRF="$errf"
    echo "FIXTURE $_frc_label: exit=$rc"
    sed 's/^/  out>/' "$outf"
    sed 's/^/  err>/' "$errf"
    case "$rc" in
        "$_frc_expected") ;;
        *) echo "FIXTURE $_frc_label FAIL: expected exit $_frc_expected, got $rc" >&2; exit 1 ;;
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

# The host and builder-connection guards: no fixture command may run before
# the rootless connection is known to exist and answer.
boot_fixtures_guard() {
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
}

# The pinned builder image must be present on BOTH connections: the
# capability-set axes are kernel fixtures that need the real container
# privileges, so a missing image or an unreachable rootful connection is a
# BLOCKER, never a silent SKIP->0.
boot_fixtures_builder_image() {
    IMAGE="docker.io/library/rust@sha256:18b6dc7bc111bde4e2fccf6c4ec95cc4a3486b41e4b090e9b0202eba9540023e"
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
}

# The derived fixture image on both connections, identified by immutable id.
# I3: fixtures run on a digest-pinned image that already carries util-linux,
# python3 and git, so no fixture performs an `apk add` (network) inside the
# measured path. The image is built once FROM the same pinned rust base used
# by the build dispatch, so its provenance is a strict superset of the base
# the fixture proofs were accepted against.
boot_fixtures_fixture_image() {
    ensure_fixture_image "$CONN"
    ensure_fixture_image "$ROOTCONN"
    fixture_id=$(podman --connection "$CONN" image inspect --format '{{.Id}}' "$FIXTURE_IMAGE" 2>/dev/null) || fixture_id=""
    [ -n "$fixture_id" ] || {
        echo "BOOT-FIXTURES-BLOCKED: fixture image '$FIXTURE_IMAGE' id unresolvable on $CONN (probe failure is not PASS)" >&2
        exit 1
    }
    echo "  fixture image $FIXTURE_IMAGE id=$fixture_id (base $FIXTURE_BASE_IMAGE)"
}

# The production artifact exists and its digest is recorded BEFORE the
# proof-only variant build, so the after-build equality gate has a baseline.
boot_fixtures_binary() {
    BIN="target/release/alumina"
    [ -x "$ROOT/$BIN" ] || {
        echo "BOOT-FIXTURES-BLOCKED: static binary missing ($BIN); run 'verify.sh mid union' first" >&2
        exit 1
    }
    release_sha_before=$(sha256_digest file "$ROOT/$BIN") || exit 1
}

# Build the proof-only fixture-facts variant and prove the production
# artifact is untouched across it (unr B4).
boot_fixtures_build_variant() {
    echo "BUILD fixture-facts variant (proof-only feature; separate target dir; production artifact untouched):"
    _bf_t0=$(now_ms)
    linux_dispatch 'cargo build --release --locked --features fixture-facts --target-dir target/fixture-facts'
    # Copy the built variant out of the rootless volume and bind the file itself
    # on both connections; uid 65534 need not traverse the host target tree.
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
}

# Fixture 1: the POSITIVE case. Streams are captured raw and asserted after
# the run, so this case also owns the capture initialisation.
boot_fixtures_positive() {
    outf=$(mktemp) || exit 1
    errf=$(mktemp) || exit 1
    trap 'rm -f "$outf" "$errf"' EXIT

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
/fixture-alumina &
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
    fixture_run_case "positive" 0 "$CONN" \
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
}

# Fixtures 2-4: the NEGATIVE cases (root UID, missing no_new_privs, and the
# rootful non-empty effective capability set).
boot_fixtures_rejected() {
    # 2) ROOT: euid 0 -> EX_CONFIG 78 (root-UID diagnostic); all four UID axes
    #    reported zero at entry. Negative fixtures must have EMPTY stdout and
    #    byte-exact stderr: exactly the facts line then the diagnostic.
    fixture_run_case "root-rejected" 78 "$CONN" \
        "cd /work && /fixture-alumina" \
        --security-opt no-new-privileges --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=0 euid=0 suid=0 fsuid=0 cap_eff=800405fb cap_prm=800405fb cap_amb=0 no_new_privs=1" \
        "alumina: prerequisite failure: process has a root UID (real/effective/saved/filesystem)")"

    # 3) NNP-MISSING: no no_new_privs flag -> EX_CONFIG 78 (missing-flag
    #    diagnostic); caps empty, uid dropped.
    fixture_run_case "no-new-privs-missing" 78 "$CONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c 'cd /work && /fixture-alumina'" \
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
    fixture_run_case "caps-effective" 78 "$ROOTCONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups --inh-caps=+net_admin --ambient-caps=+net_admin /bin/sh -c 'cd /work && /fixture-alumina'" \
        --security-opt no-new-privileges --cap-add NET_ADMIN --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=1000 cap_prm=1000 cap_amb=1000 no_new_privs=1" \
        "alumina: prerequisite failure: non-empty effective capability set")"
}

# Fixture 5: the permitted-only applicability disposition.
boot_fixtures_applicability() {
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
}

# Fixture 6: the METADATA proof on the executed variant.
boot_fixtures_metadata() {
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
        -v "$VARBIN:/fixture-alumina:ro,Z" \
        --user 0:0 "$FIXTURE_IMAGE" \
        sh -c 'python3 /app/scripts/fixture_metadata_probe.py /fixture-alumina "$1"' -- "$variant_sha" 2>&1) || metar=$?
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
}

# Linux kernel privilege fixtures. The proof-only `fixture-facts` feature build
# is executed (a clearly-separate variant artifact under target/fixture-facts;
# the production target/release artifact is left untouched, with before/after
# digest equality enforced) so the fixture binary prints its own kernel facts
# to stderr at actual entry. Each fixture runs the digest-checked copied variant
# via a read-only file bind, from cwd=/work holding the fixed documented
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
    boot_fixtures_guard
    boot_fixtures_builder_image
    boot_fixtures_fixture_image
    boot_fixtures_binary
    boot_fixtures_build_variant
    boot_fixtures_positive
    boot_fixtures_rejected
    boot_fixtures_applicability
    boot_fixtures_metadata
    echo "BOOT-FIXTURES-RAN (separate-stream capture; negative stdout empty + stderr byte-exact facts+diagnostic; positive supervised typed-terminated startup record (startup_final status=terminated + shutdown_final status=drained, reaped exit 0) with retained stdout; integer exit 0/78; all cap sets observed non-empty in caps-effective; permitted-only applicability disposition; production digest unchanged; setid-reject + security.capability absence + variant sha256 match proven)"
}


# Docs drift gate: Repowise checks every local path, link, anchor and command in
# the tracked documentation corpus. No Node, no second checker.
docs_drift_gate() {
    command -v repowise >/dev/null 2>&1 || {
        echo "DOC-DRIFT-BLOCKED: repowise required for the docs drift gate (absent)" >&2
        exit 2
    }
    drc=0
    repowise doc-drift --check --kind path --kind link --kind anchor --kind command --fail-on-confidence 0.7 || drc=$?
    case "$drc" in
        0) echo "DOC-DRIFT-OK" ;;
        1) echo "DOC-DRIFT-FAIL (unresolved path, link, anchor or command)" >&2; exit 1 ;;
        2) echo "DOC-DRIFT-BLOCKED (repowise could not evaluate the corpus)" >&2; exit 2 ;;
        *) echo "DOC-DRIFT-FAIL (adapter exit $drc)" >&2; exit 1 ;;
    esac
}

# =============================================================================
# Rust symbol-reference lint (repowise-align 2026-11-15)
#
# One report-only lint: every `path.rs::Symbol` reference in the governing
# specification (`docs/alumina-proxy.md`) resolves in the Repowise index.
# Other documents are not mechanically checked; there is no second detector
# and no check on this lint.
# =============================================================================
ref_check_report_only() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "REF-CHECK-REPORT-ONLY: unavailable (python3 not on PATH)"
        return 0
    fi
    if [ ! -f scripts/ref_check.py ]; then
        echo "REF-CHECK-REPORT-ONLY: unavailable (scripts/ref_check.py missing)"
        return 0
    fi
    rr_rc=0
    rr_out="$(python3 scripts/ref_check.py 2>&1)" || rr_rc=$?
    echo "REF-CHECK-REPORT-ONLY: exit=$rr_rc (report-only, not failing)"
    printf '%s\n' "$rr_out" | sed 's/^/  REF-CHECK: /'
    case "$rr_rc" in
        0) ;;
        1) echo "REF-CHECK-REPORT-ONLY: findings (report-only, not failing)" ;;
        2)
            case "$rr_out" in
                *"stale symbol index"*) echo "REF-CHECK-REPORT-ONLY: unavailable (stale index)" ;;
                *"repowise not on PATH"*) echo "REF-CHECK-REPORT-ONLY: unavailable (repowise not on PATH)" ;;
                *) echo "REF-CHECK-REPORT-ONLY: unavailable (BLOCKED; see REF-CHECK-BLOCKED line above)" ;;
            esac
            ;;
        *) echo "REF-CHECK-REPORT-ONLY: unavailable (adapter exit $rr_rc)" ;;
    esac
    return 0
}

unsafe_surface_gate() {
    # F3 (08-tooling-ci-scripts): file-level unsafe-surface confinement. The
    # `unsafe` keyword is allowed ONLY in the production surface — src/alloc.rs
    # and files under tests/ — and in #[cfg(test)] unit-test modules
    # under src/ (src/*/tests.rs, src/*/dot_tests.rs), whose test-only `unsafe`
    # never compiles into the production binary. Any other *.rs file containing
    # the keyword fails closed, naming the offender(s). Read-only host-side
    # check; no builds.
    # The decision is made over the resolved content of EVERY enumerated *.rs
    # path: symlinked files are read through (rg and grep -R only skip a
    # symlinked file reached by directory traversal, so the path list is passed
    # as explicit arguments — never as a traversal root), symlinked directories
    # are not traversed, and any file whose immediate path is a whitespace-bearing
    # name or does not resolve to a regular file is a scan failure rather than a
    # silently dropped path. The universe is enumerated with `find -print0`
    # (every directory named target, .git or .ooda pruned at any depth — the
    # prior rg/grep exclusion semantics, so a generated target/ tree — for
    # example from a nested crate — cannot turn this gate into a spurious
    # FAIL; producer exit captured)
    # and carried NUL-separated, so no argv word-splitting can lose a path: a
    # path list carried as shell words silently drops a whitespace-bearing entry
    # before the decision, which the mission intent forbids (a release-assurance
    # PASS must not coexist with admitted production unsafe). The list keeps the
    # scanned universe a superset of the admitted inventory, including untracked
    # and non-src .rs paths (a non-src crate stays covered). rg is preferred;
    # grep -l covers hosts without rg.
    # Producer exits are captured (cf. sha256_digest): rg/grep exit 1 = no match
    # (clean); any exit >= 2 is a tooling error and fails closed, never passing
    # on an empty offender list. The xargs transport collapses per-shard exits
    # differently per platform (BSD xargs: 1/2; GNU xargs: 123/124/125) and the
    # shards themselves always exit 0 after mapping a normal match/no-match
    # decision, so the transport must exit 0: any other code is a scan failure,
    # never a clean scan. An empty universe is a scan failure too.
    paths_file=$(mktemp "${TMPDIR:-/tmp}/alumina-unsafe-paths.XXXXXX") || { echo "UNSAFE-SURFACE-SCAN-FAIL: path list temp file unavailable (tooling error, not PASS)" >&2; exit 1; }
    if find . \( -name target -o -name .git -o -name .ooda \) -prune -o \( -type f -o -type l \) -name '*.rs' -print0 > "$paths_file" 2>/dev/null; then
        :
    else
        frc=$?
        rm -f "$paths_file"
        echo "UNSAFE-SURFACE-SCAN-FAIL: unsafe path enumeration exit $frc (tooling error, not PASS)" >&2
        exit 1
    fi
    [ -s "$paths_file" ] || { rm -f "$paths_file"; echo "UNSAFE-SURFACE-SCAN-FAIL: empty .rs path universe (tooling error, not PASS)" >&2; exit 1; }
    # Every enumerated path is validated (whitespace-free regular file) before
    # the producer runs; the shard owns its own producer choice, so rg is used
    # exactly where it is present and grep -l covers every other host.
    if offenders="$(xargs -0 sh -c '
        pattern=$1
        shift
        [ "$#" -gt 0 ] || exit 255
        for f do
            case "$f" in
                *[[:space:]]*)
                    printf "unsafe scan: whitespace-bearing path is unsupported: %s\n" "$f" >&2
                    exit 255 ;;
            esac
            [ -f "$f" ] || {
                printf "unsafe scan: enumerated path is not a regular file: %s\n" "$f" >&2
                exit 255
            }
        done
        if command -v rg >/dev/null 2>&1; then
            rg -l "$pattern" -- "$@"
        else
            grep -l -E "$pattern" -- "$@"
        fi
        rc=$?
        [ "$rc" -le 1 ] || exit 255
        exit 0
    ' sh '\bunsafe\b' < "$paths_file")"; then
        rm -f "$paths_file"
    else
        scan_rc=$?
        rm -f "$paths_file"
        echo "UNSAFE-SURFACE-SCAN-FAIL: unsafe scan transport exit $scan_rc (tooling error, not PASS)" >&2
        exit 1
    fi
    bad=""
    for f in $offenders; do
        case "$f" in
            ./src/alloc.rs|src/alloc.rs|./tests/*|tests/*|./src/*/tests.rs|src/*/tests.rs|./src/*/dot_tests.rs|src/*/dot_tests.rs) ;;
            *) bad="$bad ${f#./}" ;;
        esac
    done
    if [ -n "$bad" ]; then
        echo "UNSAFE-SURFACE-FAIL: 'unsafe' outside allowlist (prod surface: src/alloc.rs, tests/*; cfg(test) unit modules: src/*/tests.rs, src/*/dot_tests.rs):$bad" >&2
        exit 1
    fi
    echo "UNSAFE-SURFACE-OK: every enumerated .rs path outside target/.git/.ooda directories (basenames pruned at any depth, symlinked files resolved, symlinked dirs not traversed, whitespace-free regular files only) confines unsafe to prod surface src/alloc.rs, tests/* and cfg(test) unit modules src/*/tests.rs, src/*/dot_tests.rs"
}

# F-new (gate-surface-truth M1): the reviewed identity set (INTENDED) must cover
# EVERY physical src/tests .rs file in the current working tree. Physical
# enumeration (find over both roots, all depths, exit captured) includes
# not-yet-staged additions (approved landing could emplace untracked .rs before
# the native-qualified source packet is staged) and excludes already-deleted
# indexed paths (their admission tokens leave INTENDED when the move lands), so
# INTENDED stays the single authoritative admission map while the snapshot set
# tracks reality. A .rs leaf symlink is enumerated, never silently dropped; an
# enumerated symlink that does not resolve to a regular file fails closed, and
# directory symlinks are not traversed. Producer find failure fails closed and
# can never read as a PASS on an empty offender list.
# The physical enumeration: find over both roots, producer exit captured.
intended_coverage_scan() {
    prc=0
    covered_rs="$(find src tests \( -type f -o -type l \) -name '*.rs' 2>&1)" || prc=$?
    [ "$prc" -eq 0 ] || {
        echo "INTENDED-COVERAGE-FAIL: find exit $prc (tooling error, not PASS)" >&2
        exit 1
    }
}

# An enumerated .rs symlink must resolve to a regular file (never a silent drop).
intended_coverage_symlinks() {
    for f in $covered_rs; do
        if [ -L "$f" ] && [ ! -f "$f" ]; then
            echo "INTENDED-COVERAGE-FAIL: .rs symlink does not resolve to a regular file: $f" >&2
            exit 1
        fi
    done
}

# Every enumerated path must carry an INTENDED admission token.
intended_coverage_missing() {
    missing=""
    for f in $covered_rs; do
        case " $INTENDED " in
            *" $f "*) ;;
            *) missing="$missing $f" ;;
        esac
    done
    if [ -n "$missing" ]; then
        echo "INTENDED-COVERAGE-FAIL: physical src/tests .rs absent from INTENDED (drifts outside every identity snapshot):$missing" >&2
        exit 1
    fi
}

intended_coverage_gate() {
    intended_coverage_scan
    intended_coverage_symlinks
    intended_coverage_missing
    echo "INTENDED-COVERAGE-OK: every physical src/tests .rs (find, untracked included, deleted-indexed excluded) is listed in INTENDED"
}

# F-new (gate-surface-truth M1, closes assurance alumina-ajyok): an admitted
# src/*/tests.rs or src/*/dot_tests.rs at any depth is trusted as test-only
# unsafe surface ONLY if its actual immediate parent module (resolved
# <parent>.rs, else <parent>/mod.rs at the unit module's own path; both
# present is ambiguous and fails closed) attributes EVERY `mod <stem>;`
# declaration under #[cfg(test)]. First-match ACM is not enough: a later
# `#[cfg(feature = "x")] mod tests;` after a cfg(test) declaration would
# compile the module's unsafe into the binary while the gate still passed. A
# filename-only admission would let a production `mod tests;` pass at all.
# Enumerated via find over the working tree (same universe as the unsafe scan,
# symlinks included: a symlinked tests.rs is parentage-checked, not skipped),
# exit captured so a scan failure fails closed and never reads as PASS.
cfg_test_parentage_gate() {
    if umods="$(find src -mindepth 2 \( -type f -o -type l \) \( -name 'tests.rs' -o -name 'dot_tests.rs' \) 2>/dev/null)"; then
        :
    else
        fsrc=$?
        echo "CFG-TEST-PARENTAGE-SCAN-FAIL: unit-module scan producer exit $fsrc (tooling error, not PASS)" >&2
        exit 1
    fi
    pg_bad=""
    for m in $umods; do
        d=$(dirname "$m")
        stem=$(basename "$m" .rs)
        # The actual immediate parent module is <d>.rs, else <d>/mod.rs. Both
        # present is ambiguous and fails closed; neither is a missing parent.
        found=""
        [ -f "$d.rs" ] && found="rs"
        [ -f "$d/mod.rs" ] && found="$found+mod"
        case "$found" in
            rs) parent="$d.rs" ;;
            +mod) parent="$d/mod.rs" ;;
            rs+mod) pg_bad="$pg_bad $m(ambiguous parent: both $d.rs and $d/mod.rs)"; continue ;;
            *) pg_bad="$pg_bad $m(no parent module: neither $d.rs nor $d/mod.rs)"; continue ;;
        esac
        # Every declaration of `mod <stem>;` in the parent must be attributed
        # under #[cfg(test)]: a bare production `mod <stem>;` fails, and so does
        # any later non-cfg(test) redeclaration after a cfg(test) one.
        # Declarations are counted regardless of visibility prefix (`mod`,
        # `pub mod`, `pub(crate)`, `pub(super)`, `pub(self)`, `pub(in …)`), so an
        # attributed phantom cannot let a second production declaration pass
        # uncounted. Attribution is structural: it comes only from the leading
        # attribute prefix of a recognised declaration (cfg(test) anywhere in it)
        # or from an anchored attribute line immediately preceding the
        # declaration (blank lines allowed, other attribute lines preserved);
        # trailing text — including a comment that merely mentions cfg(test) —
        # never counts. Accepted forms are exactly those: `#[cfg(test)]
        # mod tests;`, `#[cfg(test)] pub(crate) mod tests;`, an anchored
        # `#[cfg(test)]` line (modulo blank lines) before the declaration, and
        # any visibility prefix. Other legitimate shapes (`cfg(all(test, …))`,
        # doc comments inside the attribute block) fail closed by design — no
        # comment or Rust parser is built, so text that happens to form a
        # declaration can only make the gate stricter, never greener.
        # The producer status is part of the observation: the capture runs with
        # `set +e` scoped to this substitution (the surrounding script is
        # `set -eu` and the status is checked immediately below), so a green
        # read, a non-attributed declaration and a tooling error are three
        # distinct outcomes of one observation. The diagnostic channel is merged
        # into the verdict (`2>&1`), so an exit-0 producer that writes a
        # diagnostic has an incomplete file in hand and can never read as `ok`.
        _cg_decl="$(set +e; awk -v stem="$stem" '
            {
                rest = $0
                cfgt = 0
                while (match(rest, /^[[:space:]]*#\[[^]]*\][[:space:]]*/)) {
                    attr = substr(rest, RSTART, RLENGTH)
                    if (attr ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/) cfgt = 1
                    rest = substr(rest, RSTART + RLENGTH)
                }
                if (rest ~ ("^[[:space:]]*(pub([[:space:]]*\\([^)]*\\))?[[:space:]]*)?mod[[:space:]]+" stem "[[:space:]]*;")) {
                    total++
                    if (!(pending || cfgt)) bad++
                    pending = 0
                    next
                }
                if ($0 ~ /^[[:space:]]*#\[cfg\(test\)\]/) { pending = 1; next }
                if ($0 ~ /^[[:space:]]*#\[/) next
                if ($0 ~ /^[[:space:]]*$/) next
                pending = 0
            }
            END { printf "%s", ((total > 0 && bad == 0) ? "ok" : "missing") }
        ' "$parent" 2>&1; printf ':%s' "$?")"
        case "$_cg_decl" in
            ok:0) ;;
            *:0) pg_bad="$pg_bad $m(parent:$parent carries a non-#[cfg(test)] 'mod $stem;' declaration)" ;;
            *) echo "CFG-TEST-PARENTAGE-FAIL: awk producer exit ${_cg_decl##*:} on $parent (tooling error, not PASS)" >&2; exit 1 ;;
        esac
    done
    if [ -n "$pg_bad" ]; then
        echo "CFG-TEST-PARENTAGE-FAIL: admitted unit-test modules not declared under #[cfg(test)] by parent:$pg_bad" >&2
        exit 1
    fi
    echo "CFG-TEST-PARENTAGE-OK: every admitted src/*/tests.rs and src/*/dot_tests.rs (symlinks included) has every 'mod <stem>;' declaration in its parent #[cfg(test)]-attributed"
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
        set -- sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        IDENTITY_HASHER="shasum"
        set -- shasum -a 256
    else
        echo "SOURCE-IDENTITY FAIL: neither sha256sum nor shasum present (identity impossible, not PASS)" >&2
        return 1
    fi
    case "$mode" in
        file) set -- "$@" "$path" ;;
    esac
    out=$("$@" 2>&1) || r=$?
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

# Hash an artifact without claiming execution; absence fails closed.
artifact_identity() {
    bin="$1"
    [ -f "$bin" ] || {
        echo "ARTIFACT-IDENTITY FAIL: artifact missing: $bin (identity impossible, not PASS)" >&2
        return 1
    }
    ah=$(sha256_digest file "$bin") || return 1
    echo "  artifact sha256 $ah  $bin"
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

# Record HEAD and the working-tree status: the two boundary-scope observations
# the before/after compare pins first. A producer failure names its exit and is
# never PASS; the snapshot directory is created only once HEAD is readable.
identity_snapshot_head() {
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
}

# Record which hasher the batch uses. The selection is made in this same shell,
# so the global propagates to the env record below.
identity_snapshot_hasher() {
    IDENTITY_HASHER=""
    if command -v sha256sum >/dev/null 2>&1; then IDENTITY_HASHER="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then IDENTITY_HASHER="shasum"; fi
    [ -n "$IDENTITY_HASHER" ] || {
        echo "SOURCE-IDENTITY FAIL: neither sha256sum nor shasum present (identity impossible, not PASS)" >&2
        exit 1
    }
}

# Missing inputs fail closed BEFORE any hashing: an absent identity input must
# never be hashed as a silently empty line.
identity_snapshot_inputs_present() {
    for f in $IDENTITY_FILES; do
        [ -f "$f" ] || {
            echo "SOURCE-IDENTITY FAIL: identity input missing: $f" >&2
            exit 1
        }
    done
}

# Hash ALL identity inputs in ONE producer invocation (single exec over ~49
# files) instead of one subprocess per file. The batch's own exit code and
# stderr are checked (never masked), and the temp stderr file is always
# removed.
#
# The batch expansion is intentionally unquoted: IDENTITY_FILES is a fixed,
# space-free set (INTENDED plus .gitignore and the docs-arm gate inputs).
# The appended inputs are identity-carried, not gate roots: the docs gate roots
# and scripts/verify_test.py. Word-splitting thus yields exactly the intended
# paths. The hasher's stderr is retained so a failed hash
# names the failing input; it is surfaced before removal, never masked.
identity_snapshot_hash_batch() {
    dir="$1"
    rc=0
    errf="$dir/inputs.sha256.err"
    : >"$dir/inputs.sha256"
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
}

# The effective build env as one record: declared knobs, supply-chain pins and
# the Cargo config inventory. The single redirect owns the file, so a failure
# mid-record leaves exactly the lines already produced.
identity_snapshot_env() {
    dir="$1"
    config_home="${CARGO_HOME:-$HOME/.cargo}"
    alihash=$(printf '%s\n' '[alias]' 'atest = ["test", "--quiet", "--no-fail-fast"]' 'aclippy = ["clippy", "--quiet", "--message-format=short"]' | sha256_digest stdin) || exit 1
    {
        identity_snapshot_env_declared
        identity_snapshot_env_supply_chain "$config_home"
        identity_snapshot_env_config "$config_home"
        identity_snapshot_env_container "$alihash"
    } >"$dir/env"
}

# The declared build environment the snapshot pins verbatim: the resolved
# compiler identity, hasher, Cargo/rustc knobs and the effective Cargo home.
#
# No toolchain pin exists in this repository, so the compiler identity is
# OBSERVED from the host that runs the build. An unobservable compiler is
# recorded as <unreadable>: never an empty or guessed value (a pin removal must
# not turn into a silently unrecorded compiler).
identity_snapshot_env_declared() {
    _tc_release=""
    if _tc=$(rustc -vV 2>&1); then
        _tc_release=$(printf '%s\n' "$_tc" | sed -n 's/^release: //p')
    fi
    case "$_tc_release" in
        "" | *[!A-Za-z0-9._-]*) printf 'toolchain_resolved=<unreadable>\n' ;;
        *) printf 'toolchain_resolved=%s\n' "$_tc_release" ;;
    esac
    printf 'hasher=%s\n' "${IDENTITY_HASHER:-<none>}"
    printf 'cargo_home=%s\n' "${CARGO_HOME:-<unset>}"
    printf 'cargo_target_dir=%s\n' "${CARGO_TARGET_DIR:-<unset>}"
    printf 'rustflags=%s\n' "${RUSTFLAGS:-<unset>}"
    printf 'rust_min_stack=%s\n' "${RUST_MIN_STACK:-<unset>}"
    printf 'rustc=%s\n' "${RUSTC:-<unset>}"
    printf 'rustc_wrapper=%s\n' "${RUSTC_WRAPPER:-<unset>}"
    printf 'rustc_workspace_wrapper=%s\n' "${RUSTC_WORKSPACE_WRAPPER:-<unset>}"
    printf 'cargo_incremental=%s\n' "${CARGO_INCREMENTAL:-<unset>}"
    printf 'cargo_term_progress_when=%s\n' "${CARGO_TERM_PROGRESS_WHEN:-<unset>}"
    printf 'podman_connection=%s\n' "${PODMAN_CONNECTION:-<unset>}"
    printf 'podman_root_connection=%s\n' "${PODMAN_ROOT_CONNECTION:-<unset>}"
    printf 'cargo_home_effective=%s\n' "$config_home"
}

# G8-C10: supply-chain tool versions + advisory-DB freshness. Absent tools/DB
# record <absent> (never a hard fail); the before/after env diff surfaces any
# host tool/DB change between snapshots.
identity_snapshot_env_supply_chain() {
    config_home="$1"
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
}

# Effective Cargo config inventory (finite ancestor closure, qkl seam A):
# Cargo's hierarchical search consults the cwd ancestry -- EVERY parent up to
# the filesystem root -- plus the selected Cargo home
# ${CARGO_HOME:-$HOME/.cargo}. Both spellings are inventoried at every stop
# (config, config.toml); where both exist at one path Cargo prefers the
# extensionless `config` spelling (Cargo Book, hierarchical structure). We
# record candidates only: no TOML precedence/merge interpreter, no claim
# either spelling is necessarily consumed. Path/name plus a SHA256 digest or a
# verified-absence marker; any unreadable or non-regular candidate fails
# closed. Replaces the prior four hardcoded fields with one traversal, so a
# candidate above the checkout now changes this record.
identity_snapshot_env_config() {
    config_home="$1"
    printf 'installed_closure_vs_lock=package-lock.json identity-covered; node_modules installed closure reconciled at commander intake (1gx.15 default-condition 67-file ledger)\n'
    printf 'cargo_config_namespace=host: cwd ancestry through filesystem root plus selected Cargo home\n'
    identity_snapshot_env_config_ancestry
    identity_snapshot_env_config_selected "$config_home"
}

# The ancestry half of the closure: every parent up to the filesystem root,
# both spellings at every stop.
identity_snapshot_env_config_ancestry() {
    d="$(pwd)"
    while :; do
        for n in config config.toml; do
            if [ "$d" = "/" ]; then p="/.cargo/$n"; else p="$d/.cargo/$n"; fi
            identity_snapshot_env_config_candidate "cargo_config" "cargo config candidate" "$p"
        done
        [ "$d" = "/" ] && break
        d="${d%/*}"
        [ -n "$d" ] || d="/"
    done
}

# The selected-Cargo-home half: the same two spellings under $CARGO_HOME.
identity_snapshot_env_config_selected() {
    config_home="$1"
    for n in config config.toml; do
        p="$config_home/$n"
        identity_snapshot_env_config_candidate "cargo_config selected" "selected cargo config" "$p"
    done
}

# One candidate, observed once at the standard-library boundary: present
# records its digest, absent is the only verified-absence marker, and every
# other status (denied, dangling, nonregular, error, unknown) fails closed.
identity_snapshot_env_config_candidate() {
    identity_candidate_label="$1"
    noun="$2"
    p="$3"
    st=$(config_observe "$p")
    case "$st" in
        absent) printf '%s absent    %s\n' "$identity_candidate_label" "$p" ;;
        present)
            h=$(sha256_digest file "$p") || {
                echo "SOURCE-IDENTITY FAIL: unreadable $noun: $p" >&2
                exit 1
            }
            printf '%s present   %s  %s\n' "$identity_candidate_label" "$h" "$p"
            ;;
        denied|dangling|nonregular|error)
            echo "SOURCE-IDENTITY FAIL: $noun not observable ($st): $p" >&2
            exit 1
            ;;
        *)
            echo "SOURCE-IDENTITY FAIL: cargo config observation unknown status '$st' for: $p" >&2
            exit 1
            ;;
    esac
}

# The container-side config pins: the mirrored namespace and the digest of the
# alias block the fresh /cargo-home is provisioned with.
identity_snapshot_env_container() {
    alihash="$1"
    printf 'container_cargo_config_namespace=/app/.cargo mirrors repo cwd (inventoried above); fixed fresh /cargo-home provisioned alias block\n'
    printf 'container_alias_block_sha256=%s\n' "$alihash"
}

# Boundary identity snapshot: HEAD, working-tree status, one digest per
# identity input and the effective build env, all written under $dir. Each step
# exits non-zero on its own failure, so a snapshot that returns 0 is complete.
identity_snapshot() {
    dir="$1"
    identity_snapshot_head "$dir"
    identity_snapshot_hasher
    identity_snapshot_inputs_present
    identity_snapshot_hash_batch "$dir"
    identity_snapshot_env "$dir"
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

# G8-C22: pin supply-chain tool versions; a drift from the accepted versions
# fails closed (a different audit/deny version can change the gate verdict, so
# the intake gate must be host-reproducible).
audit_deny_pins() {
    AUDIT_VERSION="0.22.1"
    DENY_VERSION="0.19.4"
    av=$(cargo-audit --version 2>&1) || av="<unreadable>"
    [ "${av##* }" = "$AUDIT_VERSION" ] || { echo "AUDIT-DENY FAIL: cargo-audit version '$av' != pinned $AUDIT_VERSION" >&2; exit 1; }
    dv=$(cargo-deny --version 2>&1) || dv="<unreadable>"
    [ "${dv##* }" = "$DENY_VERSION" ] || { echo "AUDIT-DENY FAIL: cargo-deny version '$dv' != pinned $DENY_VERSION" >&2; exit 1; }
}

# Both hard gates; each producer exit is checked, never folded into PASS.
audit_deny_run() {
    ar=0
    cargo audit --no-fetch || ar=$?
    [ "$ar" -eq 0 ] || { echo "AUDIT-DENY FAIL: cargo audit exit $ar" >&2; exit 1; }
    dr=0
    cargo deny check || dr=$?
    [ "$dr" -eq 0 ] || { echo "AUDIT-DENY FAIL: cargo deny exit $dr" >&2; exit 1; }
}

audit_deny_owner() {
    have=1
    command -v cargo-audit >/dev/null 2>&1 || have=0
    command -v cargo-deny >/dev/null 2>&1 || have=0
    if [ "$have" -eq 1 ]; then
        echo "AUDIT-DENY (hard gate, boundary host):"
        audit_deny_pins
        audit_deny_run
        echo "AUDIT-DENY-OK (audit $AUDIT_VERSION exit $ar; deny $DENY_VERSION exit $dr)"
    else
        echo "AUDIT-DENY-BLOCKED: cargo audit or cargo deny absent on this host" >&2
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

# Only the alias block is written now: clippy/rustfmt/git are baked into the
# derived image and the crate cache persists in $ALT_CARGO_HOME_VOL, so the
# dispatch performs no network provisioning. The two presence checks fail
# closed rather than silently installing -- a missing tool means the image is
# wrong, and installing it would reintroduce the network dependency.
DISPATCH_PROVISION='mkdir -p /cargo-home
printf "%s\n" "[alias]" "atest = [\"test\", \"--quiet\", \"--no-fail-fast\"]" "aclippy = [\"clippy\", \"--quiet\", \"--message-format=short\"]" > /cargo-home/config.toml
command -v git >/dev/null 2>&1 || { echo "LINUX-DISPATCH-BLOCKED: git absent from dispatch image (whitespace gate requires it)" >&2; exit 1; }
rustup component list --installed 2>/dev/null | grep -q clippy || { echo "LINUX-DISPATCH-BLOCKED: clippy component absent from dispatch image" >&2; exit 1; }
'

# Host and image guards: the dispatch connection must answer and the derived
# image must resolve to an immutable id before any container runs.
linux_dispatch_prepare() {
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
}

linux_dispatch_bind() {
    # Baseline mode only: verify.sh's original host bind-mount of target/, so
    # the alt can be measured apples-to-apples against verify.sh.
    podman --connection "$CONN" run --rm --pull=never \
        -v "$ROOT:/app:ro,Z" \
        -v "$ROOT/target:/app/target:Z" \
        --user 0:0 \
        -e CARGO_HOME=/cargo-home \
        -e CARGO_INCREMENTAL=0 \
        -e CARGO_TERM_PROGRESS_WHEN=never \
        -e RUST_MIN_STACK=16777216 \
        -w /app \
        "$IMAGE" sh -c "$DISPATCH_PROVISION$inner" || drc=$?
}

linux_dispatch_volume() {
    ensure_volume "$CONN" "$ALT_TARGET_VOL"
    ensure_volume "$CONN" "$ALT_CARGO_HOME_VOL"
    # The target path must exist inside the read-only source mount before the
    # volume is mounted over it.
    podman --connection "$CONN" run --rm --pull=never \
        -v "$ROOT:/app:ro,Z" \
        -v "$ALT_TARGET_VOL:/app/target" \
        -v "$ALT_CARGO_HOME_VOL:/cargo-home" \
        --user 0:0 \
        -e CARGO_HOME=/cargo-home \
        -e CARGO_INCREMENTAL=0 \
        -e CARGO_TERM_PROGRESS_WHEN=never \
        -e RUST_MIN_STACK=16777216 \
        -w /app \
        "$IMAGE" sh -c "$DISPATCH_PROVISION$inner" || drc=$?
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
    linux_dispatch_prepare
    _ld_t0=$(now_ms)
    drc=0
    mkdir -p "$ROOT/target"
    if [ "$ALT_NO_VOLUME" = "1" ]; then
        linux_dispatch_bind
    else
        linux_dispatch_volume
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
# D7: `git diff HEAD` cannot see untracked files, so without this guard the
# receipt would certify a checkout whose build consumed an input it never
# covered (a root `build.rs`, a `.cargo/config.toml`, a new module). Every
# untracked path the PINNED ignore universe admits refuses the receipt BEFORE
# the build.
#
# The universe is pinned deliberately: `--exclude-per-directory=.gitignore`
# reads only the per-directory .gitignore files (tracked, therefore
# receipt-covered as *rules*) and drops the unpinned sources
# `--exclude-standard` would honour ($GIT_DIR/info/exclude and
# core.excludesFile). A local ignore entry could otherwise hide a
# Cargo-consumed input from the receipt completely. The residual is explicit: a
# committed (or worktree-edited) ignore RULE that names a Cargo-consumed path
# hides that input under the same receipt, and an ignored path is outside this
# receipt: a committed rule is a reviewed repo change, a worktree-edited rule is
# diff-covered, and an untracked .gitignore is itself refused unless it ignores
# itself (the one shape this cannot see). The producer exit is checked (an unreadable observation is BLOCKED,
# never clean), an exit-0 diagnostic is treated as an incomplete universe, its
# stderr is kept out of the observed path list, and --full-name keeps paths
# repo-root-relative. Paths are compared in git's C-quoted form, so a path
# containing a tab, backslash or non-ASCII byte cannot match an allowlist entry:
# that is fail-closed, never an escape.
#
# Each observed path is classified against this explicit allowlist:
#
#   E2E_UNTRACKED_ALLOW  space-separated path PREFIXES, relative to the repo root
#
# A path is excused when it equals an entry or lies under it (`generated/`
# excuses `generated/facts.txt` and never `generated-evil/`). The repo's own
# generated artifacts (target/, .ooda/, node_modules/, .beads/, *.db) are
# covered by the tracked .gitignore, so they never reach this classification.
# An entry is a deliberately visible, reviewed bypass: add it with its rationale
# in the same commit, never from the environment. `.repowise/` is the one
# standing entry — a local semantic-index cache that developer machines exclude
# through the unpinned .git/info/exclude and that is never a Cargo input; a
# machine with a different local cache must name it here, which is the point.
# An allowlisted prefix is outside the receipt by design: a future build input
# placed under it would be invisible, so the entry set is pinned by a test and
# every addition is a reviewed diff.
E2E_UNTRACKED_ALLOW=".repowise/"
e2e_untracked_input_guard() {
    _gate="$1"
    _ug_err=$(mktemp) || {
        echo "E2E-$_gate-BLOCKED: mktemp failed (untracked-input observation impossible, not a receipt)" >&2
        exit 1
    }
    if _ug_list=$(git ls-files --others --full-name --exclude-per-directory=.gitignore 2>"$_ug_err"); then
        # A diagnostic on an exit-0 producer means the universe is INCOMPLETE
        # (git reports an unreadable directory or pattern file as a warning and
        # then simply leaves its contents out), so it is a gap, never a clean
        # observation. The stderr channel is kept separate so a real path list
        # is never polluted by it, and it is never discarded.
        if [ -s "$_ug_err" ]; then
            echo "E2E-$_gate-BLOCKED: git ls-files --others produced diagnostics (untracked-input observation incomplete, not a receipt)" >&2
            sed 's/^/  /' "$_ug_err" >&2
            rm -f "$_ug_err"
            exit 1
        fi
        rm -f "$_ug_err"
    else
        _ug_rc=$?
        echo "E2E-$_gate-BLOCKED: git ls-files --others exit $_ug_rc (untracked-input observation failed, not a receipt)" >&2
        sed 's/^/  /' "$_ug_err" >&2
        rm -f "$_ug_err"
        exit 1
    fi
    _ug_bad=""
    while IFS= read -r _ug_path; do
        # The expansion is intentionally unquoted: the allowlist is a fixed,
        # space-separated prefix set and word-splitting is the list separator.
        # shellcheck disable=SC2086
        for _ug_prefix in $E2E_UNTRACKED_ALLOW; do
            # An empty record (no untracked path at all) and an allowlisted
            # path are both skipped for the next observed path.
            case "$_ug_path" in
                ""|"$_ug_prefix"*) continue 2 ;;
            esac
        done
        _ug_bad="$_ug_bad
  $_ug_path"
    done <<EOF
$_ug_list
EOF
    if [ -z "$_ug_bad" ]; then
        return 0
    fi
    echo "E2E-$_gate-BLOCKED: untracked path(s) outside the explicit allowlist (git diff HEAD cannot cover them, so the receipt would not bind the built binary):$_ug_bad" >&2
    echo "E2E-$_gate-BLOCKED: commit the path(s), remove them, or name a path prefix in E2E_UNTRACKED_ALLOW with its rationale in the same commit" >&2
    exit 1
}

# Exact-candidate input digest record (pre/post-build and after the executed
# harness): HEAD + dirty diff + untracked harness py/sh + gate script, over a
# checkout with NO untracked path outside the explicit allowlist above. The diff
# producer exit is checked SEPARATELY (never a masked pipeline); the untracked
# harness scripts are hashed explicitly (git diff excludes them). Requires $TGT.
e2e_receipt_fields() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    e2e_untracked_input_guard "$_gate"
    # --no-ext-diff/--no-textconv: an external diff driver or a textconv
    # attribute can make `git diff HEAD` emit a constant (or nothing) with exit
    # 0, which would hide every tracked worktree edit from the receipt - and
    # therefore from the pre/post-build stability comparison that exists to
    # catch a mid-build source change. --binary keeps a binary-attributed edit
    # content-visible instead of collapsing it to "Binary files differ". The
    # producer's stderr is kept out of the hashed bytes and an exit-0 diagnostic
    # is an incomplete diff, i.e. BLOCKED, exactly like the untracked universe.
    _df_err=$(mktemp) || {
        echo "E2E-$_gate-BLOCKED: mktemp failed (source-diff observation impossible, not a receipt)" >&2
        exit 1
    }
    if git diff --no-ext-diff --no-textconv --binary HEAD >"$TGT/$_gate-diff.$$" 2>"$_df_err"; then
        if [ -s "$_df_err" ]; then
            echo "E2E-$_gate-BLOCKED: git diff HEAD produced diagnostics (source-diff observation incomplete, not a receipt)" >&2
            sed 's/^/  /' "$_df_err" >&2
            rm -f "$_df_err"
            exit 1
        fi
        rm -f "$_df_err"
    else
        rcd=$?
        echo "E2E-$_gate-BLOCKED: git diff HEAD exit $rcd (unreadable diff, not a receipt)" >&2
        sed 's/^/  /' "$_df_err" >&2
        rm -f "$_df_err"
        exit 1
    fi
    rgh=0
    head=$(git rev-parse --verify HEAD 2>&1) || rgh=$?
    # The receipt binds the checkout only when HEAD was read AND is non-empty:
    # an unreadable and an empty HEAD are one refusal, with the observed exit.
    case "$rgh:$head" in
        0:?*) ;;
        *) echo "E2E-$_gate-BLOCKED: git rev-parse --verify HEAD exit $rgh (unreadable HEAD, not a receipt)" >&2; exit 1 ;;
    esac
    # The four input digest fields, in order: the dirty diff, the harness py,
    # the harness sh and this gate script. One pass, one guard: an unhashable
    # input refuses the receipt exactly as a per-field guard did, and the
    # sha256_digest owner names the failing path.
    _rf_fields=""
    for _rf_path in "$TGT/$_gate-diff.$$" "$_harness_py" "$_harness_sh" scripts/verify.sh; do
        _rf_fields="$_rf_fields $(sha256_digest file "$_rf_path")" || exit 1
    done
    printf '%s%s\n' "$head" "$_rf_fields"
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

# R1: the artifact PROFILE is explicitly observed from the build owner (the
# native host triple under which the release build actually runs), not
# guessed from --target-dir. The identical triple is carried into the cargo
# build AND into the artifact consumer path, so the executed binary is the
# one Cargo just produced - a stale default-path artifact can never be
# consumed. On the non-Linux dispatch route the triple is observed inside
# the same rust image that performs the build.
e2e_build_owner() {
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
    if [ "$(uname -s)" = "Linux" ]; then
        _probe_buf=$(observe_build_target rustc -vV) || exit 1
    else
        _probe_buf=$(observe_build_target \
            podman --connection "${PODMAN_CONNECTION}" run --rm --pull=never \
            docker.io/library/rust@sha256:18b6dc7bc111bde4e2fccf6c4ec95cc4a3486b41e4b090e9b0202eba9540023e \
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
}

# The exact-candidate build: pre-build input record, the build itself, the
# post-build record, the stability compare and the artifact existence gate.
e2e_build_sources() {
    TGT="$ROOT/target"
    BIN="target/${E2E_TARGET}/release/alumina"
    closure_metadata
    # Pre-build source-input stability record (exact-candidate inputs hashed by
    # the shared owner; explicitly includes the untracked harness scripts).
    mkdir -p "$TGT"
    before=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    if [ "$(uname -s)" = "Linux" ]; then
        echo "PRODUCTION-RELEASE-BUILD (native Linux, exact current source, target=${E2E_TARGET}):"
        cargo build --locked --release --target "$E2E_TARGET" --target-dir "$TGT"
    else
        echo "PRODUCTION-RELEASE-BUILD (native Linux via container dispatch; host $(uname -s), target=${E2E_TARGET}):"
        linux_dispatch "cargo build --locked --release --target ${E2E_TARGET} --target-dir /app/target"
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
}

# B3/R1: resolve the ACTUAL harness-image tag + immutable ID from the rootful
# connection the harness consumers open (e2e_relay.sh/e2e_shutdown.sh use
# ${PODMAN_ROOT_CONNECTION}). An unresolvable ID is a blocker. The immutable
# ID is EXPORTED to the consumers, which must re-check that the tag still
# resolves to this ID on their connection and then run the ID itself (R1:
# the receipt's image is the image executed).
e2e_harness_identity() {
    echo "e2e/$_gate identity (executed binary tied to exact candidate):"
    head=$(git rev-parse --verify HEAD 2>&1) || {
        echo "E2E-$_gate-BLOCKED: git rev-parse HEAD failed" >&2
        exit 1
    }
    binhash=$(sha256_digest file "$ROOT/$BIN") || exit 1
    E2E_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
    E2E_ROOT_CONN="${PODMAN_ROOT_CONNECTION:?PODMAN_ROOT_CONNECTION must be set to your rootful podman connection}"
    harness_id=$(podman --connection "$E2E_ROOT_CONN" image inspect --format '{{.Id}}' "$E2E_IMAGE" 2>/dev/null) \
        || harness_id=""
    if [ -z "$harness_id" ]; then
        echo "E2E-$_gate-BLOCKED: harness image '$E2E_IMAGE' id unresolvable on ${E2E_ROOT_CONN}: ${E2E_ROOT_CONN}" >&2
        exit 1
    fi
    export E2E_IMAGE E2E_IMAGE_ID="$harness_id" E2E_ROOT_CONN
}

# Durable through-execution receipt (consumed by e2e_verify_stable after the
# harness runs): exact-candidate inputs + executed binary digest, then the
# two-line identity record.
e2e_receipt_print() {
    printf '%s\n' "$after" >"$TGT/.e2e-$_gate-inputs"
    printf '%s\n' "$binhash" >"$TGT/.e2e-$_gate-binhash"
    printf '  HEAD=%s target=%s dirty-diff-sha256=%s harness-py-sha256=%s harness-sh-sha256=%s binary-sha256=%s\n' \
        "$head" "$E2E_TARGET" "$(printf '%s' "$after" | cut -d' ' -f2)" \
        "$(printf '%s' "$after" | cut -d' ' -f3)" "$(printf '%s' "$after" | cut -d' ' -f4)" "$binhash"
    printf '  builder=%s builder-image=%s harness-image=%s harness-image-id=%s harness-conn=%s\n' \
        "$_builder" "docker.io/library/rust@sha256:18b6dc7bc111bde4e2fccf6c4ec95cc4a3486b41e4b090e9b0202eba9540023e" \
        "$E2E_IMAGE" "$harness_id" "$E2E_ROOT_CONN"
}

e2e_build_receipt() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    ROOT="$(pwd)"
    e2e_build_owner
    e2e_build_sources
    e2e_harness_identity
    e2e_receipt_print
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
#   cargo atest -p alumina --locked --test <target>
inner_check() {
    echo "INNER-CHECK (cargo check, no clippy/fmt/whitespace/release):"
    cargo check --locked -p alumina --all-targets
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
    linux_dispatch 'cargo build --locked -p alumina --bin alumina'
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
        foundations|boot|eligibility|binary_entry|mio_matrix|main_thread_serving|monitor_stdout|stdout_stall|stdout_closed) ;;
        "")
            echo "INNER-TEST usage: verify.sh inner test <target>" >&2
            exit 2
            ;;
        *)
            echo "INNER-TEST-UNKNOWN-TARGET: '$_target' is not a test target of this crate (whitelist: foundations boot eligibility binary_entry mio_matrix main_thread_serving monitor_stdout stdout_stall stdout_closed)" >&2
            exit 2
            ;;
    esac
    # `mio_matrix`'s crate root is `#![cfg(feature = "alloc-witness")]`, so a
    # witness-off build compiles an EMPTY binary whose "pass" proves nothing.
    # That one target therefore runs with the feature; every other target keeps
    # the plain witness-off invocation.
    _run_args="-p alumina --locked"
    if [ "$_target" = "mio_matrix" ]; then
        _run_args="$_run_args --features alloc-witness"
    fi
    _run_args="$_run_args --test $_target"
    echo "INNER-NO-CLAIM: host-native run of cargo atest $_run_args backs no done-claim (MID/BOUNDARY own that)"
    # shellcheck disable=SC2086
    if cargo atest $_run_args; then
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
    host-mid/foundations|host-mid/boot|host-mid/clippy|host-mid/union|host-mid/full)
        [ "$#" -eq 2 ] || usage
        # Scan BEFORE the dispatch: the pre-scan is a host-state precondition,
        # not hang prevention for the container (the container has its own
        # process namespace; a host orphan is not visible or waited on there).
        # A stale host orphan still makes this host's receipt chain-ambiguous -
        # its loopback listener belongs to no current gate - so it fails before
        # the dispatch is recorded. The post-scan proves this dispatch left no
        # new one.
        assert_no_leaked_gate_children || exit 1
        linux_dispatch "sh scripts/verify.sh mid $SCOPE"
        if [ "$SCOPE" = "union" ]; then
            copy_out_artifact "release/alumina" "target/release/alumina" || exit 1
        fi
        assert_no_leaked_gate_children
        ;;
    gate-children/scan) assert_no_leaked_gate_children ;;
    fixtures/boot) boot_fixtures ;;
    supply-chain/audit-deny) [ "$#" -eq 2 ] || usage; audit_deny_owner ;;
    identity/snapshot) [ "$#" -eq 3 ] && [ -n "$3" ] || usage; identity_snapshot "$3" ;;
    identity/compare) [ "$#" -eq 4 ] && [ -n "$3" ] && [ -n "$4" ] || usage; identity_compare "$3" "$4" ;;
    identity/artifact) [ "$#" -eq 3 ] && [ -n "$3" ] || usage; artifact_identity "$3" ;;
    e2e/relay) e2e_relay ;;
    e2e/shutdown) e2e_shutdown ;;
    docs/*) docs_drift_gate; intended_coverage_gate; cfg_test_parentage_gate; unsafe_surface_gate; canonical_digest_gate; ref_check_report_only ;;
    *) usage ;;
esac
