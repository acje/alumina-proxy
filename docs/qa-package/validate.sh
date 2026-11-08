#!/bin/sh
# Local fixture smoke and identity; not a release qualification gate.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT" || { echo "QA-PACKAGE-ERROR: cannot cd to repo root" >&2; exit 1; }
echo "QA-PACKAGE-VALIDATE start: $(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(uname -s)/$(uname -m) toolchain=1.99.0"

prereq_fail() {
    echo "$1" >&2
    echo "QA-PACKAGE-PREREQ-FAIL: mandatory prerequisite failed before any fixture effect" >&2
    exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
    HASHER=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    HASHER="shasum -a 256"
else
    prereq_fail "no sha256 hasher (sha256sum or shasum); artifact hash impossible"
fi
command -v git >/dev/null 2>&1 || prereq_fail "git absent; source identity impossible"
HEAD_ID=$(git rev-parse --verify HEAD 2>/dev/null) || prereq_fail "source HEAD not resolvable"
[ -n "$HEAD_ID" ] || prereq_fail "source HEAD empty"
STATUS=$(git status --porcelain 2>/dev/null) || prereq_fail "git status unreadable"
# Hash the status-list, not working-tree contents. Check the hasher itself.
STATUS_HASH=$(if [ -n "$STATUS" ]; then printf '%s\n' "$STATUS"; fi | $HASHER 2>/dev/null) || prereq_fail "working-tree status-list hash producer failed"
PORCELAIN=${STATUS_HASH%% *}
[ -n "$PORCELAIN" ] || prereq_fail "working-tree status-list hash empty"
command -v file >/dev/null 2>&1 || prereq_fail "'file' absent; static-ELF probe impossible"
echo "source HEAD: $HEAD_ID"
echo "source working-tree status-list identity (NOT content identity): $PORCELAIN"

BIN="$ROOT/target/fixture-facts/release/alumina"
MARKER="$ROOT/target/fixture-facts/release/variant.sha256"
# The fixture producer writes this marker after building the variant. Remove a
# prior receipt first, so matching stale bytes cannot be attributed to this run.
if ! rm -f "$MARKER" || [ -e "$MARKER" ] || [ -L "$MARKER" ]; then
    echo "QA-PACKAGE-ERROR: cannot clear prior fresh-variant marker ($MARKER)" >&2
    exit 1
fi
if ! sh scripts/verify.sh fixtures boot; then
    echo "QA-PACKAGE-FAIL: fixtures boot failed" >&2
    exit 1
fi

[ -x "$BIN" ] || { echo "QA-PACKAGE-FAIL: exercised artifact missing or not executable ($BIN)" >&2; exit 1; }
[ -r "$MARKER" ] || { echo "QA-PACKAGE-ERROR: fresh-variant marker absent or unreadable ($MARKER)" >&2; exit 1; }
built_sha=$(cat "$MARKER" 2>/dev/null) || { echo "QA-PACKAGE-ERROR: cannot read fresh-variant marker" >&2; exit 1; }
[ -n "$built_sha" ] || { echo "QA-PACKAGE-ERROR: fresh-variant marker empty" >&2; exit 1; }
artifact_hash=$($HASHER "$BIN" 2>/dev/null) || { echo "QA-PACKAGE-ERROR: artifact hasher failed" >&2; exit 1; }
artifact_sha=${artifact_hash%% *}
[ -n "$artifact_sha" ] && [ "$artifact_sha" = "$built_sha" ] || {
    echo "QA-PACKAGE-ERROR: artifact digest does not match this run's fixture-facts marker" >&2
    exit 1
}
fileout=$(file "$BIN" 2>&1) || { echo "QA-PACKAGE-ERROR: file(1) probe failed" >&2; exit 1; }
printf '%s\n' "$fileout"
case "$fileout" in *ELF*'statically linked'*) ;; *)
    echo "QA-PACKAGE-FAIL: exercised artifact is not a statically linked ELF" >&2
    exit 1;;
esac
echo "exercised artifact (fixture-facts variant): target/fixture-facts/release/alumina"
echo "exercised artifact sha256: $artifact_sha"
echo "exercised fixture-facts variant freshness: built in this run (sha256 $built_sha)"
echo "QA-PACKAGE-VALIDATE-OK: fixture smoke only; not release qualification"
