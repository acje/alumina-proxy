#!/bin/sh
# bench_run.sh -- host-side supervisor for one HTTP CONNECT forward proxy
# (alumina | envoy | haproxy) under an e2-micro workload profile
# (1gbps steady, storm150, storm50). Builds the podman run against the pinned
# glibc benchmark container (localhost/alumina-bench), passing the workload
# profile and identity env into the in-container supervisor body
# scripts/bench/run.sh (mounted read-only at /app/scripts/bench/run.sh).
# Writes a JSON receipt to .ooda/benchmarks/.
#
# Topology (fresh e2-micro suite; see docs/benchmarks/e2micro-suite.md §3):
# native Linux via rootful podman connection, --network none, loopback
# global-unicast alias, DNS responder (UDP+TCP) on 127.0.0.1:53, TLS1.3
# byte-exact framed echo backend on 8.8.8.8:443, client ->
#     example.com -> 8.8.8.8   CONNECT proxy on 127.0.0.1:8080 -> backend.
#
#   alumina: client -> CONNECT via a freshly built current-HEAD musl binary at
#            .ooda/alumina-head/baseline/alumina-musl, sha-pinned by
#            HEAD_CANDIDATE_SHA (fail-closed when unset/mismatched).
#   envoy:   client -> CONNECT via Envoy v1.40.2 (image /usr/local/bin/envoy,
#            --concurrency 2, e2-micro 2-vCPU match) driven by
#            scripts/bench/envoy-connect.yaml.
#   haproxy: client -> CONNECT via HAProxy 3.4.7 (image /usr/local/sbin/haproxy,
#            nbthread 2, e2-micro 2-vCPU match) driven by
#            scripts/bench/haproxy-connect.cfg.
#
# e2-micro equivalence is modeled by WORKLOAD PARAMETERS only; the harness
# container is never cgroup-capped (it also runs client+backend+DNS).
#
# Session exit 0 -> client valid + all children reaped cleanly
#              3 -> measurement invalid (honest, reported in JSON)
#              1 -> harness/supervision/protocol failure
set -eu

# Local podman connection names (gitignored; never committed). Sourced when
# present so the harness runs out-of-the-box on a dev machine; an explicit
# environment variable still wins and the fail-closed checks below remain.
if [ -f .ooda/podman-connections.env ]; then
    . ./.ooda/podman-connections.env
fi

ROOT="$(pwd)"
PROXY="${1:?usage: bench_run.sh <alumina|envoy|haproxy> <smoke|timed> <1gbps|storm150|storm50>}"
KIND="${2:?usage: bench_run.sh <alumina|envoy|haproxy> <smoke|timed> <1gbps|storm150|storm50>}"
WORKLOAD="${3:?usage: bench_run.sh <alumina|envoy|haproxy> <smoke|timed> <1gbps|storm150|storm50>}"

case "$PROXY" in
    alumina|envoy|haproxy) ;;
    *) echo "BENCH-BLOCKED: proxy must be alumina, envoy or haproxy" >&2; exit 2 ;;
esac
case "$KIND" in
    smoke|timed) ;;
    *) echo "BENCH-BLOCKED: kind must be smoke or timed" >&2; exit 2 ;;
esac

WORKLOAD_ARGS=""
case "$WORKLOAD" in
    1gbps)
        WORKLOAD_ARGS="--workload steady --conns 32 --target-mbps 1000 --outstanding-cap 2048"
        BENCH_WORKLOAD="$WORKLOAD"
        ;;
    storm150)
        WORKLOAD_ARGS="--workload storm --arrival-rate 150 --session-frames-min 4 --session-frames-max 16"
        BENCH_WORKLOAD="$WORKLOAD"
        ;;
    storm50)
        WORKLOAD_ARGS="--workload storm --arrival-rate 50 --session-frames-min 4 --session-frames-max 16"
        BENCH_WORKLOAD="$WORKLOAD"
        ;;
    *)
        echo "BENCH-BLOCKED: workload must be 1gbps, storm150 or storm50" >&2; exit 2 ;;
esac

CONN="${BENCH_PODMAN_CONNECTION:?BENCH_PODMAN_CONNECTION must be set to your rootful podman connection}"
IMAGE="${BENCH_IMAGE:-localhost/alumina-bench:20261027}"
IMAGE_ID="${BENCH_IMAGE_ID:?BENCH_IMAGE_ID must be pinned to the built bench image}"

command -v podman >/dev/null 2>&1 || { echo "BENCH-BLOCKED: podman required" >&2; exit 1; }
podman --connection "$CONN" info >/dev/null 2>&1 || {
    echo "BENCH-BLOCKED: rootful podman connection $CONN unreachable" >&2; exit 1; }
id=$(podman --connection "$CONN" image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo "?")
[ "$id" = "$IMAGE_ID" ] || {
    echo "BENCH-BLOCKED: bench image '$IMAGE' resolves to '$id', not $IMAGE_ID" >&2
    exit 1
}

BENCH_SOURCE_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
BENCH_DIRTY_COUNT="$(git status --porcelain --untracked-files=no 2>/dev/null | wc -l | tr -d ' ')"
BENCH_RUST_TARGET="aarch64-unknown-linux-musl"
BENCH_BINARY_SHA256=""

if [ "$PROXY" = "alumina" ]; then
    CANDIDATE_REL="alumina-head/baseline/alumina-musl"
    CANDIDATE_SHA="${HEAD_CANDIDATE_SHA:-}"
    [ -n "$CANDIDATE_SHA" ] || {
        echo "BENCH-BLOCKED: HEAD_CANDIDATE_SHA required for alumina (fail-closed)" >&2; exit 1; }
    [ -f "$ROOT/.ooda/$CANDIDATE_REL" ] || {
        echo "BENCH-BLOCKED: alumina binary missing (.ooda/$CANDIDATE_REL)" >&2; exit 1; }
    computed=$(shasum -a 256 "$ROOT/.ooda/$CANDIDATE_REL" | awk '{print $1}')
    [ "$computed" = "$CANDIDATE_SHA" ] || {
        echo "BENCH-BLOCKED: alumina binary identity mismatch (got $computed, want $CANDIDATE_SHA)" >&2
        exit 1
    }
    BENCH_BINARY_SHA256="$CANDIDATE_SHA"
    echo "BENCH-BINARY-IDENTITY: .ooda/$CANDIDATE_REL sha256=$CANDIDATE_SHA"
fi

# Echo backend identity (M-03): the measured path is the compiled static-musl
# Rust TLS1.3 echo backend, sha-pinned fail-closed like HEAD_CANDIDATE_SHA.
# BENCH_BACKEND defaults to compiled; BENCH_BACKEND=python selects the
# in-process python EchoBackend (selftest reference / one-line fallback).
BENCH_BACKEND="${BENCH_BACKEND:-compiled}"
case "$BENCH_BACKEND" in
    compiled|python) ;;
    *) echo "BENCH-BLOCKED: BENCH_BACKEND must be compiled or python" >&2; exit 1 ;;
esac
ECHO_REL="echo-backend/echo-backend-musl"
BENCH_ECHO_SHA="${BENCH_ECHO_SHA:-}"
[ -f "$ROOT/.ooda/$ECHO_REL" ] || {
    echo "BENCH-BLOCKED: compiled echo backend binary missing (.ooda/$ECHO_REL)" >&2
    exit 1
}
computed=$(shasum -a 256 "$ROOT/.ooda/$ECHO_REL" | awk '{print $1}')
[ -n "$BENCH_ECHO_SHA" ] && [ "$computed" = "$BENCH_ECHO_SHA" ] || {
    echo "BENCH-BLOCKED: compiled echo backend identity mismatch (got $computed, want ${BENCH_ECHO_SHA:-<unset>})" >&2
    exit 1
}
echo "BENCH-ECHO-IDENTITY: .ooda/$ECHO_REL sha256=$BENCH_ECHO_SHA"

OUTDIR="$ROOT/.ooda/benchmarks"
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"
TS="$(date +%Y%m%dT%H%M%SZ)"
STAMP="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)-bench-$PROXY-$WORKLOAD-$KIND-$TS"

if [ "$KIND" = "smoke" ]; then
    SECONDS=2
    WARMUP=0
else
    SECONDS=60
    WARMUP=5
fi

# Host-owned container identity + cancellation cleanup (B8): a named container
# lets an INT/TERM on the host force removal immediately instead of waiting on
# podman --timeout. Idempotent; --rm remains as the clean-exit path.
CN="bench-${PROXY}-$$"
HOST_CLEANED=0
host_cleanup() {
    [ "$HOST_CLEANED" -eq 1 ] && return 0
    HOST_CLEANED=1
    podman --connection "$CONN" rm -f "$CN" >/dev/null 2>&1 || true
    return 0
}
trap 'host_cleanup; exit 130' INT TERM
trap 'rc=$?; host_cleanup; exit $rc' EXIT

rcc=0
podman --connection "$CONN" run --rm --name "$CN" --pull=never --timeout 360 \
    -v "$ROOT:/app:ro,Z" \
    -v "$ROOT/.ooda:/ooda:ro,Z" \
    -v "$OUTDIR:/out:Z" \
    --network none \
    --security-opt no-new-privileges \
    --cap-add NET_ADMIN \
    --user 0:0 \
    -e PROXY="$PROXY" \
    -e KIND="$KIND" \
    -e SECONDS="$SECONDS" \
    -e WARMUP="$WARMUP" \
    -e STAMP="$STAMP" \
    -e WORKLOAD_ARGS="$WORKLOAD_ARGS" \
    -e WORKLOAD_LABEL="$WORKLOAD" \
    -e BENCH_WORKLOAD="$BENCH_WORKLOAD" \
    -e BENCH_SOURCE_HEAD="$BENCH_SOURCE_HEAD" \
    -e BENCH_DIRTY_COUNT="$BENCH_DIRTY_COUNT" \
    -e BENCH_RUST_TARGET="$BENCH_RUST_TARGET" \
    -e BENCH_BINARY_SHA256="$BENCH_BINARY_SHA256" \
    -e BENCH_BACKEND="$BENCH_BACKEND" \
    -e BENCH_IMAGE_ID="$IMAGE_ID" \
    "$IMAGE_ID" sh /app/scripts/bench/run.sh || rcc=$?

if [ "$rcc" -ne 0 ]; then
    if [ "$rcc" -eq 130 ]; then
        echo "BENCH-HOST-CANCELLED: interrupted; container $CN cleaned up" >&2
    else
        echo "BENCH-HOST-FAIL: exit $rcc" >&2
    fi
    host_cleanup
    exit "$rcc"
fi
host_cleanup
exit 0
