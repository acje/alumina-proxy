#!/bin/sh
# scripts/bench/run.sh -- in-container supervisor body for the e2-micro
# benchmark suite. Executed by scripts/bench_run.sh's podman run (mounted
# read-only at /app/scripts/bench/run.sh). Stages the loopback alias + DNS +
# certs + proxy config, starts the DNS responder / TLS1.3 echo backend / one
# proxy (alumina | envoy | haproxy), runs the workload driver, reaps children
# cleanly and reports BENCH-OK / BENCH-INVALID / BENCH-FAIL.
#
# Env provided by bench_run.sh: PROXY, KIND, SECONDS, WARMUP, STAMP,
# WORKLOAD_ARGS, WORKLOAD_LABEL, BENCH_WORKLOAD, BENCH_SOURCE_HEAD,
# BENCH_DIRTY_COUNT, BENCH_RUST_TARGET, BENCH_BINARY_SHA256, BENCH_IMAGE_ID,
# BENCH_BACKEND.
set -eu
mkdir -p /work
cd /work

# --- staging: loopback alias + glibc resolver + genuine CA/cert ---
# Backend binds the loopback global-unicast alias; the CONNECT proxies resolve
# example.com to it via the in-container DNS responder (see resolv.conf below).
ip addr add 8.8.8.8/32 dev lo
# glibc resolvers (envoy/haproxy) resolve example.com via 127.0.0.1:53 (UDP);
# alumina uses its own resolver list ["127.0.0.1"] (TCP). Both are served.
printf '%s\n' 'nameserver 127.0.0.1' > /etc/resolv.conf
# genuine CA + endpoint cert: client validates chain and SAN=example.com
openssl req -x509 -newkey rsa:2048 -keyout /work/ca.key -out /work/ca.pem \
    -days 2 -nodes -subj "/CN=bench-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout /work/server.key -out /work/server.csr \
    -days 2 -nodes -subj "/CN=example.com" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:example.com' > /work/ext.cnf
openssl x509 -req -in /work/server.csr -CA /work/ca.pem -CAkey /work/ca.key \
    -CAcreateserial -out /work/server.pem -days 1 -extfile /work/ext.cnf >/dev/null 2>&1
chown -R 65534:65534 /work

# Acquisition slots are initialized before any trap is installed so a failure
# at any point still reaps every owned child (B8). One idempotent supervision
# owner handles both the normal teardown (strict) and the trap path (lenient).
ALU=0
SRV=0
DNSPID=0
CLEANED=0
stop() {
    pid="$1"
    label="$2"
    strict="$3"
    [ "${pid:-0}" -gt 0 ] 2>/dev/null || return 0
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null; w=$?
        if [ "$strict" -eq 1 ]; then
            echo "  BENCH-REAP-FAIL: $label pid $pid exited before reap (status $w) -- unexpected death" >&2
            return 1
        fi
        echo "  BENCH-CLEANUP: $label pid $pid already exited (status $w)" >&2
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    waited=0
    killed=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge 30 ]; then
            kill -9 "$pid" 2>/dev/null || true
            killed=1
        fi
        if [ "$waited" -ge 50 ]; then
            echo "  BENCH-REAP-FAIL: $label pid $pid leaked after TERM+SIGKILL grace" >&2
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    wait "$pid" 2>/dev/null; w=$?
    if [ "$killed" -eq 1 ]; then
        echo "  BENCH-REAP: $label pid $pid forced SIGKILL after TERM grace (status $w)" >&2
        if [ "$strict" -eq 1 ]; then
            # a required child that needed SIGKILL is not a clean supervised
            # exit; the session is harness-failed for every label, not just the
            # measured subject.
            echo "  BENCH-REAP-FAIL: $label did not exit on TERM" >&2
            return 1
        fi
        return 0
    fi
    if [ "$w" -eq 0 ] || [ "$w" -eq 143 ]; then
        echo "  BENCH-REAP: $label pid $pid via TERM (status $w)" >&2
        return 0
    fi
    echo "  BENCH-REAP-FAIL: $label pid $pid abnormal TERM status $w" >&2
    if [ "$strict" -eq 1 ]; then
        return 1
    fi
    return 0
}
cleanup() {
    [ "$CLEANED" -eq 1 ] && return 0
    CLEANED=1
    stop "$ALU" proxy 0 || true
    stop "$SRV" backend 0 || true
    stop "$DNSPID" dns 0 || true
    return 0
}
trap 'cleanup; exit 130' INT TERM
trap 'rc=$?; cleanup; exit $rc' EXIT

# DNS responder (UDP + TCP on 127.0.0.1:53) mapping example.com -> 8.8.8.8
python3 /app/scripts/bench_workload.py --role dns-responder \
    --dns-bind 127.0.0.1:53 --dns-answer example.com:8.8.8.8 2>/tmp/dns.log &
DNSPID=$!
sleep 0.3

# TLS1.3 byte-exact echo backend (genuine CA-signed cert). The measured path
# uses the compiled static-musl Rust backend (identity fail-closed pinned by
# bench_run.sh via BENCH_ECHO_SHA); BENCH_BACKEND=python selects the in-process
# python EchoBackend (selftest reference / one-line fallback).
BENCH_BACKEND="${BENCH_BACKEND:-compiled}"
case "$BENCH_BACKEND" in
    compiled)
        install -m 0755 /ooda/echo-backend/echo-backend-musl /work/echo-backend
        /work/echo-backend --cert /work/server.pem --key /work/server.key \
            --addr 8.8.8.8:443 >/tmp/backend.log 2>&1 &
        SRV=$!
        ;;
    python)
        python3 /app/scripts/bench_workload.py --role backend \
            --backend-addr 8.8.8.8 --backend-port 443 \
            --cert /work/server.pem --key /work/server.key >/tmp/backend.log 2>&1 &
        SRV=$!
        ;;
    *)
        echo "BENCH-FAIL: unknown BENCH_BACKEND '$BENCH_BACKEND'" >&2
        exit 1
        ;;
esac

python3 - "$SRV" <<'PYEOF'
import socket, sys, time
pid = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 443)); s.close()
        print("BENCH-BACKEND-READY", flush=True); sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit("backend not listening in time")
PYEOF

ALU=0
ALUARGS=""
BENCH_EXEC_BINARY=""
case "$PROXY" in
    alumina)
        install -m 0755 "/ooda/alumina-head/baseline/alumina-musl" /work/alumina
        # CONNECT allowlist for the measured host with [any_illegal] notify
        # actions (alumina-specific; does not affect the measured golden path).
        printf '%s\n' \
            'listen = "127.0.0.1:8080"' \
            'startup_unresolved_allowance = 0' \
            'resolver = ["127.0.0.1"]' \
            '[any_illegal]' \
            'connect_parse = { action = "notify", scope = "connection" }' \
            'host_not_allowlisted = { action = "notify", scope = "connection" }' \
            'tls_profile = { action = "notify", scope = "connection" }' \
            'ech = { action = "notify", scope = "connection" }' \
            '[allowed_fqdn."example.com:443"]' \
            'early_data = { action = "notify", scope = "connection" }' \
            'ja4 = { action = "notify", scope = "connection" }' > /work/config.toml
        setpriv --reuid 65534 --regid 65534 --clear-groups \
            /bin/sh -c "cd /work && exec /work/alumina" >/tmp/proxy.log 2>&1 &
        ALU=$!
        BENCH_EXEC_BINARY="/work/alumina"
        ;;
    envoy)
        cp /app/scripts/bench/envoy-connect.yaml /work/envoy.yaml
        setpriv --reuid 65534 --regid 65534 --clear-groups \
            /bin/sh -c "cd /work && exec /usr/local/bin/envoy -c /work/envoy.yaml --concurrency 2 --disable-hot-restart" >/tmp/proxy.log 2>&1 &
        ALU=$!
        BENCH_EXEC_BINARY="/usr/local/bin/envoy"
        ;;
    haproxy)
        cp /app/scripts/bench/haproxy-connect.cfg /work/haproxy.cfg
        setpriv --reuid 65534 --regid 65534 --clear-groups \
            /bin/sh -c "cd /work && exec /usr/local/sbin/haproxy -f /work/haproxy.cfg" >/tmp/proxy.log 2>&1 &
        ALU=$!
        BENCH_EXEC_BINARY="/usr/local/sbin/haproxy"
        ;;
    *)
        echo "BENCH-FAIL: unknown proxy '$PROXY'" >&2
        exit 1
        ;;
esac
ALUARGS="--proxy-pid $ALU"
export BENCH_EXEC_BINARY

python3 - <<'PYEOF'
import socket, sys, time
deadline = time.time() + 60
while time.time() < deadline:
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=1.0)
        s.close()
        print("BENCH-PROXY-READY", flush=True); sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit("proxy listener never became reachable")
PYEOF

case "$PROXY" in
    alumina) CFGFILE="/work/config.toml" ;;
    envoy)   CFGFILE="/work/envoy.yaml" ;;
    haproxy) CFGFILE="/work/haproxy.cfg" ;;
    *) CFGFILE="/dev/null" ;;
esac
export BENCH_CONFIG_SHA="$(sha256sum "$CFGFILE" 2>/dev/null | awk '{print $1}' || true)"

REPORT="/out/$STAMP.json"
driver_rc=0
python3 /app/scripts/bench_workload.py --role client --mode via-proxy \
    --backend-addr 8.8.8.8 --backend-port 443 \
    --proxy-host 127.0.0.1 --proxy-port 8080 \
    --peer-host example.com --peer-port 443 \
    --cafile /work/ca.pem \
    --seconds "$SECONDS" --warmup "$WARMUP" \
    --backend-pid "$SRV" $ALUARGS \
    $WORKLOAD_ARGS \
    --json-out "$REPORT" --kind "$KIND" 2>/tmp/client.log || driver_rc=$?
sed 's/^/  client> /' /tmp/client.log 2>/dev/null || true

rc2=0
stop "$SRV" "backend" 1 || rc2=$?
stop "$DNSPID" "dns" 0 || rc2=$?
if [ "$ALU" -gt 0 ]; then
    stop "$ALU" "proxy" 1 || rc2=$?
fi
# Disarm traps only after a successful reap; on failure the armed EXIT trap
# re-runs the idempotent lenient cleanup before exit.
if [ "$rc2" -ne 0 ]; then
    echo "BENCH-FAIL: reap_rc=$rc2" >&2
    exit 1
fi
trap - INT TERM EXIT
CLEANED=1

echo "--- proxy stderr ---"
sed 's/^/  proxy> /' /tmp/proxy.log 2>/dev/null || true
echo "--- backend stderr ---"
sed 's/^/  backend> /' /tmp/backend.log 2>/dev/null || true
echo "--- dns stderr ---"
sed 's/^/  dns> /' /tmp/dns.log 2>/dev/null || true

# Session statuses: 0 valid + clean reap; 3 honest invalid; 1 harness failure.
if [ "$driver_rc" -eq 3 ]; then
    echo "BENCH-INVALID: measurement invalid (see report $REPORT); child reaps clean" >&2
    exit 3
fi
if [ "$driver_rc" -ne 0 ]; then
    echo "BENCH-FAIL: driver_rc=$driver_rc" >&2
    exit 1
fi
echo "BENCH-OK: $PROXY/$KIND/$WORKLOAD_LABEL report=$REPORT (supervised, clean)"
exit 0
