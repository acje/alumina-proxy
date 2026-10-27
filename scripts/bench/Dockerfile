# Alumina e2-micro benchmark harness image (bench-suite-20261027).
#
# SEPARATE from the pinned localhost/alumina-e2e:e2e-20261011 image (untouched).
# Multi-stage: copy the Envoy v1.40.2 and HAProxy 3.4.7 release binaries onto a
# glibc debian:trixie-slim base, then apt-get the runtime libraries the two
# binaries need (the official haproxy:3.4.7 image is itself trixie-built:
# glibc>=2.38 + OpenSSL 3.5, so trixie-slim satisfies its symbol versions;
# ldd shows envoy needs only base glibc) plus the python3/openssl/iproute2/
# util-linux tools the in-container topology needs.
#
# The client, backend, DNS responder and one proxy all run inside this one
# container so CPU sampling is uniform in-container over the measurement
# aperture. e2-micro equivalence is modeled by WORKLOAD PARAMETERS only; this
# harness is never container cgroup-capped.
FROM envoyproxy/envoy:v1.40.2 AS envoy
FROM haproxy:3.4.7 AS haproxy
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        openssl \
        ca-certificates \
        libssl3 \
        liblua5.4-0 \
        libpcre2-8-0 \
        libzstd1 \
        zlib1g \
        libcrypt1 \
        iproute2 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=haproxy /usr/local/sbin/haproxy /usr/local/sbin/haproxy

CMD ["/bin/true"]
