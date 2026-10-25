# Alumina — agent instructions

Alumina is a single-binary, statically-linked HTTPS CONNECT egress proxy for
constrained servers. Work here is governed by the fixed repository
specification, not feature growth.

## Rules

- `docs/alumina-proxy.md` is the sole, byte-canonical governing
  specification (sha256 `42ee92b8…25de`). Never edit it; documents only
  restate or cite it. The authorised exceptions are the narrow, user-authorized
  `rp2e` (2026-10-14) tripwire/action/monitoring/pacing amendment, the
  `alumina-9t6w` (2026-10-15) `<fqdn>:<port>` allowlist/CONNECT/dial amendment,
  the `alumina-tm6m` (2026-10-16) `512 / 128` tunnels/pending setups and
  `2 × 128 KiB` per-slot slab amendment, the `alumina-sechd` (2026-10-17)
  security-hardening CONNECT/TLS identity/DNS-cache/scheduling/logging
  amendment, the `alumina-skhc` (2026-10-17) CONNECT/configuration/
  destination-address hardening amendment, the `alumina-icdl`
  (2026-10-17) CONNECT Content-Length canonical-digit amendment, and the
  `alumina-mema` (2026-10-18) memory-accounting retained-serving-workspace
  amendment, the `alumina-hrdn` (2026-10-19) DNS wrong-family
  records/ClientHello handshake bound/CONNECT discriminant split amendment, the
  `alumina-hrdn2` (2026-10-19) CONNECT header-line count bound/passive resolver
  degraded signaling/widened refresh band amendment, the `alumina-hrdn3`
  (2026-10-19) CNAME bailiwick enforcement/DNS anomaly fact surface/resolver
  peer assertion amendment, the `alumina-hrdn4` (2026-10-20) resolver set in
  the validated TOML config/resolv.conf reader removed/V18 failover (Stage 1&2)
  amendment, the `alumina-dot-chain-v37` (2026-10-20) resolver endpoint as
  `IP#fqdn` (V37, Package 1 of the DoT chain) amendment, the
  `alumina-dot-chain-v1-v5` (2026-10-20) DoT transport (V1) and strict SPKI
  pinning (V5), Package 2 of the DoT chain amendment, the `alumina-sslv`
  (2026-10-21) serving-from-stale observability level bit amendment, the
  `alumina-failbk` (2026-10-21) failback consecutive-success hysteresis
  amendment, the `alumina-dotrt` (2026-10-21) DoT transport serving-lifetime
  warm reuse amendment, the `alumina-dotdg` (2026-10-21) DoT→plain downgrade
  counter amendment, and the `alumina-zai` (2026-10-21) Zero-Allocation
  Invariant first-party scope/rustls bounded seam amendment, and the
  `alumina-cfgk` (2026-10-24) keyed `[allowed_fqdn."<fqdn>:<port>"]`
  configuration schema/16 KiB document bound amendment and its second
  authorization (2026-10-24) startup-final record-shape extension (`:67`,
  `:236`; log queue geometry unchanged), and the `alox7` (2026-10-25)
  low-risk alox hardening amendment (probe isolation, failover ordinal,
  failback reset, JA4 baseline overflow, zero-TTL stale serving, DoT TLS
  1.3-only, monitor loss-flag bitset), all
  recorded in the document; no further amendment authority is implied.
- Status is a scoped local testQA candidate — not production-qualified;
  serving-qualification gates stay open (`docs/build-plan.md` owns them).
- Native verification entry point, QA run and prerequisite ownership are
  `docs/qa-package/README.md`; the verify command set is in
  `docs/verification.md`.
  Doc-only changes: `sh scripts/verify.sh docs`.
- `mid` selectors are Linux-only and fail closed off-Linux (reach them via
  `sh scripts/verify.sh boundary phase1` on macOS); `fixtures boot` and the
  `e2e` selectors are directly host-runnable with existing Podman VM
  connections/images (`boundary phase1` never executes E2E).
- Behavioural changes run red→green and preserve the fixed profile: single
  boot owner and single serving owner, two reused 128 KiB per-tunnel buffers,
  no post-boot heap alloc/dealloc, no runtime-surface expansion.
