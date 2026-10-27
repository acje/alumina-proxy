# Alumina — agent instructions

Alumina is a single-binary, statically-linked HTTPS CONNECT egress proxy for
constrained servers. Work here is governed by the fixed repository
specification, not feature growth.

## Design direction

Alumina is the castle's **exit gate** — deliberately narrow, permanently. It
does not guard the interior, police ingress, or inspect payloads; scope never
grows beyond CONNECT-egress-with-allowlist. The application and operator are
trusted at rest; the problem is accepting the inevitable compromise of an
application and using egress to identify it and stop further exploitation.

Every change must preserve:

- **No silent acceptance.** Every deviation from the configured golden path is
  detected and acted on (flare / block / tarpit); there is no tolerated rate of
  bad behavior. Tripwires are trigger-happy: react on the first sign of
  deviation.
- **Operator chooses the action; the proxy owns the semantics.** The action for
  a context is operator configuration; security semantics are fixed constants
  (the allowlist is the operator's, enforcement is the proxy's).
- **More is less.** Narrow scope is the mechanism for provable invariants. The
  fixed profile — single boot owner and single serving owner, two reused 128 KiB
  per-tunnel buffers, no post-boot heap alloc/dealloc, no runtime-surface
  expansion — is the inviolable contract and never yields to a feature.

## Rules

- `docs/alumina-proxy.md` is the sole, byte-canonical governing
  specification (sha256 `42ee92b8…25de`). Never edit it; documents only
  restate or cite it.
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
