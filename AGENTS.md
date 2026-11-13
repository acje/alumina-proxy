# Alumina — agent instructions

Alumina is a single-binary, statically-linked HTTPS CONNECT egress proxy for
constrained servers. Work here is governed by the fixed repository
specification, not feature growth.

## Rust style
Select the `alox-style` pointer skill; canonical rules are the sf-sdlc SSOT
docs `docs/rust-style.md` + `docs/alox-style.md` (global pointers only). The
fixed governing spec, allocation limits, numeric bounds, and verification
gates here are unchanged.

## Design direction

Alumina is the castle's **exit gate** — deliberately narrow, permanently. It
does not guard the interior, police ingress, or inspect payloads; scope never
grows beyond CONNECT-egress-with-allowlist. The application and operator are
trusted at rest; the problem is accepting the inevitable compromise of an
application and using egress to identify it and stop further exploitation.

Every change must preserve:

- **No silent acceptance.** Every deviation observable through the proxy's
  CONNECT/initial-ClientHello and enumerated tripwire surfaces is detected and
  acted on (`notify` / `block`; the reserved tarpit action is deferred, not
  configurable); there is no tolerated rate of bad behavior, and behavior
  hidden inside the tunnel or riding an admitted endpoint's own capabilities
  never surfaces there — outside the detection reach. The idiomatic
  deployment's only client is the trusted-at-rest app on a fixed golden path,
  so a tripwire firing is a **high-value signal**, almost certainly operator
  misconfiguration or adversarial activity.
- **Operator chooses the action; the proxy owns the semantics.** The action for
  a context is operator configuration; security semantics are fixed constants
  (the allowlist is the operator's, enforcement is the proxy's). The all-scope
  block bar (threshold and window, the three per-class gate sections
  `[bad_handshake]`/`[illegal_fqdn]`/`[ja4]`) is operator configuration
  too; the gate mechanism itself is a fixed constant.
- **More is less.** Narrow scope is the mechanism for provable invariants. The
  fixed profile — single boot owner and single serving owner, two reused 128 KiB
  per-tunnel buffers, no post-boot *first-party* heap alloc/dealloc, no
  runtime-surface expansion — is the inviolable contract and never yields to a
  feature. Dependency-internal allocation is a bounded seam outside the
  invariant's first-party scope, and the per-connect DoT setup seam is an
  authorised first-party allocation point (`docs/alumina-proxy.md` §Zero-Allocation
  Invariant: first-party scope).

## Documentation model

- **`docs/alumina-proxy.md` defines what the code should do.** It is the
  governing specification and byte-frozen until a deliberate governance
  amendment changes it; a design improvement that needs different behaviour
  amends the spec, the code, and the tests in one governed increment.

### Reconciling a deviation

There is no default direction of authority between code, specification, and
documentation. Each discrepancy is evaluated on its merits and resolved by
whichever change best serves one goal: **a more robust and more secure proxy.**
The resolution — code change, governed spec amendment, documentation
correction, or explicit acceptance — is recorded in `bd` with its rationale.
Iterate on every perspective of the system; never let a discrepancy stand
because one side "wins".

## Rules

- `docs/alumina-proxy.md` is the sole, byte-canonical governing
  specification (sha256 `99c5b420a7ac2802731b6ad80bc5f9bdf1cb3136a722ea7eccb606e099507e03`) and is byte-frozen by default.
  Only an explicitly user-authorized, scoped governance amendment may change
  it. That increment must update the spec, this digest pin, code and tests
  together, pass required independent source and governance
  reviews before adoption, and preserve all security and resource limits.
  Other documents only restate or cite the specification.
- Native verification entry point, QA run and prerequisite ownership are
  `docs/qa-package/README.md`; the verify command set is in
  `docs/verification.md`.
  Doc-only changes: `sh scripts/verify.sh docs`.
- `mid` selectors are Linux-only and fail closed off-Linux; on macOS use the
  corresponding `sh scripts/verify.sh host-mid <scope>` Podman dispatch.
  `fixtures boot` and the `e2e` selectors are independently host-runnable with
  the prerequisites described in the QA package.
- Behavioural changes run red→green and preserve the fixed profile: single
  boot owner and single serving owner, two reused 128 KiB per-tunnel buffers,
  no post-boot *first-party* heap alloc/dealloc (dependency allocations are a
  bounded seam and the per-connect DoT setup seam is an authorised first-party
  allocation point — §Design direction; `docs/alumina-proxy.md` §Zero-
  Allocation Invariant) — no runtime-surface expansion.
