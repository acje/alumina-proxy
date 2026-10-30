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
  bad behavior. In the idiomatic deployment the only client is the
  trusted-at-rest app on a fixed golden path, so a tripwire firing is a
  high-value signal — highly unexpected, almost certainly operator
  misconfiguration or adversarial activity. Tripwires react
  on the first sign of deviation.
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

- **`docs/architecture.html` is the single source of truth for architecture
  documentation.** It is *derived from code* at a pinned revision and exists so
  that a reviewer can do higher-level code review without re-reading every
  module. Every factual claim cites a spec clause or a `file:line` at that
  revision.
- **It describes, it does not adjudicate.** No findings, severities, review
  verdicts, recommendations, open questions, decisions, task lists, or bead IDs
  appear in it. Issues, decisions, evidence, and verdicts live in `bd` only.
  As-built statements whose subject is a limitation are retained as fact with
  no issue framing.
- **`docs/alumina-proxy.md` defines what the code should do.** It is the
  governing specification and byte-frozen until a deliberate governance
  amendment changes it; a design improvement that needs different behaviour
  amends the spec, the code, the tests, and the architecture document in one
  governed increment.
- **One architecture narrative.** `docs/architecture.md` is retired; no other
  document may carry a second architecture narrative. Practical/QA documents
  may cite the architecture document, never duplicate it.
- **Behavioural change carries its documentation.** Any increment that changes
  observable behaviour updates `docs/architecture.html` in the same increment;
  its citations must still resolve at the new revision.

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
  specification (sha256 `4e59e9d9e535475510e961fa719c69d1fa1ca8838452b32d5805b8f30fb9e78a`). Never edit it; documents only
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
