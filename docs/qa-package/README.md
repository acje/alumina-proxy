# Alumina — local static native QA package (testQA candidate)

This is the **local, isolated** static native QA package for the `alumina`
resolver. The identity below — HEAD `bbda19f` with the approved
serde-removal manifest/lock diff and the native verification consolidation
diff applied (canonical `docs/alumina-proxy.md` byte-unchanged) — is the
**historical `bbda19f` receipt provenance**, dated 2026-10-13, and is scoped to
that candidate, **not** a current-HEAD claim after the rp2e
tripwire/action/monitoring/pacing amendment (`docs/alumina-proxy.md:238-315`).
The exercised fixture-facts variant is built from the exact current source
in-run by `validate.sh`. It bundles run/validation instructions, a non-secret
example configuration, and an artifact/source identity record. It makes **no
external deployment** and contains **no secrets**.

The repository is a **scoped testQA-ready candidate**, not a
production-qualified or externally-deployed system (qualification gates in
[../build-plan.md](../build-plan.md)).

## Package contents

| File | Purpose |
|---|---|
| `config.example.toml` | Example runtime configuration (fixed documented inputs, no secrets) |
| `validate.sh` | Identity capture + local isolated smoke (positive/negative) + docs + deny/audit; hard-0 gate |

## Artifact / source identity

Three **distinct intended native Linux variants**; each has its own build
command, scope and digest — not interchangeable, no artificial shared identity:

| Variant | Path | Built/tested |
|---|---|---|
| Exercised smoke artifact (fixture-facts) | `target/fixture-facts/release/alumina` | built by the `fixtures boot` gate from exact source in-run; static-ELF + executed under privilege profile (typed-terminated positive + exit-78 negatives); sha + non-setid + `security.capability` absence proven in-run (`METADATA-OK`) |
| Production release (MID) | `target/release/alumina` | built by `mid union` (via `boundary phase1` slow tier); static-ELF + whitespace + witness gates; **not executed** by this wrapper |
| Production release (e2e musl) | `target/aarch64-unknown-linux-musl/release/alumina` | native relay/shutdown gates green (`sh scripts/verify.sh e2e relay`: 11/11; `e2e shutdown`: 10/10; harness image `localhost/alumina-e2e:e2e-20261011`, immutable ID `9191d288…`) — **historical `bbda19f`-era receipt provenance**, dated/scoped to that candidate, not a current-HEAD claim after rp2e; **not executed by this wrapper** |

`validate.sh` records per-run: source `HEAD`, working-tree status-list identity
(changed-path list, not content), and sha256 + static-ELF of the exercised
fixture-facts artifact it just built and ran.

## The authoritative smoke: the existing native fixture runner

The packaged binary is a **Linux aarch64 static ELF** — it cannot run on the
Darwin host; there is **no separate smoke command**. The sole authoritative
local smoke is the repository's native fixture runner (`validate.sh` delegates
via `scripts/verify.sh boundary phase1`):

```sh
sh scripts/verify.sh fixtures boot
```

That runner is a **host Podman coordinator (Darwin allowed by source)**: it
builds the fixture-facts variant from exact source, executes it under the
approved privilege profile (uid 65534, `no_new_privs`, empty caps) with staged
fixed inputs in a disposable container, bounds the child with real SIGTERM +
10 s deadline, and asserts the typed records with guard-bitten predicates
(plant/fail/revert/clean proven). **Standalone prerequisites:** the production
release binary `target/release/alumina` must already be built — on Linux `sh
scripts/verify.sh mid union`; on macOS run `sh scripts/verify.sh boundary
phase1` (the `mid` selectors fail closed off-Linux) — and the existing
rootless `flock-vm` **and** rootful `flock-vm-root` connections with the
pinned builder image present on both are required — `verify.sh` checks them
and fails closed otherwise. The
only authorized execution route is the pinned builder image over the
`flock-vm`/`flock-vm-root` connections — foreground `--rm` only, **no cloud
start, no VM/TCP-remote target rotation, no daemon**. The wrapper
`validate.sh` invokes `boundary phase1` (composed: the fast tier — identity +
change-scope classification + docs/unsafe/whitespace/audit — then the slow
tier, which dispatches the mid union once and then fixtures), then probes the
fixture-facts static/hash/freshness. The docs
control runs once inside `boundary phase1` (the same `docslink_check` the
`docs` selector runs); the wrapper does not re-invoke it.
Its convenience is **build ordering only** — it never provisions VMs,
connections, or images (existing infrastructure remains prerequisite), and it
**never invokes the E2E selectors** (`e2e relay`/`e2e shutdown` are separate
host selectors, not part of this smoke wrapper).

## Selector host context (sole owner)

Source-derived prerequisite context for every `scripts/verify.sh` selector
(durable authoritative source table in bd `alumina-1d5x`). Tool/connection/
image availability is **not asserted here** (not re-tested; no runnable-now
claim), and this repo never provisions VMs, connections or images.

- `mid foundations` / `mid boot` — **Linux-only**; fail closed on any
  non-Linux host. These standalone selectors are **behavior-proof only**
  (atest foundations/boot tests, fmt, whitespace): the release build,
  static-ELF, clippy, and closure-metadata proofs live at `mid union` /
  `boundary phase1`. On macOS they run through `boundary phase1` (Linux
  dispatch via the rootless `flock-vm` connection, `--pull=never`, pinned
  builder image; requires `podman`, a reachable `flock-vm` and the pinned
  image present).
- `mid full` — **Linux-only**; fail closed on any non-Linux host. Runs the
  gate-only test surface (lib unit tests + the 5 integration binaries that run
  in no other selector: eligibility, mio_matrix, main_thread_stack,
  monitor_stdout, stdout_stall) witness-off then witness-on
  (`--features alloc-witness`, incl. the eligibility witness and the
  alloc-witness-only mio_matrix binary); atest-only (no clippy/fmt).
  foundations and boot are not re-run here — `mid union` already runs them in
  the same BOUNDARY dispatch. On macOS it runs through `boundary phase1`
  (Linux dispatch via the rootless `flock-vm` connection, `--pull=never`,
  pinned builder image; requires `podman`, a reachable `flock-vm` and the
  pinned image present).
- `fixtures boot` — **host Podman coordinator (Darwin allowed by source)**;
  requires existing rootless `flock-vm` and rootful `flock-vm-root`
  connections with the pinned builder image present on both (`--pull=never`),
  prebuilt `target/release/alumina` (requires it, does not build it), and a
  SHA256 tool.
- `e2e relay` / `e2e shutdown` — **directly host-runnable (Linux or
  Darwin)**; each rebuilds the exact-source production target in-run (no
  prebuilt artifact needed) and runs **host Cargo metadata** plus git/SHA
  identity receipts. Build route depends on host: on Linux the native build
  uses host `rustc +1.99.0`; on Darwin the target probe and rebuild run
  `podman --connection flock-vm run --rm --pull=never
  <pinned rust image>` — **only `flock-vm` is accepted; any
  `PODMAN_CONNECTION` override is rejected by `e2e_build_receipt` before any
  probe/build effect** (the leftover-rootless-builder alternative is not a
  supported route) — then `linux_dispatch` hardcodes `flock-vm` +
  `--pull=never`. Gate execution then needs the **rootful** connection
  (`${PODMAN_ROOT_CONNECTION:-flock-vm-root}`) and `E2E_IMAGE` default
  `localhost/alumina-e2e:e2e-20261011`: the immutable harness image ID is
  resolved on that rootful connection, recorded in the receipt, and the
  consumers re-verify the tag resolves to it and run the ID itself.
- `boundary phase1` — **host coordinator**, split into a fast tier and a slow
  tier (both exit 1 `BLOCKED` by design; neither ever invokes the e2e
  selectors). The fast tier (`boundary phase1-fast`) runs cheap host gates
  only — identity BEFORE, change-scope classification (writes
  `target/phase1-scope`), docs link gate, unsafe-surface gate, `git diff
  --check`, audit/deny, identity AFTER/compare — with **no Linux MID, no
  fixtures**, so a cheap-gate failure aborts before the ~90-min
  compile-dominated dispatch. The slow tier (`boundary phase1-slow`) reads the
  scope marker (missing => full, fail-safe): on docs-only it emits an explicit
  `PHASE1-SLOW-SKIPPED-BY-DESIGN` and skips the MID; on full it dispatches the
  Linux MID union once (foundations + boot command sets) and the Linux `mid
  full` unfiltered full suite once (witness-off + witness-on), then fixtures,
  identity AFTER/compare and artifact identity. The composed selector runs the
  fast tier then the slow tier unless the scope is docs-only. Host
  tools required and fail closed when absent: `podman` + reachable `flock-vm`;
  Node with **`NODE_OPTIONS`/`NODE_PATH` unset** and
  `scripts/docs_check/check.mjs`; `git`; `sha256sum` (or `shasum`);
  `python3` (config-candidate observation); `cargo-audit` + `cargo-deny`.
  **Never invokes the e2e selectors**; exit-zero coordination is not release
  qualification.
- `docs` (`verify.sh docs`) — offline link gate (canonical + moved/new roots): requires Node with
  **`NODE_OPTIONS`/`NODE_PATH` unset** and `scripts/docs_check/check.mjs`
  present; runs no network.

## Example inputs are illustrative — never executed by any gate

`config.example.toml` (`[allowed_fqdn."<fqdn>:<port>"]` keyed tables —
`api.github.com:443`, `example.com:443`, `www.example.net:443`, each carrying
`early_data = { action = "flare_only", scope = "connection" }` under
`[any_illegal] scope = "connection"` — resolver
`["1.1.1.1#cloudflare-dns.com#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
"8.8.8.8#dns.google#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
"9.9.9.9#dns.quad9.net#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
"208.67.222.222#dns.opendns.com#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
"94.140.14.14#dns.adguard.com#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]` —
`IP#fqdn#pin-sha256=<b64>` strict-pin entries carrying each resolver's validated
DoT hostname and SPKI pin (the V5 strict-pin form, null-pin syntax placeholders)
documents a fixed, non-secret configuration shape; it is
**illustrative only and executed by nothing**. The fixture runner stages its own
fixed inputs; `validate.sh` never reads the example. Specifying it as a runnable
input, or relabelling the fixture gate's inputs as the example, would be a false
claim. The example's public resolver set is illustrative only — it is never
executed, so nothing in this package dials any resolver it names.

## Protocol compatibility (workloads dialed through Alumina)

The example allowlist is in `<fqdn>:<port>` form — `api.github.com:443` (a
real-world HTTPS API target) and illustrative `example.com:443` /
`www.example.net:443` — so HTTPS and NATS transports can be reasoned about
against Alumina's fixed wire contract, with **zero `alumina-proxy` code
changes**. The contract (`docs/alumina-proxy.md:17-50,200-202`) requires: (1)
an explicit `HTTP/1.1` `CONNECT <fqdn>:<port>` whose port exactly
matches the allowlisted entry; (2) the **client speaks first**,
immediately after `200 Connection established`, with a TLS 1.3 `ClientHello`
whose SNI equals `<fqdn>` (Barrier A); (3) the upstream server sends **zero
bytes before the validated `ClientHello` is flushed upstream** (Barrier B —
`EarlyUpstreamData` closes the tunnel if the server speaks first). Once the
gate opens, encrypted application bytes are relayed opaquely, with no ALPN or
application-protocol inspection (`docs/alumina-proxy.md:19-21,48-50`).

| Workload | Transport | Against Alumina |
| --- | --- | --- |
| HTTPS REST/API — `https://api.github.com:443` (e.g. `reqwest` with `HTTPS_PROXY=http://<proxy>:5353`, TLS 1.3) | TLS 1.3 `ClientHello` (SNI) immediately after `200` | **Compatible** — works out of the box |
| NATS Mode 1 — standard NATS (`nats://` / `tls://` server-first StartTLS) | server-speaks-first plaintext `INFO {...}` before any TLS upgrade | **Incompatible** — even when the CONNECT port is authorized, the server-first plaintext `INFO` trips Barrier B (`EarlyUpstreamData`) and Barrier A (non-TLS client bytes) |
| NATS Mode 2 — NATS `tls_first` (`handshake_first: true`; `async_nats::ConnectOptions::tls_first()`) | client TLS 1.3 `ClientHello` (SNI) right after `200`; `INFO` inside the encrypted TLS 1.3 stream | **Compatible** — wire-compatible with zero `alumina-proxy` changes |
| NATS Mode 3 — NATS over WebSockets (`wss://<nats-fqdn>:443`) | TLS 1.3 `ClientHello` (SNI) right after `200`; HTTP `Upgrade: websocket` + NATS frames inside the encrypted tunnel | **Compatible** — wire-compatible with zero `alumina-proxy` changes |

For NATS workloads the `alumina-proxy` side needs no change; the NATS
**client/workload** must (a) establish the TCP tunnel via
`HTTP CONNECT <nats-fqdn>:<allowlisted-port>` to Alumina and (b) match the
allowlisted entry's port and speak a TLS 1.3 `ClientHello` first (`wss://` or
`tls_first`). A client that tunnels via HTTP CONNECT to an allowlisted port and
speaks a TLS 1.3 `ClientHello` first matches the contract exactly.

## Documented binary outcomes (grounded in the fixture gate)

- **Supervised typed-terminated:** `startup_final status="terminated"` →
  `shutdown_final status="drained"`, receipt `FIXTURE-POSITIVE-SUPERVISED:
  reaped child rc=0`, child reaped at exit 0.
- **Privilege negatives:** root uid / missing `no_new_privs` / raised caps →
  exit 78 with a naming diagnostic; empty stdout, byte-exact stderr.
- **Unresolved-allowlist bound:** `startup_unresolved_allowance = 0` + no
  resolvable name → EX_TEMPFAIL 75 — bounded intentional failure, never a hang
  or false clean.

## JA4-flare verification (TLS 1.3-only)

A JA4 change-signal flare is verified with **two TLS 1.3-only ClientHellos** whose
JA4 fingerprints differ; it is a **fact**, never a block. The client must be pinned
to TLS 1.3 on both offers — the version-offer gate (`docs/alumina-proxy.md:47`;
`validate_versions` at `src/client_hello.rs:652-665`) requires `supported_versions`
with `0x0304` as the only non-GREASE version, so a TLS 1.2-capable offer is
`InvalidVersionOffer` → `any_illegal` → **Block**, not a flare.

Procedure (Go client pinned to TLS 1.3):

1. Dial the allowlisted `<fqdn>:<port>` via HTTP CONNECT to the proxy, then send the
   baseline ClientHello with `tls.Config{ MinVersion: tls.VersionTLS13,
   MaxVersion: tls.VersionTLS13, NextProtos: []string{...} }` and SNI `<fqdn>`.
   The baseline is **silent**: it records the first-seen JA4 baseline and emits no
   JA4 change fact.
2. Open a second tunnel to the same ordinal and send a ClientHello yielding a
   **distinct JA4** (e.g. a different ALPN set in `NextProtos`). The serving path
   records `note_fact_ja4_change` (`src/serving.rs:2737`) — a **fact**, not an
   action.
3. Read the monitor records. The `kind=monitor_domain` detail batch carries the
   change signal — `d0j=1` (per-ordinal change counter) with
   `d0v="<36-char-ja4>"` (the latest changed JA4, 36 chars), zero-suppressed
   together per the C1 amendment (`docs/alumina-proxy.md:950-964`). The
   `kind=monitor` summary carries the globals `actions_total=0` and
   `refusals_total=0` — a JA4 change is a fact, so no action or refusal fires.

Expected signal (flare_only, no block):

| Record | Field | Expected |
| --- | --- | --- |
| `kind=monitor` summary | `actions_total` | `0` |
| `kind=monitor` summary | `refusals_total` | `0` |
| `kind=monitor_domain` batch | `d0j` | `1` |
| `kind=monitor_domain` batch | `d0v` | `"<36-char-ja4>"` |

Anti-pattern: **curl and `openssl s_client` default to offering TLS 1.2**, so their
ClientHellos trip `InvalidVersionOffer` → `any_illegal` → **Block** (incrementing
`actions_total`/`refusals_total`), never a flare. A JA4 flare is only observable
with a TLS 1.3-only client.

## Validating the package

```sh
sh docs/qa-package/validate.sh
```

1. Mandatory prerequisites fail **before any gate effect** (`git rev-parse`,
   sha256 hasher, `file`): any absence is `QA-PACKAGE-PREREQ-FAIL` and aborts
   the run before the heavy native gate, never a silent skip and never a
   pass-by-existing.
2. Runs `scripts/verify.sh boundary phase1` with `PHASE1_SCOPE=full` forced
   (the wrapper always exercises the full ceremony — the Linux MID union once,
   then supervised `fixtures boot` positive + exit-78 negatives, the docs link
   gate once (`docslink_check`), `cargo audit` + `cargo deny check` — never a
   docs-only skip).
3. Probes the exercised fixture-facts artifact the gate just built: static ELF
   + sha256 + freshness proven against the in-run variant marker the fixture
   gate wrote.
4. Emits `QA-PACKAGE-VALIDATE-OK`, exit 0, only when identity resolved, the
   fresh-variant proof holds and every sub-gate hard-0. Three-state outcome:
   - **OK** (exit 0) — every sub-gate hard-0, including `boundary phase1`
     exiting 0.
   - **BLOCKED** (non-zero) — `boundary phase1` coordinated (emitted
     `BOUNDARY-OWNER-COORD-OK`) but its completion is `FINAL-PHASE1-COMPLETION:
     BLOCKED` pending release gates; attribution is still this-run, but
     `QA-PACKAGE-VALIDATE-OK` is never emitted.
   - **FAIL** (non-zero) — genuine gate failure (non-zero boundary without the
     coordination markers, or any probe/identity/freshness failure).

## Known-open items (not claims of completion)

- F3 current-serving completeness witness open (matrix implemented —
  `tests/mio_matrix.rs`; build-plan §0).
- F4 parser-fuzzing campaigns not shipped.
- Deployment confinement, external validation, production qualification out of
  scope; `RELEASE-NOT-READY` stays the honest boundary
  diagnostic — never converted to a release clean.
