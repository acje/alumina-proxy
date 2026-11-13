# Alumina — local static native QA package (testQA candidate)

This is the **local, isolated** static native QA package for the `alumina`
resolver. The exercised fixture-facts variant is built from the exact current
source in-run by `validate.sh`. It bundles run/validation instructions, a
non-secret example configuration, and an artifact/source identity record. It
makes **no external deployment** and contains **no secrets**.

The repository is a **scoped testQA-ready candidate**, not a
production-qualified or externally-deployed system (qualification gates in
[../verification.md](../verification.md)).

Historically, on 2026-11-08, the local run for source revision
`b1ff6909f215b860badec8f519349d7dc85f688c` completed its Linux union and
boot-fixture children; the then-existing boundary wrapper's final marker remained
**BLOCKED** with exit 1 by design. That wrapper has since been removed. Separate
relay and shutdown E2E runs passed their selected
local cases using a plain-DNS fixture, not a live validating-resolver matrix.
Those receipts are scoped to that source revision and their respective
artifacts; they do not establish deployment or release qualification.

## Package contents

| File | Purpose |
| --- | --- |
| `config.example.toml` | Example runtime configuration (fixed documented inputs, no secrets) |
| `validate.sh` | Source status-list identity + local fixture smoke (positive/negative) + fresh artifact hash and static-ELF probe; not a release gate |

## Artifact / source identity

Three **distinct intended native Linux variants**; each has its own build
command, scope and digest — not interchangeable, no artificial shared identity:

| Variant | Path | Built/tested |
| --- | --- | --- |
| Exercised smoke artifact (fixture-facts) | `target/fixture-facts/release/alumina` | built by `fixtures boot` in-run; executed under privilege profiles; sha + non-setid + `security.capability` absence checked by the fixture; `validate.sh` probes static ELF and the fresh marker |
| Production release (MID) | `target/release/alumina` | built by Linux `mid union` or copied out by `host-mid union`; static-ELF + whitespace + witness checks; **not executed** by the validator |
| Production release (e2e musl) | `target/aarch64-unknown-linux-musl/release/alumina` | production release target for the native `e2e relay` / `e2e shutdown` host selectors; **not executed by the validator** |

`validate.sh` records per-run: source `HEAD`, working-tree status-list identity
(changed-path list, not content), and sha256 + static-ELF of the exercised
fixture-facts artifact it just built and ran.

## The authoritative smoke: the existing native fixture runner

The packaged binary is a **Linux aarch64 static ELF** — it cannot run on the
Darwin host. The local smoke is the repository's native fixture runner;
`validate.sh` invokes it directly and adds its own artifact checks:

```sh
sh scripts/verify.sh fixtures boot
```

That runner is a **host Podman coordinator (Darwin allowed by source)**: it
builds the fixture-facts variant from exact source, executes it under the
approved privilege profile (uid 65534, `no_new_privs`, empty caps) with staged
fixed inputs in a disposable container, bounds the child with real SIGTERM +
10 s deadline, and asserts the typed records with guard-bitten predicates
(plant/fail/revert/clean proven). The production release binary
`target/release/alumina` must already be built; use `sh scripts/verify.sh mid
union` on Linux or `sh scripts/verify.sh host-mid union` on macOS. The latter
copies the release artifact to the host. Existing rootless **and** rootful
Podman connections (`PODMAN_CONNECTION` / `PODMAN_ROOT_CONNECTION`) and the
pinned base image on both are required. Connection names may be exported or set
in the gitignored `.ooda/podman-connections.env` (sourced when present; an
already-set environment variable wins). The derived `ALT_IMAGE` (also the
fixture image by default) should already be present on both connections: if
absent, the script attempts to build it, requiring network access. The harness
does not provision VMs or connections; container runs use `--rm --pull=never`.
No build or fixture checks should run concurrently because they share artifacts
and volumes. The validator does not run MID, docs, audit/deny or E2E checks.

## Selector host context (sole owner)

Source-derived prerequisite context for every `scripts/verify.sh` selector
(durable authoritative source table in bd `alumina-1d5x`). Tool/connection/
image availability is **not asserted here** (not re-tested; no runnable-now
claim). The harness does not provision VMs or connections; it may build a
missing derived image as described below.

- `mid foundations` / `mid boot` — **Linux-only**; fail closed on any
  non-Linux host. These standalone selectors are **behavior-proof only**
  (atest foundations/boot tests, fmt, whitespace): the release build,
  static-ELF, clippy, and closure-metadata proofs live at `mid union`.
- `mid full` — **Linux-only**; fail closed on any non-Linux host. Standalone
  gate-only selector: runs the gate-only test surface (lib unit tests + the 6
  gate-only integration binaries: eligibility, mio_matrix, main_thread_stack,
  monitor_stdout, stdout_stall, stdout_closed) witness-off then witness-on
  (`--features alloc-witness`, incl. the eligibility witness and the
  alloc-witness-only mio_matrix binary); atest-only (no clippy/fmt). Its
  surface is subsumed by `mid union` (one Linux dispatch, lib + all eight
  integration targets witness-off/on).
- `host-mid foundations|boot|clippy|union|full` — host Podman dispatch of the
  corresponding Linux `mid` selector, including on macOS. Requires `podman`, a
  reachable rootless `PODMAN_CONNECTION` and the derived `ALT_IMAGE` (default
  `localhost/alumina-verify:20261029`). If missing, the script attempts to
  build it from the pinned Rust base, including networked package/component
  installation. It uses named target and Cargo-home volumes by default and
  creates missing volumes; `ALT_NO_VOLUME=1` uses host target bind-mounts.
  `host-mid union` copies the production artifact to `target/release/alumina`
  with volume/host digest comparison (copy is unnecessary in bind-mount mode).
- `fixtures boot` — **host Podman coordinator (Darwin allowed by source)**;
  requires existing rootless and rootful Podman connections with the pinned
  base image present on both and the derived fixture image on both (or a
  successful automatic build),
  prebuilt `target/release/alumina` (requires it, does not build it), and a
  SHA256 tool.
- `e2e relay` / `e2e shutdown` — **directly host-runnable (Linux or
  Darwin)**; each rebuilds the exact-source production target in-run (no
  prebuilt artifact needed) and runs **host Cargo metadata** plus git/SHA
  identity receipts. Build route depends on host: on Linux the native build
  uses host `rustc +1.99.0`; on Darwin the target probe and rebuild run
  `podman --connection "$PODMAN_CONNECTION" run --rm --pull=never
  <pinned rust image>` — `PODMAN_CONNECTION` is **required** (fail-closed) and
  both the probe and the build dispatch resolve the **same** connection, so a
  probe/build owner mismatch is impossible by construction. Gate execution
  then needs the **rootful** connection (`$PODMAN_ROOT_CONNECTION`, required)
  and `E2E_IMAGE` default
  `localhost/alumina-e2e:e2e-20261011`: the immutable harness image ID is
  resolved on that rootful connection, recorded in the receipt, and the
  consumers re-verify the tag resolves to it and run the ID itself.
- `supply-chain audit-deny` — independent host check requiring `cargo-audit`
  0.22.1, `cargo-deny` 0.19.4 and Cargo toolchain 1.99.0. It runs audit with
  `--no-fetch` against the local advisory DB, then `cargo deny check`; missing
  tools, version mismatch or a failing check is nonzero.
- `identity snapshot <directory>` / `identity compare <before> <after>` —
  independent source/environment stability receipts. Snapshots require git,
  SHA256, Python 3 and Node with `NODE_OPTIONS`/`NODE_PATH` unset; they record
  HEAD, status, hashes of the fixed input set and selected environment/config
  observations. Compare checks those four records, not every possible input.
  `identity artifact <path>` hashes an existing file; it does not prove that
  file was built or executed. Keep snapshots under `target/` to avoid changing
  the status list.
- `docs` (`verify.sh docs`) — full offline docs gate, not just links:
  link/fragment over the 8-root `DOCSLINK_ROOTS` (incl.
  `docs/trust-telemetry-design.md`) + physical INTENDED +
  cfg-parentage + unsafe surface + frozen-spec digest; requires Node with
  **`NODE_OPTIONS`/`NODE_PATH` unset** and `scripts/docs_check/check.mjs`
  present; runs no network.

## Example inputs are illustrative — never executed by any gate

`config.example.toml` (`[allowed_fqdn."<fqdn>:<port>"]` keyed tables —
`api.github.com:443`, `example.com:443`, `www.example.net:443`, each carrying
`early_data = { action = "notify", scope = "connection" }` and
`ja4 = { action = "notify", scope = "connection" }` plus a mandatory
`dns_assurance = "resolver_trusted"` string key; `[any_illegal]` with
the four per-control keys `connect_parse`, `host_not_allowlisted`, `tls_profile`,
`ech`, and the three optional per-class SP-001 gate bars `[bad_handshake]`,
`[illegal_fqdn]`, `[ja4]` (each `threshold = 1`, `window_secs = 900`,
the SP-001 defaults); an `[early_data]` gate section is rejected at load (exit 78)
instead of being accepted as an inert bar — resolver
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

## JA4 change-signal verification (TLS 1.3-only)

A JA4 change signal is verified with **two TLS 1.3-only ClientHellos** whose JA4
fingerprints differ. The change is a **fact** that selects the configured per-FQDN
`ja4` control action through `decide()` (§T6, §Per-control enforcement schema):
with the example config's `ja4 = { action = "notify", scope = "connection" }` the
change fires a **Notify** — never a Block. The client must be pinned
to TLS 1.3 on both offers — the version-offer gate (`docs/alumina-proxy.md:47`;
`validate_versions` at `src/inspection/client_hello.rs:701-716`) requires `supported_versions`
with `0x0304` as the only non-GREASE version, so a TLS 1.2-capable offer is
`InvalidVersionOffer` → `any_illegal` → the configured `any_illegal` action
(**Block** in the example config), not a JA4 change signal.

Procedure (Go client pinned to TLS 1.3):

1. Dial the allowlisted `<fqdn>:<port>` via HTTP CONNECT to the proxy, then send the
   baseline ClientHello with `tls.Config{ MinVersion: tls.VersionTLS13,
   MaxVersion: tls.VersionTLS13, NextProtos: []string{...} }` and SNI `<fqdn>`.
   The baseline is **silent**: it records the first-seen JA4 baseline and emits no
   JA4 change fact.
2. Open a second tunnel to the same ordinal and send a ClientHello yielding a
   **distinct JA4** (e.g. a different ALPN set in `NextProtos`). The serving path
   records `note_fact_ja4_change` (`src/runtime/reactor.rs:2859`) — the change fact
   that selects the per-FQDN `ja4` control action.
3. Read the monitor records. The `kind=monitor_domain` detail batch carries the
   change signal — `d0j=1` (per-ordinal change counter) with
   `d0v="<36-char-ja4>"` (the latest changed JA4, 36 chars), zero-suppressed
   together per the C1 amendment (`docs/alumina-proxy.md:713-718`). The
   `kind=monitor` summary carries the globals `actions_total=1` (the Notify) and
   `refusals_total=0` (no Block).

Expected signal (notify, no block):

| Record | Field | Expected |
| --- | --- | --- |
| `kind=monitor` summary | `actions_total` | `1` (the Notify) |
| `kind=monitor` summary | `refusals_total` | `0` |
| `kind=monitor_domain` batch | `d0j` | `1` |
| `kind=monitor_domain` batch | `d0v` | `"<36-char-ja4>"` |

Anti-pattern: **curl and `openssl s_client` default to offering TLS 1.2**, so their
ClientHellos trip `InvalidVersionOffer` → `any_illegal` → **Block** (incrementing
`actions_total`/`refusals_total`), never a JA4 change signal. A JA4 change signal
is only observable with a TLS 1.3-only client.

## Validating the package

```sh
sh docs/qa-package/validate.sh
```

1. Checks a SHA256 hasher, git HEAD and status, and `file` before any fixture
   effect. Missing or failing prerequisites produce `QA-PACKAGE-PREREQ-FAIL`.
   The recorded status-list hash identifies changed paths, **not their content**.
2. Removes the prior fixture variant marker, then runs `fixtures boot`; it
   requires the prebuilt production binary and Podman prerequisites above.
3. Requires an executable fixture-facts artifact and a nonempty in-run marker,
   compares their SHA256 digests, and checks `file` output for a statically
   linked ELF. Probe errors, missing or mismatched artifacts and fixture
   failure are nonzero and never produce success.
4. Emits `QA-PACKAGE-VALIDATE-OK: fixture smoke only; not release
   qualification` and exits 0 only after those checks pass. This does not run
   MID, docs, supply-chain, source snapshot/compare or E2E selectors; run any
   applicable checks independently using [the command set](../verification.md).
