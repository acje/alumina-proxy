# alumina `x86_64-unknown-linux-musl`

Static build of `alumina`, the HTTPS CONNECT egress proxy, for
`x86_64-unknown-linux-musl`. It is produced by this repository's own Linux
boundary gate (`sh scripts/verify.sh mid union`) in the same container run that
publishes it, so the shipped binary is the exact file the gate proved static —
no dynamic `NEEDED` entries, no `PT_INTERP`.

## Status

A **scoped local QA candidate, not production-qualified** and not externally
deployed. Qualification requirements and validation prerequisites are in the QA
package (`README.md`, `docs/qa-package/README.md`).

## Configuration is yours to write

The binary reads `./config.toml`; there are no CLI arguments or environment
overrides. `config.example.toml` documents the schema but is not a runnable
configuration:

- Its `pin-sha256=` resolver values are **SYNTAX PLACEHOLDERS**. Replace each
  with the resolver's real SPKI SHA-256 pin; a wrong pin fails the handshake
  closed.
- Every `[allowed_fqdn."<fqdn>:<port>"]` entry must declare an explicit
  `dns_assurance` trust class (`resolver_trusted`, `resolver_authenticated`, or
  `delegated_dnssec`). All keys are mandatory — a missing key fails startup with
  exit 78.
- The example binds `127.0.0.1:5353` for local testing.

## Deployment

The documented pattern is an operator-built `FROM scratch` image
(`docs/deployment.md` §2). This release is a binary, not a prebuilt container
image.

## Assets

| Asset | What it is |
| --- | --- |
| `alumina-<tag>-x86_64-unknown-linux-musl` | the static binary the gate proved (`<tag>` is this release's tag) |
| `config.example.toml` | schema example, placeholders unreplaced (see above) |
| `SHA256SUMS` | sha256 of the two assets above |

Download all three into one directory, then verify, substituting the release tag:

```sh
sha256sum -c SHA256SUMS
gh attestation verify alumina-<tag>-x86_64-unknown-linux-musl --repo acje/alumina-proxy
```

The provenance attestation covers the binary asset only; `SHA256SUMS` and
`config.example.toml` are not attested subjects.
