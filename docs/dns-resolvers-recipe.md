# DNS resolvers — verified 5-resolver strict-SPKI-pinned DoT recipe

A durable, operator-facing recipe for deploying a **5-resolver strict-SPKI-pinned
DNS-over-TLS** configuration that succeeds at startup from the `europe-north1`
deploy region, and for confirming per-resolver health afterwards via the
`resolver_probe` observability record. It exists so operators do not rediscover
the `1.1.1.1`/`8.8.8.8` startup failure (root cause: the 5-second exchange
deadline exceeded from the GCP region).

The governing specification is the byte-canonical
[docs/alumina-proxy.md](alumina-proxy.md) (never edit it; this document only
restates and cites it). The `resolver_probe` record is authorized by the
`alumina-rbp` amendment section
[docs/alumina-proxy.md:807-843](alumina-proxy.md#hardening-post-window-per-resolver-probe-sweep--resolver_probe-verdict-log--user-authorized-amendment).

## Purpose

Alumina resolves allowlisted hostnames through the configured `resolver` array
using strict-SPKI-pinned DoT (`IP#fqdn#pin-sha256=<SPKI>`). Every configured
resolver is probed at startup within a fixed 90-second window
([spec :64](alumina-proxy.md)), each DNS exchange has a **5-second deadline**
([spec :82](alumina-proxy.md)), and the transport is a single DNS TCP
connection with one outstanding query ([spec :172](alumina-proxy.md)). A
resolver that cannot complete an exchange within that deadline fails startup
resolution for the names it serves, so resolver **order must reflect regional
reachability**, not just pin validity.

## The verified 5-resolver config

This `resolver` array is the verified configuration (pins verified live
2026-10-22; `9.9.9.9` primary per the SM-3 reorder, `gh-report-ops` commit
`fe743b4`):

```toml
resolver = [
  "9.9.9.9#dns.quad9.net#pin-sha256=i2kObfz0qIKCGNWt7MjBUeSrh0Dyjb0/zWINImZES+I",
  "1.1.1.1#cloudflare-dns.com#pin-sha256=ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew",
  "8.8.8.8#dns.google#pin-sha256=60uKZ6e4SYDbrLwHgVIDsbhvops9zUtkPbwHu7x6u1E",
  "208.67.222.222#dns.opendns.com#pin-sha256=oPU2uDzd0QMkEuxy5gJcJeRJgPe6Qe+6/sVuL2lGrNM",
  "94.140.14.14#dns.adguard.com#pin-sha256=WdoEPzdQVQmBmUM18RYjroe9T7pflZmN3TXiKP7fAmY",
]
```

All five entries are strict-SPKI-pinned DoT (`IP#fqdn#pin-sha256=…`), matching
the fixed resolver-set capacity of 5 ([spec :172](alumina-proxy.md)).

## Per-resolver pin facts (verified live 2026-10-22)

Pins are the base64 SHA-256 of the server's SPKI, captured with
`openssl s_client` (see [re-verifying pins](#re-verifying-pins-on-certificate-rotation)).

| # | Address | FQDN | SPKI pin | Issuer | Stability note |
| --- | --- | --- | --- | --- | --- |
| 0 | `9.9.9.9` | `dns.quad9.net` | `i2kObfz0qIKCGNWt7MjBUeSrh0Dyjb0/zWINImZES+I` | DigiCert | Stable ≥ 2026-02-21 |
| 1 | `1.1.1.1` | `cloudflare-dns.com` | `ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew` | SSL.com | Cloudflare rotates edge certs regularly — re-verify on rotation |
| 2 | `8.8.8.8` | `dns.google` | `60uKZ6e4SYDbrLwHgVIDsbhvops9zUtkPbwHu7x6u1E` | Google Trust Services WE2 | Stable |
| 3 | `208.67.222.222` | `dns.opendns.com` | `oPU2uDzd0QMkEuxy5gJcJeRJgPe6Qe+6/sVuL2lGrNM` | HydrantID/IdenTrust | Cisco OpenDNS DigiCert→IdenTrust transition had incidents Oct 2026 |
| 4 | `94.140.14.14` | `dns.adguard.com` | `WdoEPzdQVQmBmUM18RYjroe9T7pflZmN3TXiKP7fAmY` | ZeroSSL | Cert issued 2026-10-21 |

## Why `9.9.9.9` is primary

Deploy ground truth (`gh-report-ops` commit `cb949a7`): at startup `secs=15`,
three `1.1.1.1` exchanges plus three `8.8.8.8` exchanges each exceeded the
5-second exchange deadline ([spec :82](alumina-proxy.md)) from `europe-north1`;
`9.9.9.9` succeeded within the deadline. The pins were valid — they matched the
live SPKIs — so this was a **regional reachability** problem, not a pin problem.

The fix was to reorder so `9.9.9.9` is primary (`gh-report-ops` commit
`fe743b4`). `1.1.1.1` and `8.8.8.8` are retained as valid-pin backups that may
be regionally slow. Resolver order is a deployment decision: it should reflect
the measured reachability of the deploy region within the fixed 5-second
exchange deadline, not a global preference ranking.

## How to verify per-resolver health via `resolver_probe`

After the startup decision, the `alumina-rbp` amendment
([spec :807-843](alumina-proxy.md#hardening-post-window-per-resolver-probe-sweep--resolver_probe-verdict-log--user-authorized-amendment))
runs a one-time post-window probe sweep that tests every configured resolver the
startup window did not already exercise, then emits **one** `resolver_probe`
record. It is post-window observability only — it never extends the window,
delays the listener, or changes readiness.

The record carries one inline segment per resolver: index, address (with
FQDN/pin presence), verdict, and the failure reason when failed. Exact format
(from `src/log.rs`):

```
level=info kind=resolver_probe secs=11 resolver0="1.1.1.1" verdict0=ok resolver1="9.9.9.9" fqdn1="dns.quad9.net" verdict1=failed reason1="timeout" resolver2="8.8.8.8" fqdn2="dns.google" pin2=1 verdict2=not_probed
```

Verdict vocabulary:

| Verdict | Meaning |
| --- | --- |
| `ok` | The probe exchange succeeded; the resolver is healthy |
| `failed` | The probe exchange failed; the record carries a `reason` (e.g. `timeout`, `handshake`) |
| `not_probed` | The resolver was the active resolver exercised by the startup window, so the sweep skipped it |

To confirm health after a deploy, grep the startup log for the single
`kind=resolver_probe` record and check that every resolver is either `ok` or
`not_probed` (the startup-active resolver), with no `failed` verdicts:

```sh
# every resolver should be ok or not_probed; any failed carries its reason
grep 'kind=resolver_probe' <startup-log>
```

A `failed` verdict with `reason="timeout"` against a valid pin means the
resolver is not reachable within the 5-second exchange deadline from the deploy
region — reorder the array to promote a reachable resolver, exactly as the
`9.9.9.9` reorder did.

## Re-verifying pins on certificate rotation

Pins change when a resolver rotates its serving certificate. Re-verify a pin
before relying on it (strict pinning fails closed against a mismatched SPKI):

```sh
# capture the server's SPKI SHA-256 base64 pin
openssl s_client -connect <ip>:853 -servername <fqdn> -tls1_2 \
  </dev/null 2>/dev/null | grep -A1 'Server public key is'
```

The base64 value after `Server public key is` is the SPKI SHA-256 to place in
`pin-sha256=…`. Re-verify the pin for each resolver in the table above whenever
its issuer rotates certificates (Cloudflare edge certs rotate regularly;
OpenDNS's DigiCert→IdenTrust transition had incidents in Oct 2026).

## Fixed-profile note

This recipe changes **no** window or deadline: the 90-second startup window
([spec :64](alumina-proxy.md)), the 5-second DNS exchange deadline
([spec :82](alumina-proxy.md)), and the 1-connection/1-query transport
([spec :172](alumina-proxy.md)) are fixed profile rows and are unchanged. The
`resolver_probe` sweep is post-window observability only — it relocates the
single existing DNS connection sequentially and never opens a second one
([spec :807-843](alumina-proxy.md#hardening-post-window-per-resolver-probe-sweep--resolver_probe-verdict-log--user-authorized-amendment)).
