# Trust chain: design goal and current status

A complete cryptographic chain of trust is the design goal: the DNS root, or an
explicitly declared DNSSEC trust anchor, authenticates every supporting CNAME
and terminal A/AAAA RRset, with an authenticated negative proof where a name
legitimately has no address record; the resolver hop is itself authenticated
where a recursive or pinned-DoT resolver is used (a delegated validating
recursive supplies the DNSSEC verdict under the deployment's trusted-anchor
policy — an asserted AD bit alone does not prove a root anchor); an approved
CONNECT `name:port` may connect only to valid DNSSEC-derived addresses and its
initial SNI must match that approved name; and in the opaque client↔server TLS,
the client verifies the server's certificate and hostname, while the server
verifies the client certificate only under mutual TLS. DNSSEC and the WebPKI
form two composable trust hierarchies, not one certificate chain, and no DANE
deployment is required.

The goal is conditional and its boundaries are explicit. Delegated DNSSEC
assurance applies only under the qualified resolver policy and its trusted
external validation; without authenticated DNSSEC data, resolution is not
DNSSEC-secure. The selected strong profiles do not downgrade to an
unauthenticated path. SNI is a client-supplied consistency check, not
cryptographic proof. Legacy `resolver_trusted` retains bounded stale-serving;
strong profiles require current proof even when an address remains
stale-servable. The chain promises no latest-authoritative-data guarantee,
no exclusive ownership of an admitted endpoint, and no protection against abuse
riding inside that endpoint's own capabilities. It also requires a protected
deployment that keeps trust anchors, configuration, and time correct and
prevents bypass.

| Scope | Current status |
| --- | --- |
| Proxy policy binding | Implemented — allowlisted CONNECT `name:port`, validated DNS-derived address eligibility, and SNI matching the approved name (`docs/alumina-proxy.md:59,88,255`) |
| Resolver transport | Implemented — DNS over TCP only; strict-pinned DoT authenticates the resolver hop by SPKI/TLS-signature key possession (no CA chain needed), while an unpinned DoT entry validates against an empty root store and fails closed (`docs/alumina-proxy.md:107,113`) |
| DNS assurance | Implemented per allowlist entry — `dns_assurance` is mandatory (a missing key rejects the config, exit 78); `resolver_trusted` is the explicit legacy class, `resolver_authenticated` requires authenticated-origin proof, and `delegated_dnssec` additionally requires qualified origin and AD=1. Both strong profiles require all resolvers strict-pinned and the operator-declared `root_validating_no_stale` policy. Current proof is checked at startup readiness and every actual dial; A/AAAA assurance records are attempted at boot and material changes, including idle expiry. See the [governing assurance rules](alumina-proxy.md#hardening-per-entry-dns-assurance-and-qualified-admission). |
| Endpoint & deployment | Client- and deployment-owned — the proxy relays opaque TLS and never authenticates the upstream server; client verification of the upstream server certificate and hostname (with the server verifying a client certificate only when mutual TLS is configured), correct clocks and anchors, and bypass-resistant deployment are operator responsibilities (`docs/alumina-proxy.md:55,90,287`) |

None of the above claims that every deployment delivers the complete chain.
The proxy performs no local DNSSEC validation; its delegated claim depends on
the operator's root-validating, correct-time, no-expired-stale resolver policy,
not on AD alone. Plain DNS over TCP does not cryptographically authenticate the
resolver or DNS data. Endpoint certificate and hostname verification remain
client-owned, and authenticated resolver origin is not endpoint validation.
The [specification](alumina-proxy.md) is the sole governing behavior and is
byte-frozen by default, subject to scoped governance amendments. Assurance
notifications are bounded best-effort attempts, not delivery guarantees.
