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

The goal is conditional and its boundaries are explicit. It applies only to
signed DNS data, qualified configuration, and endpoints that perform the
corresponding checks — without authenticated DNSSEC data, resolution is not
DNSSEC-secure, and a proposed DNSSEC-strict profile would not downgrade to an
unauthenticated path. SNI is a client-supplied consistency check, not
cryptographic proof. The
chain promises no latest-authoritative-data guarantee (current cache admission
is bounded freshness and deliberate stale-serving — never authenticated
proof; upstream staleness is not independently established), no exclusive
ownership of an admitted endpoint, and no protection against abuse riding
inside an admitted endpoint's own capabilities. Completing
it also requires a protected deployment that keeps trust anchors,
configuration, and time correct and prevents bypass.

| Scope | Current status |
| --- | --- |
| Proxy policy binding | Implemented — allowlisted CONNECT `name:port`, validated DNS-derived address eligibility, and SNI matching the approved name (`docs/alumina-proxy.md:59,88,255`) |
| Resolver transport | Implemented — DNS over TCP only; strict-pinned DoT authenticates the resolver hop by SPKI/TLS-signature key possession (no CA chain needed), while an unpinned DoT entry validates against an empty root store and fails closed (`docs/alumina-proxy.md:107,113`) |
| DNSSEC assurance | Observation only, admission not implemented — existing A/AAAA queries now set the AD bit (RD set, CD clear, no DO/EDNS), and the raw response AD=0/1 flag is retained as an immutable per-reply observation only; cache admission still runs on freshness and bounded stale-serving, never on authenticated proof, and no authenticated-cache, admission, or log capability exists yet (`docs/alumina-proxy.md:116,119-120`) |
| Endpoint & deployment | Client- and deployment-owned — the proxy relays opaque TLS and never authenticates the upstream server; client verification of the upstream server certificate and hostname (with the server verifying a client certificate only when mutual TLS is configured), correct clocks and anchors, and bypass-resistant deployment are operator responsibilities (`docs/alumina-proxy.md:55,90,287`) |

None of the above is a claim that Alumina currently delivers the complete
chain: this goal is non-normative, and any move toward it is a governed future
amendment. The byte-frozen [alumina-proxy.md](alumina-proxy.md) remains the
sole authoritative statement of current behavior, and
[docs/architecture.html](architecture.html) remains the as-built
architecture reference — this section records only status against a stated
intent. Until such an amendment lands, plain-DNS-over-TCP is not cryptographic
authentication of the resolver or DNS data (`docs/alumina-proxy.md:113`), and
DNSSEC-strict admission is not yet implemented. The proposed DNSSEC-strict
profile, once adopted, would not downgrade to an unauthenticated path — a
stronger posture than today's narrower guarantee, already documented below,
that a DoT handshake or identity failure never downgrades to plain DNS and
that mixed plain/DoT resolver arrays are rejected at startup.
