# alox-f07 — Explicit CNAME bailiwick: self-default zone + declared suffix union (DRAFT)

**Status**: DRAFT — NOT authorized. This document records a proposed amendment to
`docs/alumina-proxy.md` (the byte-canonical governing specification) for review; it does not
amend the specification and confers no authority. Recording follows the established
alox7/alox8 amendment pattern (`#### SP-### — title` + "Resolution:" prose) and requires a
user-authorized amendment before any spec text changes.

**Date**: 2026-10-26
**Package / mission**: `f07-bailiwick-261026` / `f07-derivation-evidence` (epic `alumina-kjwox`)
**Scope**: CNAME bailiwick derivation (`:71`), configuration schema exactly-one-key (`:1052`),
threat-model note RT-005 (`:1335`), fixed-profile accounting note (`:452`).

## Problem

The current bailiwick rule derives the allowed CNAME target zones as "the deduplicated
parent-zone set derived from the allowlist" (`:71`). This implicit parent-zone derivation has
two defects that F-07 (public-suffix / shared-tenant gap) exposed:

1. **Public-suffix over-breadth**: for an allowlisted name under a public suffix (e.g.
   `sub.example.org` under `example.org`), the derived parent zone `example.org` is shared by
   every tenant on that public suffix; a CNAME into another tenant's zone under the same
   parent is admitted even though it is outside the operator's control.
2. **Implicit, non-declarative authority**: the operator cannot express "this name may CNAME
   into these additional zones" without also widening every sibling allowlisted name under the
   same parent.

## Resolution (proposed)

### SP-014 — Explicit CNAME bailiwick: self-default zone + declared suffix union

The implicit parent-zone derivation is replaced by an explicit two-part bailiwick:

- **Self-default zone**: each allowlisted name's own zone is itself — the allowlist name and
  its subdomains only, matched at label boundaries. A CNAME chain rooted at an allowlisted
  name may land on the name itself or any subdomain of it.
- **Declared suffix union**: an optional per-entry `cname_bailiwick` array of bare-name
  suffixes (`[allowed_fqdn."<fqdn>:<port>"].cname_bailiwick = ["<suffix>", ...]`) widens the
  bailiwick for that entry to the union of the self-default zone and every declared suffix,
  each matched at label boundaries. A declared suffix covers itself and its subdomains.

A followed CNAME link must land inside the entry's union (self-default zone or a declared
suffix) or the exchange fails with the distinct `BailiwickViolation` outcome, unchanged. The
union is per-entry: an entry with no declared suffixes is restricted to its self-default zone
only. Cross-allowlist coverage is preserved only to the extent another allowlisted name's zone
falls within the entry's own self-default or declared-suffix union.

Configuration validation: `cname_bailiwick` is optional; when present it is an array of
validated bare names — no port, no wildcard, no IP literal, at least two labels — and the
total declared suffixes across all entries is at most `ALLOWLIST_MAX` (32), else invalid
configuration (exit 78). This refines the cfgk exactly-one-key rule at `:1052`: an
`[allowed_fqdn."..."]` table now contains the mandatory `early_data` key and an optional
`cname_bailiwick` key; every other key remains invalid configuration (exit 78).

This **supersedes and refines RT-005** (`:1335`): the parent-zone granularity note is replaced
by the explicit self-default + declared-suffix model. The residual RT-005 acknowledged (a
parent-zone compromise pivots allowlist names inside that zone) is narrowed to the
operator-declared suffix union: the operator, not the derivation, now chooses the zone
granularity; a declared suffix is an explicit trust boundary, and the residual is bounded to
zones the operator declared. The `:71` bailiwick sentence is amended accordingly.

Implementation: `BailiwickZones` (`src/dns.rs`) holds the allowlist entries and the declared
suffixes in fixed `[DnsName; ALLOWLIST_MAX]` arrays (no heap), with a parallel `suffix_owner`
slot index so every suffix is attributed to the allowlist entry that declared it.
`covers_for(root, name)` accepts `name` only when it falls inside `root`'s own self-default
zone (the allowlist entry and its label-boundary subdomains) or inside one of that same
entry's declared suffixes, via the existing `soa_covers` label-boundary match — a neighbour
entry's zone never widens the bailiwick. `Config::cname_bailiwick()` returns the validated
per-entry suffix lists; `from_allowlist(allowlist, &suffix_lists)` builds the zones in
allowlist order. Allocation profile unchanged (fixed-slot storage, no post-boot heap).

### Fixed-profile accounting follow-up

The `BailiwickZones` change adds no heap, but the DNS named-buffer accounting figure at
`:452` (`BootInventory::named_fixed_buffer_bytes` ≈ 196 MiB lower bound) should be re-measured
once the amendment is authorized: re-audit `DNS_NAMED_BUFFER_BYTES` / `BootInventory` for the
fixed `[DnsName; ALLOWLIST_MAX]` zone storage. This is a follow-up for the authorized
revision, not part of this DRAFT's binding semantics.

## Verification evidence (executed, tree modified but UNCOMMITTED)

- RED (H-1 per-entry fix): 4 multi-entry tests added (`bailiwick_config_multi` helper +
  `rejects_cross_allowlist_cname_without_declared_suffix`,
  `accepts_cross_allowlist_cname_with_declared_suffix`,
  `rejects_cross_allowlist_sibling_without_declared_suffix`,
  `accepts_cross_allowlist_sibling_with_declared_suffix`); the two reject-without-declared
  tests failed for the right reason (got `Ok(Positive)` instead of `Err(BailiwickViolation)`);
  165 passed / 2 failed (exit 101). The two accept-with-suffix tests passed pre-fix (guards).
- GREEN (H-1 per-entry fix): `covers_for(&self, root, name)` with per-entry `suffix_owner`
  selection; `root_chain` call site and doc comment updated; the global-union-dependent
  `accepts_apex_allowlist_subdomain_target` repurposed to
  `rejects_apex_allowlist_subdomain_target_without_declared_suffix` (now asserts
  `Err(BailiwickViolation)`). INNER `cargo +1.99.0 test --lib dns::tests` → 167 passed /
  0 failed (exit 0); `--lib startup_dns::tests` → 69 passed / 0 failed (exit 0);
  `--lib cname_bailiwick_config_tests` → 12 passed / 0 failed (exit 0).
- MID (macOS host, `+1.99.0`, tree modified but UNCOMMITTED):
  - `RUST_MIN_STACK=16777216 cargo +1.99.0 test` → 772 lib + 28 + 5 + 8 + 1 integration, all
    green (exit 0).
  - `RUST_MIN_STACK=16777216 cargo +1.99.0 test --features alloc-witness --lib` → 797 passed /
    0 failed (exit 0).
  - `cargo +1.99.0 fmt --check` → clean (exit 0).
  - `cargo +1.99.0 clippy -p alumina --locked --all-targets -- -D warnings` → clean (exit 0).
- H-1 resolution (linus review bead `alumina-kjwox.5`): the first-cycle global-union
  implementation was rejected because it still admitted CNAMEs into another allowlist entry's
  zone. Resolved by per-entry selection: each suffix slot records its declaring allowlist
  index (`suffix_owner`), and `covers_for` consults only suffixes owned by the chain root's
  entry. Covered by the 4-test multi-entry battery and the repurposed apex test.
- Stack-layout note (debug build, macOS): `serve::tests::trailing_last_name_unresolved_is_counted`
  overflows the default 2 MiB test-thread stack with these changes (SIGABRT in
  `ResponseWorkspace::default()`, dns.rs:740 — the designed fixed-profile ~100 KiB response
  workspace). The test passes at committed HEAD with 2 MiB, needs 2–3 MiB with these changes
  (the fixed `[DnsName; ALLOWLIST_MAX]` zone storage adds ~16.9 KiB per `BailiwickZones`), and
  passes with `RUST_MIN_STACK=16777216`. `serve.rs` is unmodified; this is a debug-build
  stack-layout sensitivity, not a logic regression. The repo's own `scripts/verify.sh` does not
  set `RUST_MIN_STACK`; the `mid` selectors are Linux-only and fail closed off-Linux.
- Round 2 (F-07 same-bare-name multi-port consistency, mission `f07-round2-multiport-20261026`):
  - RED: 3 config tests added (`accepts_same_bare_name_different_ports_with_identical_bailiwick`,
    `rejects_same_bare_name_different_ports_with_divergent_bailiwick`,
    `rejects_same_bare_name_different_ports_with_divergent_bailiwick_reverse`); the two reject
    tests failed for the right reason (parse returned `Ok` instead of
    `Err(DivergentCnameBailiwick)`); `--lib cname_bailiwick_config_tests` → 13 passed / 2 failed
    (exit 101). dns.rs negative guard `declared_suffix_does_not_widen_non_declaring_root`
    (header 0x1405, `bar.github.io` → `edge.github.io` expects `Err(BailiwickViolation)`) added
    green (pins H-1 per-entry behavior); `--lib dns::tests` → 168 passed / 0 failed (exit 0).
  - GREEN: `build_allowlist` (src/config.rs) now rejects divergent `cname_bailiwick` on the same
    bare name across different ports (first-seen list comparison matching `position()`),
    `ConfigError::DivergentCnameBailiwick { name, reason }` (exit 78), and
    `bailiwick_config_multi` extended to `(entry, port, suffixes)` 3-tuples (all 4 call sites pass
    `"443"`). INNER `--lib cname_bailiwick_config_tests` → 15 passed / 0 failed (exit 0);
    `--lib dns::tests` → 168 passed / 0 failed (exit 0); `--lib startup_dns::tests` → 69 passed /
    0 failed (exit 0).
  - MID (macOS host, `+1.99.0`, tree modified but UNCOMMITTED):
    - `RUST_MIN_STACK=16777216 cargo +1.99.0 test` → 776 lib + 28 + 5 + 8 + 1 integration, all
      green (exit 0).
    - `RUST_MIN_STACK=16777216 cargo +1.99.0 test --features alloc-witness --lib` → 801 passed /
      0 failed (exit 0).
    - `cargo +1.99.0 fmt --check` → clean (exit 0).
    - `cargo +1.99.0 clippy -p alumina --locked --all-targets -- -D warnings` → clean (exit 0;
      `#[expect(clippy::too_many_lines)]` added to `ConfigError::fmt` for the new Display arm).
  - No runtime change to `covers_for`/`position`/`BailiwickZones` — the same-name consistency
    rule is enforced at config parse only (boot-time, no alloc-witness impact).

## MOLTKE verdict

VERDICT: TRUE POSITIVE (TP) — distinct from RT-005 (verdict bead `alumina-4nfeb`).

- **Distinction**: RT-005 is the accepted residual where compromise of a *legitimate* parent
  zone pivots allowlist names inside that zone; F-07 is the derivation picking a *never-
  appropriate* trust unit (e.g. a public-suffix / shared-tenant parent such as `example.org`
  for `sub.example.org`), admitting a CNAME into another tenant's zone under the same parent.
- **Gap closed by SP-014**: per-entry self-default + declared-suffix union — a name no longer
  inherits its public-suffix parent as bailiwick unless declared; multi-entry `suffix_owner`
  and the same-bare-name consistency rule (round 2) eliminate cross-entry widening and silent
  first-match collapse.
- **Fixed profile preserved**: alloc-witness 801 green; no PSL, no runtime discovery.
- **Compatibility**: sibling-under-derived-parent chains (e.g. `sub.example.org ->
  edge.example.org`) now require explicit `cname_bailiwick = ["<parent>"]`.
- **Recommendation**: adopt DRAFT SP-014 amendment (user decision).

## Open items before authorization

- [ ] User authorization of this amendment (the spec is byte-canonical and never edited
      without an authorized amendment).
- [ ] Re-measure DNS named-buffer accounting (`:452`) once authorized.
- [x] MOLTKE final TP/FP verdict on the F-07 gap closure — TRUE POSITIVE (TP), distinct from RT-005, gap closed by SP-014 per-entry design (verdict bead `alumina-4nfeb`).
