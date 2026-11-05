use super::*;

use crate::config::{Config, parse_config_document};

use crate::dns::cache::Cache;

use crate::dns::schedule::{PerTypeTransition, Schedules};

use std::fmt::Write as _;

fn config() -> Config {
    parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n[allowed_fqdn.\"other.test:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n",
        )
        .expect("valid config")
}

fn fqdn(name: &str) -> Fqdn {
    config()
        .allowlist()
        .iter()
        .find(|f| f.as_str() == name)
        .expect("allowlisted")
        .clone()
}

fn header(tid: u16, qr_flag: bool, rcode: u8, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut m = vec![0u8; 12];
    m[0] = (tid >> 8) as u8;
    m[1] = u8::try_from(tid & 0xff).expect("dns header field low byte");
    let mut flags = u16::from(rcode);
    if qr_flag {
        flags |= 0x8000;
    }
    m[2] = (flags >> 8) as u8;
    m[3] = u8::try_from(flags & 0xff).expect("dns header field low byte");
    m[4] = (qd >> 8) as u8;
    m[5] = u8::try_from(qd & 0xff).expect("dns header field low byte");
    m[6] = (an >> 8) as u8;
    m[7] = u8::try_from(an & 0xff).expect("dns header field low byte");
    m[8] = (ns >> 8) as u8;
    m[9] = u8::try_from(ns & 0xff).expect("dns header field low byte");
    m[10] = (ar >> 8) as u8;
    m[11] = u8::try_from(ar & 0xff).expect("dns header field low byte");
    m
}

fn qname_bytes(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).expect("dns label at most 63 bytes"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn single_label_qname(label: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(u8::try_from(label.len()).expect("dns label at most 63 bytes"));
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out
}

fn a_record(owner: &str, octets: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut m = qname_bytes(owner);
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(&4u16.to_be_bytes());
    m.extend_from_slice(&octets);
    m
}

fn aaaa_record(owner: &str, octets: [u8; 16], ttl: u32) -> Vec<u8> {
    let mut m = qname_bytes(owner);
    m.extend_from_slice(&28u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(&16u16.to_be_bytes());
    m.extend_from_slice(&octets);
    m
}

fn cname_record(owner: &str, target: &str, ttl: u32) -> Vec<u8> {
    let mut m = qname_bytes(owner);
    m.extend_from_slice(&5u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&ttl.to_be_bytes());
    let target_bytes = qname_bytes(target);
    m.extend_from_slice(
        &u16::try_from(target_bytes.len())
            .expect("qname wire length fits u16")
            .to_be_bytes(),
    );
    m.extend_from_slice(&target_bytes);
    m
}

fn soa_with_owner(owner: &[u8], ttl: u32, minimum: u32) -> Vec<u8> {
    let mname = qname_bytes("ns1.example.org");
    let rname = qname_bytes("hostmaster.example.org");
    let rdata_len = mname.len() + rname.len() + 20;
    let mut m = owner.to_vec();
    m.extend_from_slice(&6u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(
        &u16::try_from(rdata_len)
            .expect("soa rdata fits u16")
            .to_be_bytes(),
    );
    m.extend_from_slice(&mname);
    m.extend_from_slice(&rname);
    let mut fields = Vec::new();
    for v in [1u32, 3600, 600, 86400, minimum] {
        fields.extend_from_slice(&v.to_be_bytes());
    }
    m.extend_from_slice(&fields);
    m
}

fn soa_record(owner: &str, ttl: u32, minimum: u32) -> Vec<u8> {
    soa_with_owner(&qname_bytes(owner), ttl, minimum)
}

fn root_soa_record(ttl: u32, minimum: u32) -> Vec<u8> {
    soa_with_owner(&[0u8], ttl, minimum)
}

fn direct_a(name: &str, tid: u16, octets: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut m = header(tid, true, 0, 1, 1, 0, 0);
    m.extend_from_slice(&qname_bytes(name));
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&a_record(name, octets, ttl));
    m
}

fn raw_record(owner: &str, ty: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut m = qname_bytes(owner);
    m.extend_from_slice(&ty.to_be_bytes());
    m.extend_from_slice(&class.to_be_bytes());
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("rdata length fits u16")
            .to_be_bytes(),
    );
    m.extend_from_slice(rdata);
    m
}

fn parse_response_ws(
    name: &str,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> Result<Outcome, DnsError> {
    let mut ws = ResponseWorkspace::default();
    let zones = BailiwickZones::from_allowlist(config().allowlist(), config().cname_bailiwick())
        .expect("validated config keeps suffix count within ALLOWLIST_MAX");
    parse_response(&mut ws, &zones, &fqdn(name), family, tid, msg)
}

/// A config with exactly one allowlist entry plus optional declared
/// `cname_bailiwick` suffixes, for F-07 bailiwick-derivation tests that
/// must not share the default `config()` allowlist.
fn bailiwick_config(entry: &str, suffixes: &[&str]) -> Config {
    let mut doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"{entry}:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
    );
    if !suffixes.is_empty() {
        let list = suffixes
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(doc, "cname_bailiwick = [{list}]").expect("write into String");
    }
    parse_config_document(&doc).expect("valid config")
}

/// A config with multiple allowlist entries, each with an explicit port and
/// optional declared `cname_bailiwick` suffixes, for F-07 per-entry
/// bailiwick tests.
fn bailiwick_config_multi(entries: &[(&str, &str, &[&str])]) -> Config {
    let mut doc = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n"
            .to_string();
    for (entry, port, suffixes) in entries {
        writeln!(
                doc,
                "[allowed_fqdn.\"{entry}:{port}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}"
            )
            .expect("write into String");
        if !suffixes.is_empty() {
            let list = suffixes
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(doc, "cname_bailiwick = [{list}]").expect("write into String");
        }
    }
    parse_config_document(&doc).expect("valid config")
}

fn fqdn_in(cfg: &Config, name: &str) -> Fqdn {
    cfg.allowlist()
        .iter()
        .find(|f| f.as_str() == name)
        .expect("allowlisted")
        .clone()
}

fn parse_with_zones(
    cfg: &Config,
    name: &str,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> Result<Outcome, DnsError> {
    let mut ws = ResponseWorkspace::default();
    let zones = BailiwickZones::from_allowlist(cfg.allowlist(), cfg.cname_bailiwick())
        .expect("validated config keeps suffix count within ALLOWLIST_MAX");
    parse_response(&mut ws, &zones, &fqdn_in(cfg, name), family, tid, msg)
}

fn parse_with_flag(
    name: &str,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> (Result<Outcome, DnsError>, bool) {
    let mut ws = ResponseWorkspace::default();
    let zones = BailiwickZones::from_allowlist(config().allowlist(), config().cname_bailiwick())
        .expect("validated config keeps suffix count within ALLOWLIST_MAX");
    let outcome = parse_response(&mut ws, &zones, &fqdn(name), family, tid, msg);
    (outcome, ws.extreme_ttl())
}

fn parse_response_flagged(
    ws: &mut ResponseWorkspace,
    name: &str,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> Result<Outcome, DnsError> {
    let zones = BailiwickZones::from_allowlist(config().allowlist(), config().cname_bailiwick())
        .expect("validated config keeps suffix count within ALLOWLIST_MAX");
    parse_response(ws, &zones, &fqdn(name), family, tid, msg)
}

fn parse_reply_into(
    ws: &mut ResponseWorkspace,
    name: &str,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> Result<ParsedReply, DnsError> {
    let zones = BailiwickZones::from_allowlist(config().allowlist(), config().cname_bailiwick())
        .expect("validated config keeps suffix count within ALLOWLIST_MAX");
    ParsedReply::parse_reply(ws, &zones, &fqdn(name), family, tid, msg)
}

fn positive_freshness_deadline(outcome: &Outcome, receipt: u64) -> (u64, u64) {
    let mut cache = Cache::new(2).expect("cache");
    let mut schedules = Schedules::new(2).expect("schedules");
    let index = cache.name_index(0).expect("index");
    let generation = cache.entry(index, Family::A).expect("entry").generation();
    apply_outcome(
        &mut cache,
        &mut schedules,
        0,
        generation,
        receipt,
        receipt,
        outcome,
    )
    .expect("apply");
    let entry = cache.entry(index, Family::A).expect("entry");
    let (freshness, retirement) = entry.deadlines();
    (
        freshness.expect("freshness deadline"),
        retirement.expect("retirement deadline"),
    )
}

mod positive {
    use super::*;

    #[test]
    fn parses_direct_a_positive() {
        let msg = direct_a("sub.example.org", 0x1234, [93, 184, 216, 34], 120);
        let out = parse_response_ws("sub.example.org", Family::A, 0x1234, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::Positive {
                family: Family::A,
                bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(
                    93, 184, 216, 34
                ))])
                .expect("bindings"),
                ttl: 120,
            }
        );
    }

    #[test]
    fn parses_direct_a_with_compressed_owner() {
        let mut msg = header(0x1234, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[140, 82, 121, 5]);
        let out = parse_response_ws("sub.example.org", Family::A, 0x1234, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(140, 82, 121, 5))]
                );
                assert_eq!(ttl, 60);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn cname_chain_positive() {
        let mut msg = header(9, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&a_record("a.sub.example.org", [203, 0, 113, 7], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 9, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40, "earliest supporting TTL across chain");
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }
}

mod validation {
    use super::*;

    #[test]
    fn rejects_tid_mismatch() {
        let msg = direct_a("sub.example.org", 0x1234, [1, 1, 1, 1], 60);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0xbeef, &msg),
            Err(DnsError::BadTid {
                expected: 0xbeef,
                got: 0x1234
            })
        );
    }

    #[test]
    fn rejects_question_mismatch() {
        let mut msg = header(7, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("other.test"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("other.test", [1, 2, 3, 4], 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 7, &msg),
            Err(DnsError::QuestionMismatch)
        );
    }

    #[test]
    fn rejects_truncated_flag() {
        let mut msg = header(32, true, 0, 1, 0, 0, 0);
        msg[2] |= 0x02; // flags bit 9 (0x0200): TC
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 32, &msg),
            Err(DnsError::Truncated)
        );
    }

    #[test]
    fn rejects_bad_opcode() {
        let mut msg = header(33, true, 0, 1, 0, 0, 0);
        msg[2] |= 0x08; // opcode 1 (0x0800)
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 33, &msg),
            Err(DnsError::BadOpcode { got: 1 })
        );
    }

    #[test]
    fn rejects_question_count_zero() {
        let msg = header(34, true, 0, 0, 0, 0, 0);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 34, &msg),
            Err(DnsError::QuestionCount { got: 0 })
        );
    }

    #[test]
    fn rejects_question_count_two() {
        let msg = header(35, true, 0, 2, 0, 0, 0);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 35, &msg),
            Err(DnsError::QuestionCount { got: 2 })
        );
    }

    #[test]
    fn rejects_bad_class_in_answer() {
        let mut msg = header(36, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&raw_record("sub.example.org", 1, 2, 60, &[1, 2, 3, 4]));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 36, &msg),
            Err(DnsError::BadClass { got: 2 })
        );
    }
}

mod bailiwick_cname {
    use super::*;

    #[test]
    fn rejects_cname_loop() {
        let mut msg = header(10, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 100));
        msg.extend_from_slice(&cname_record("a.sub.example.org", "sub.example.org", 100));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 10, &msg),
            Err(DnsError::CnameLoop)
        );
    }

    #[test]
    fn rejects_cross_zone_cname_target() {
        let mut msg = header(0x1260, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 200));
        msg.extend_from_slice(&a_record("edge.test", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1260, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn rejects_chain_with_foreign_zone_link() {
        let mut msg = header(0x1261, true, 0, 1, 3, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&cname_record("a.sub.example.org", "evil.test", 200));
        msg.extend_from_slice(&a_record("evil.test", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1261, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn accepts_same_zone_cname() {
        let mut msg = header(0x1262, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&a_record("a.sub.example.org", [203, 0, 113, 7], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1262, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn rejects_apex_allowlist_subdomain_target_without_declared_suffix() {
        let mut msg = header(0x1263, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "deep.other.test", 200));
        msg.extend_from_slice(&a_record("deep.other.test", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1263, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn rejects_public_suffix_cname_target() {
        let cfg = bailiwick_config("example.co.uk", &[]);
        let mut msg = header(0x1302, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("example.co.uk"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("example.co.uk", "cdn.co.uk", 200));
        msg.extend_from_slice(&a_record("cdn.co.uk", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_with_zones(&cfg, "example.co.uk", Family::A, 0x1302, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn rejects_shared_tenant_cname_target() {
        let cfg = bailiwick_config("foo.github.io", &[]);
        let mut msg = header(0x1303, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("foo.github.io"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("foo.github.io", "bar.github.io", 200));
        msg.extend_from_slice(&a_record("bar.github.io", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_with_zones(&cfg, "foo.github.io", Family::A, 0x1303, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn accepts_self_zone_subdomain_cname_target() {
        let cfg = bailiwick_config("sub.example.org", &[]);
        let mut msg = header(0x1304, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&a_record("a.sub.example.org", [203, 0, 113, 7], 40));
        let out =
            parse_with_zones(&cfg, "sub.example.org", Family::A, 0x1304, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn rejects_sibling_zone_cname_target() {
        let cfg = bailiwick_config("sub.example.org", &[]);
        let mut msg = header(0x1305, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.example.org", 200));
        msg.extend_from_slice(&a_record("edge.example.org", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_with_zones(&cfg, "sub.example.org", Family::A, 0x1305, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn accepts_declared_suffix_cname_target() {
        let cfg = bailiwick_config("sub.example.org", &["example.org"]);
        let mut msg = header(0x1306, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.example.org", 200));
        msg.extend_from_slice(&a_record("edge.example.org", [203, 0, 113, 7], 40));
        let out =
            parse_with_zones(&cfg, "sub.example.org", Family::A, 0x1306, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn covers_label_boundary_union() {
        let cfg = bailiwick_config("sub.example.org", &["example.org"]);
        let zones = BailiwickZones::from_allowlist(cfg.allowlist(), cfg.cname_bailiwick())
            .expect("validated config keeps suffix count within ALLOWLIST_MAX");
        let root = DnsName::from_exact(b"sub.example.org");
        for covered in ["edge.example.org", "a.example.org", "example.org"] {
            assert!(
                zones.covers_for(root.as_slice(), covered.as_bytes()),
                "{covered} must be covered by the self-zone or declared suffix"
            );
        }
        for uncovered in ["badexample.org", "notexample.org"] {
            assert!(
                !zones.covers_for(root.as_slice(), uncovered.as_bytes()),
                "{uncovered} must not be covered across a label boundary"
            );
        }
    }

    /// Drives the fixed suffix-slot write past `ALLOWLIST_MAX` with input that
    /// bypasses config validation (a hand-built parallel suffix list), proving
    /// the write is fail-stop and typed rather than an out-of-bounds panic.
    #[test]
    fn from_allowlist_fails_stop_on_suffix_slot_overflow() {
        let mut doc = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n"
            .to_string();
        for i in 0..ALLOWLIST_MAX {
            writeln!(
                doc,
                "[allowed_fqdn.\"host{i}.example.com:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}"
            )
            .expect("write into String");
        }
        let cfg = parse_config_document(&doc).expect("valid config");
        let suffixes: Vec<Vec<String>> = (0..ALLOWLIST_MAX)
            .map(|i| vec![format!("s{i}a.example.net"), format!("s{i}b.example.net")])
            .collect();
        let err = BailiwickZones::from_allowlist(cfg.allowlist(), &suffixes)
            .expect_err("suffix slot overflow must be a typed error");
        assert!(
            matches!(
                err,
                DnsError::BailiwickSuffixOverflow { got, max }
                    if got == ALLOWLIST_MAX + 1 && max == ALLOWLIST_MAX
            ),
            "expected BailiwickSuffixOverflow {{ got: {}, max: {} }}, got {err:?}",
            ALLOWLIST_MAX + 1,
            ALLOWLIST_MAX
        );
    }

    #[test]
    fn rejects_cross_allowlist_cname_without_declared_suffix() {
        let cfg =
            bailiwick_config_multi(&[("foo.github.io", "443", &[]), ("bar.github.io", "443", &[])]);
        let mut msg = header(0x1401, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("foo.github.io"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("foo.github.io", "bar.github.io", 200));
        msg.extend_from_slice(&a_record("bar.github.io", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_with_zones(&cfg, "foo.github.io", Family::A, 0x1401, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn accepts_cross_allowlist_cname_with_declared_suffix() {
        let cfg = bailiwick_config_multi(&[
            ("foo.github.io", "443", &["bar.github.io"]),
            ("bar.github.io", "443", &[]),
        ]);
        let mut msg = header(0x1402, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("foo.github.io"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("foo.github.io", "bar.github.io", 200));
        msg.extend_from_slice(&a_record("bar.github.io", [203, 0, 113, 7], 40));
        let out = parse_with_zones(&cfg, "foo.github.io", Family::A, 0x1402, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn rejects_cross_allowlist_sibling_without_declared_suffix() {
        let cfg = bailiwick_config_multi(&[
            ("sub.example.org", "443", &[]),
            ("edge.example.org", "443", &[]),
        ]);
        let mut msg = header(0x1403, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.example.org", 200));
        msg.extend_from_slice(&a_record("edge.example.org", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_with_zones(&cfg, "sub.example.org", Family::A, 0x1403, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn accepts_cross_allowlist_sibling_with_declared_suffix() {
        let cfg = bailiwick_config_multi(&[
            ("sub.example.org", "443", &["example.org"]),
            ("edge.example.org", "443", &[]),
        ]);
        let mut msg = header(0x1404, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.example.org", 200));
        msg.extend_from_slice(&a_record("edge.example.org", [203, 0, 113, 7], 40));
        let out =
            parse_with_zones(&cfg, "sub.example.org", Family::A, 0x1404, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn declared_suffix_does_not_widen_non_declaring_root() {
        let cfg = bailiwick_config_multi(&[
            ("foo.github.io", "443", &["edge.github.io"]),
            ("bar.github.io", "443", &[]),
        ]);
        let mut msg = header(0x1405, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("bar.github.io"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("bar.github.io", "edge.github.io", 200));
        msg.extend_from_slice(&a_record("edge.github.io", [203, 0, 113, 7], 40));
        assert_eq!(
            parse_with_zones(&cfg, "bar.github.io", Family::A, 0x1405, &msg),
            Err(DnsError::BailiwickViolation)
        );
    }

    #[test]
    fn cname_loop_within_self_zone_still_rejected() {
        let cfg = bailiwick_config("sub.example.org", &[]);
        let mut msg = header(0x1307, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 100));
        msg.extend_from_slice(&cname_record("a.sub.example.org", "sub.example.org", 100));
        assert_eq!(
            parse_with_zones(&cfg, "sub.example.org", Family::A, 0x1307, &msg),
            Err(DnsError::CnameLoop)
        );
    }
}

mod ttl_flags {
    use super::*;

    #[test]
    fn extreme_ttl_accepted_positive_flags() {
        let msg = direct_a("sub.example.org", 0x1300, [1, 2, 3, 4], 400_000);
        let (outcome, flag) = parse_with_flag("sub.example.org", Family::A, 0x1300, &msg);
        assert!(
            outcome.is_ok(),
            "a high-TTL positive still validates: {outcome:?}"
        );
        assert!(flag, "a TTL above the extreme threshold flags the exchange");
    }

    #[test]
    fn wrong_family_high_ttl_flags() {
        let mut msg = header(0x1301, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&28u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 400_000));
        let (_, flag) = parse_with_flag("sub.example.org", Family::Aaaa, 0x1301, &msg);
        assert!(
            flag,
            "a wrong-family high-TTL record is still inspected and flags the exchange"
        );
    }

    #[test]
    fn normal_ttl_does_not_flag() {
        let msg = direct_a("sub.example.org", 0x1302, [1, 2, 3, 4], 120);
        let (outcome, flag) = parse_with_flag("sub.example.org", Family::A, 0x1302, &msg);
        assert!(outcome.is_ok());
        assert!(!flag, "a bounded TTL never flags the exchange");
    }

    #[test]
    fn extreme_ttl_at_threshold_does_not_flag() {
        let msg = direct_a(
            "sub.example.org",
            0x1303,
            [1, 2, 3, 4],
            EXTREME_TTL_THRESHOLD,
        );
        let (_, flag) = parse_with_flag("sub.example.org", Family::A, 0x1303, &msg);
        assert!(!flag, "exactly the threshold is not extreme");
    }
}

mod workspace {
    use super::*;

    #[test]
    fn wire_parser_reused_workspace_extreme_flag_survives_late_error_then_clears() {
        let mut ws = ResponseWorkspace::default();
        let high = direct_a("sub.example.org", 0x1320, [1, 2, 3, 4], 400_000);
        assert!(
            parse_response_flagged(&mut ws, "sub.example.org", Family::A, 0x1320, &high).is_ok()
        );
        assert!(ws.extreme_ttl(), "a high-TTL success flags on first use");
        let mut malformed = header(0x1321, true, 0, 1, 2, 0, 0);
        malformed.extend_from_slice(&qname_bytes("sub.example.org"));
        malformed.extend_from_slice(&1u16.to_be_bytes());
        malformed.extend_from_slice(&1u16.to_be_bytes());
        malformed.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 400_000));
        let mut truncated = qname_bytes("sub.example.org");
        truncated.extend_from_slice(&1u16.to_be_bytes());
        truncated.extend_from_slice(&1u16.to_be_bytes());
        truncated.extend_from_slice(&60u32.to_be_bytes());
        truncated.extend_from_slice(&4u16.to_be_bytes());
        truncated.extend_from_slice(&[9, 9]);
        malformed.extend_from_slice(&truncated);
        assert!(
            parse_response_flagged(&mut ws, "sub.example.org", Family::A, 0x1321, &malformed)
                .is_err()
        );
        assert!(
            ws.extreme_ttl(),
            "an error after a high-TTL record leaves that parse's flag set"
        );
        let normal = direct_a("sub.example.org", 0x1322, [9, 9, 9, 9], 120);
        assert!(
            parse_response_flagged(&mut ws, "sub.example.org", Family::A, 0x1322, &normal).is_ok()
        );
        assert!(
            !ws.extreme_ttl(),
            "the flag describes the most recent parse only"
        );
    }

    #[test]
    fn wire_parser_oversized_reply_error_retains_prior_extreme_flag() {
        let mut ws = ResponseWorkspace::default();
        let high = direct_a("sub.example.org", 0x1323, [1, 2, 3, 4], 400_000);
        assert!(
            parse_response_flagged(&mut ws, "sub.example.org", Family::A, 0x1323, &high).is_ok()
        );
        assert!(ws.extreme_ttl());
        let oversized = vec![0u8; DNS_MSG_LIMIT + 1];
        assert!(matches!(
            parse_response_flagged(&mut ws, "sub.example.org", Family::A, 0x1324, &oversized),
            Err(DnsError::MessageTooLong)
        ));
        assert!(
            ws.extreme_ttl(),
            "an overlong parse errors before the per-parse flag reset and keeps the prior flag"
        );
    }

    #[test]
    fn parse_reply_binds_its_own_flag_and_payload_across_workspace_reuse() {
        let mut ws = ResponseWorkspace::default();
        let high = direct_a("sub.example.org", 0x1330, [1, 2, 3, 4], 400_000);
        let high_reply = parse_reply_into(&mut ws, "sub.example.org", Family::A, 0x1330, &high)
            .expect("high reply");
        assert!(high_reply.extreme_ttl());
        let normal = direct_a("sub.example.org", 0x1331, [9, 9, 9, 9], 120);
        let normal_reply = parse_reply_into(&mut ws, "sub.example.org", Family::A, 0x1331, &normal)
            .expect("normal reply");
        assert!(!normal_reply.extreme_ttl());
        assert!(
            high_reply.extreme_ttl(),
            "an owned reply keeps its own parse's flag after the workspace is reused"
        );
        match (&high_reply.outcome, &normal_reply.outcome) {
            (
                Outcome::Positive {
                    family: hf,
                    bindings: hb,
                    ttl: ht,
                },
                Outcome::Positive {
                    family: nf,
                    bindings: nb,
                    ttl: nt,
                },
            ) => {
                assert_eq!(*hf, Family::A);
                assert_eq!(*ht, 400_000);
                assert_eq!(hb.as_slice(), &[NumericAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
                assert_eq!(*nf, Family::A);
                assert_eq!(*nt, 120);
                assert_eq!(nb.as_slice(), &[NumericAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
            }
            other => panic!("expected positives, got {other:?}"),
        }
    }

    #[test]
    fn parse_reply_err_carries_no_success_value_and_retains_the_flag() {
        let mut ws = ResponseWorkspace::default();
        let high = direct_a("sub.example.org", 0x1340, [1, 2, 3, 4], 400_000);
        let high_reply = parse_reply_into(&mut ws, "sub.example.org", Family::A, 0x1340, &high)
            .expect("high reply");
        assert!(high_reply.extreme_ttl());
        let oversized = vec![0u8; DNS_MSG_LIMIT + 1];
        assert!(matches!(
            parse_reply_into(&mut ws, "sub.example.org", Family::A, 0x1341, &oversized),
            Err(DnsError::MessageTooLong)
        ));
        assert!(
            ws.extreme_ttl(),
            "an overlong parse error is pre-reset and can construct no reply value"
        );
        assert!(high_reply.extreme_ttl());
    }

    #[test]
    fn observe_carries_kind_and_extreme_from_the_same_wire_reply() {
        let mut ws = ResponseWorkspace::default();
        let high = direct_a("sub.example.org", 0x1350, [1, 2, 3, 4], 400_000);
        let reply = parse_reply_into(&mut ws, "sub.example.org", Family::A, 0x1350, &high)
            .expect("high reply");
        let observed = reply.observe();
        let (kind, extreme) = observed.probe_facts();
        assert_eq!(
            kind,
            classify_published(&reply.outcome),
            "observe classifies the same reply the classifier does"
        );
        assert_eq!(extreme, reply.extreme_ttl());
        assert_eq!(kind, PublishedKind::ResolvedPositive);
        assert!(
            extreme,
            "the observed view carries the extreme flag from its reply"
        );
    }

    #[test]
    fn parsed_reply_layout_is_bounded_by_the_outcome_plus_alignment() {
        println!(
            "parsed_reply_layout size_reply={} align_reply={} size_outcome={} align_outcome={} size_observed={} align_observed={}",
            std::mem::size_of::<ParsedReply>(),
            std::mem::align_of::<ParsedReply>(),
            std::mem::size_of::<Outcome>(),
            std::mem::align_of::<Outcome>(),
            std::mem::size_of::<ObservedReply<'_>>(),
            std::mem::align_of::<ObservedReply<'_>>(),
        );
        assert!(
            std::mem::size_of::<ParsedReply>()
                <= std::mem::size_of::<Outcome>() + std::mem::align_of::<Outcome>(),
            "the owned reply must stay within one outcome plus one alignment unit"
        );
        assert!(
            std::mem::size_of::<ObservedReply<'_>>() <= 16,
            "the borrowed observed view stays within the two-pointer budget: {} bytes",
            std::mem::size_of::<ObservedReply<'_>>()
        );
    }
}

mod negative_soa {
    use super::*;

    #[test]
    fn parses_nxdomain_with_soa() {
        let mut msg = header(11, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 11, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NxDomain {
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn parses_nodata_with_soa() {
        let mut msg = header(12, true, 0, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 12, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NoData {
                family: Family::A,
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn soa_covers_root_owner_covers_every_terminal() {
        assert!(soa_covers(b"sub.example.org", b""));
        assert!(soa_covers(b"example.org", b""));
        assert!(soa_covers(b"", b""));
    }

    #[test]
    fn soa_covers_keeps_equal_owner_and_boundary_suffix() {
        assert!(soa_covers(b"example.org", b"example.org"));
        assert!(soa_covers(b"sub.example.org", b"example.org"));
        assert!(!soa_covers(b"sub.example.org", b"other.example.net"));
        assert!(!soa_covers(b"sub.example.org", b"ample.org"));
    }

    #[test]
    fn nodata_with_root_soa_covers_terminal() {
        let mut msg = header(0x1401, true, 0, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&root_soa_record(300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1401, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NoData {
                family: Family::A,
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn nodata_through_cname_with_root_soa_covers_terminal() {
        let mut msg = header(0x1402, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&root_soa_record(300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1402, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NoData {
                family: Family::A,
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn nxdomain_with_root_soa_schedules_negative() {
        let mut msg = header(0x1403, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&root_soa_record(300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1403, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NxDomain {
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn empty_noerror_without_soa_is_not_nodata() {
        let mut msg = header(13, true, 0, 1, 0, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 13, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }
}

mod authority_soa {
    use super::*;

    #[test]
    fn rejects_non_covering_soa() {
        let mut msg = header(15, true, 0, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("other.example.net", 300, 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 15, &msg),
            Err(DnsError::NonCoveringSoa)
        );
    }

    #[test]
    fn positive_accepts_non_covering_authority_soa() {
        let mut msg = header(0x1248, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&soa_record("other.example.net", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1248, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                assert_eq!(ttl, 120);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn nodata_requires_authority_not_answer_soa() {
        let mut msg = header(26, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 26, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn nxdomain_ignores_answer_soa_for_scheduling() {
        let mut msg = header(27, true, 3, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 27, &msg).expect("parse");
        assert_eq!(out, Outcome::NxDomain { soa: None });
    }

    #[test]
    fn positive_ignores_unrelated_answer_soa() {
        let mut msg = header(28, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 28, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                assert_eq!(ttl, 120);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }
}

mod policy_rejects {
    use super::*;

    #[test]
    fn rejects_servfail_rcode() {
        let mut msg = header(14, true, 2, 1, 0, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 14, &msg),
            Err(DnsError::BadRcode { code: 2 })
        );
    }

    #[test]
    fn rejects_second_soa() {
        let mut msg = header(42, true, 0, 1, 0, 2, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 42, &msg),
            Err(DnsError::SoaCount { got: 2 })
        );
    }

    #[test]
    fn rejects_dname_in_answer() {
        let mut msg = header(43, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&raw_record("sub.example.org", 39, 1, 60, &[]));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 43, &msg),
            Err(DnsError::DnameUnsupported)
        );
    }

    #[test]
    fn rejects_formerr_notimp_refused_rcodes() {
        for code in [1u8, 4, 5] {
            let mut msg = header(u16::from(code), true, code, 1, 0, 0, 0);
            msg.extend_from_slice(&qname_bytes("sub.example.org"));
            msg.extend_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes());
            assert_eq!(
                parse_response_ws("sub.example.org", Family::A, u16::from(code), &msg),
                Err(DnsError::BadRcode { code })
            );
        }
    }
}

mod malformed_rdata {
    use super::*;

    #[test]
    fn rejects_trailing_bytes() {
        let mut msg = direct_a("sub.example.org", 16, [1, 1, 1, 1], 60);
        msg.push(0);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 16, &msg),
            Err(DnsError::TrailingBytes)
        );
    }

    #[test]
    fn rejects_bad_rdata_length() {
        let mut msg = header(17, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut rec = qname_bytes("sub.example.org");
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&60u32.to_be_bytes());
        rec.extend_from_slice(&3u16.to_be_bytes());
        rec.extend_from_slice(&[1, 2, 3]);
        msg.extend_from_slice(&rec);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 17, &msg),
            Err(DnsError::BadRdataLength {
                ty: 1,
                got: 3,
                expected: 4
            })
        );
    }

    #[test]
    fn rejects_malformed_a_rdlen_in_authority() {
        let mut msg = header(0x1249, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&raw_record("example.org", 1, 1, 60, &[1, 2, 3]));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1249, &msg),
            Err(DnsError::BadRdataLength {
                ty: 1,
                got: 3,
                expected: 4
            })
        );
    }

    #[test]
    fn rejects_malformed_aaaa_rdlen_in_additional() {
        let mut msg = header(0x124a, true, 0, 1, 1, 0, 1);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&raw_record("example.org", 28, 1, 0, &[1u8; 4]));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x124a, &msg),
            Err(DnsError::BadRdataLength {
                ty: 28,
                got: 4,
                expected: 16
            })
        );
    }

    #[test]
    fn accepts_opt_record_in_additional() {
        let mut msg = header(0x124b, true, 0, 1, 1, 0, 1);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&raw_record("example.org", 41, 1, 0, &[0u8; 11]));
        let out = parse_response_ws("sub.example.org", Family::A, 0x124b, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn accepts_unknown_type_in_authority() {
        let mut msg = header(0x124c, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&raw_record("example.org", 99, 1, 60, &[10, 11, 12, 13]));
        let out = parse_response_ws("sub.example.org", Family::A, 0x124c, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn rejects_soa_with_truncated_tail() {
        // W1-L1a-F2: the fixed 20-byte SOA tail (serial, refresh, retry,
        // expire, minimum) must follow the two names exactly; a truncated
        // tail is rejected as MalformedSoa rather than misread.
        let mut rdata = qname_bytes("ns1.example.org");
        rdata.extend_from_slice(&qname_bytes("hostmaster.example.org"));
        rdata.extend_from_slice(&[0u8; 19]);
        let mut msg = header(0x1254, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&raw_record("example.org", 6, 1, 300, &rdata));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1254, &msg),
            Err(DnsError::MalformedSoa)
        );
    }

    #[test]
    fn rejects_soa_with_name_overrunning_rdata() {
        // W1-L1a-F2: a name whose encoded form overruns the declared rdata
        // boundary is rejected as MalformedSoa (cumulative sub-component
        // bounds), even though the name bytes remain inside the message.
        let mut rdata = qname_bytes("ns1.example.org");
        rdata.extend_from_slice(&qname_bytes("hostmaster.example.org"));
        rdata.extend_from_slice(&[0u8; 20]);
        let declared = qname_bytes("ns1.example.org").len() + 20;
        let mut msg = header(0x1255, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&qname_bytes("example.org"));
        msg.extend_from_slice(&6u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(
            &u16::try_from(declared)
                .expect("declared rdlen fits u16")
                .to_be_bytes(),
        );
        msg.extend_from_slice(&rdata);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1255, &msg),
            Err(DnsError::MalformedSoa)
        );
    }
}

mod cache_schedule {
    use super::*;

    #[test]
    fn apply_publishes_positive_to_cache_and_schedule() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let generation = cache.entry(name, Family::A).expect("entry").generation();
        let outcome = Outcome::Positive {
            family: Family::A,
            bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
                .expect("bindings"),
            ttl: 120,
        };
        apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            1000,
            &outcome,
        )
        .expect("apply");
        let entry = cache.entry(name, Family::A).expect("entry");
        assert_eq!(entry.deadlines(), (Some(1120), Some(1120 + 259_200)));
        assert_eq!(entry.state(1100), crate::dns::cache::EntryState::Fresh);
        let due = schedules
            .due_time(0, Family::A)
            .expect("due")
            .expect("some");
        assert_eq!(due, 1000 + 120, "normal refresh from receipt");
    }

    #[test]
    fn ineligible_only_positive_schedules_backoff_not_refresh() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let generation = cache.entry(name, Family::A).expect("entry").generation();
        let outcome = Outcome::Positive {
            family: Family::A,
            bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
                .expect("bindings"),
            ttl: 120,
        };
        apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            1000,
            &outcome,
        )
        .expect("apply");
        let due = schedules
            .due_time(0, Family::A)
            .expect("due")
            .expect("scheduled");
        assert_eq!(
            due,
            1000 + 1,
            "ineligible-only positive advances the 1s retry backoff, not a normal refresh"
        );
    }

    #[test]
    fn apply_nxdomain_evicts_both_families() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let gen_a = cache.entry(name, Family::A).expect("entry").generation();
        let gen_aaaa = cache.entry(name, Family::Aaaa).expect("entry").generation();
        let outcome = Outcome::NxDomain { soa: None };
        apply_outcome(&mut cache, &mut schedules, 0, gen_a, 1000, 1000, &outcome).expect("apply");
        assert!(cache.entry(name, Family::A).expect("entry").is_empty());
        assert!(cache.entry(name, Family::Aaaa).expect("entry").is_empty());
        assert_ne!(
            cache.entry(name, Family::Aaaa).expect("entry").generation(),
            gen_aaaa
        );
    }

    #[test]
    fn positive_schedule_overflow_after_stage_leaves_cache_untouched() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let generation = cache.entry(name, Family::A).expect("entry").generation();
        let before_due = schedules.due_time(0, Family::A).expect("due");
        let outcome = Outcome::Positive {
            family: Family::A,
            bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
                .expect("bindings"),
            ttl: 120,
        };
        let err = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            u64::MAX,
            &outcome,
        )
        .expect_err("schedule deadline overflow must refuse the whole outcome");
        assert!(
            matches!(err, DnsError::Cache(CacheError::DeadlineOverflow)),
            "expected DeadlineOverflow, got {err:?}"
        );
        assert_eq!(
            cache.entry(name, Family::A).expect("entry").generation(),
            generation,
            "cache must be untouched when the schedule refuses"
        );
        assert_eq!(
            schedules.due_time(0, Family::A).expect("due"),
            before_due,
            "schedule must be unchanged after its own refusal"
        );
    }

    #[test]
    fn nxdomain_schedule_overflow_after_evict_leaves_cache_untouched() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let a_generation = cache.entry(name, Family::A).expect("entry").generation();
        let aaaa_generation = cache.entry(name, Family::Aaaa).expect("entry").generation();
        apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            a_generation,
            1000,
            1000,
            &Outcome::Positive {
                family: Family::A,
                bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(
                    93, 184, 216, 34,
                ))])
                .expect("bindings"),
                ttl: 120,
            },
        )
        .expect("seed an eligible positive for the A family");
        let seeded_generation = cache.entry(name, Family::A).expect("entry").generation();
        assert_ne!(
            seeded_generation, a_generation,
            "seed advanced the A generation"
        );
        let err = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            seeded_generation,
            1000,
            u64::MAX,
            &Outcome::NxDomain { soa: None },
        )
        .expect_err("nxdomain schedule deadline overflow must refuse the whole outcome");
        assert!(
            matches!(err, DnsError::Cache(CacheError::DeadlineOverflow)),
            "expected DeadlineOverflow, got {err:?}"
        );
        assert_eq!(
            cache.entry(name, Family::A).expect("entry").generation(),
            seeded_generation,
            "the A entry must survive when the schedule refuses"
        );
        assert!(
            !cache.entry(name, Family::A).expect("entry").is_empty(),
            "the seeded A binding must survive"
        );
        assert_eq!(
            cache.entry(name, Family::Aaaa).expect("entry").generation(),
            aaaa_generation,
            "the AAAA entry must survive when the schedule refuses"
        );
    }

    #[test]
    fn apply_nxdomain_recovers_both_exchange_incidents() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let generation = cache.entry(name, Family::A).expect("entry").generation();
        schedules
            .note_exchange_failure(
                0,
                Family::A,
                1000,
                crate::dns::transport::FailureReason::Connect,
            )
            .expect("open the A incident");
        schedules
            .note_exchange_failure(
                0,
                Family::Aaaa,
                1000,
                crate::dns::transport::FailureReason::Connect,
            )
            .expect("open the AAAA incident");
        let incidents = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            1012,
            &Outcome::NxDomain { soa: None },
        )
        .expect("apply");
        assert_eq!(
            incidents.per_type,
            [
                PerTypeTransition::Recovered { duration: 12 },
                PerTypeTransition::Recovered { duration: 12 },
            ],
            "an NXDOMAIN clears both per-type exchange incidents"
        );
    }

    #[test]
    fn apply_positive_recovers_only_its_own_family_incident() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let gen_a = cache.entry(name, Family::A).expect("entry").generation();
        let gen_aaaa = cache.entry(name, Family::Aaaa).expect("entry").generation();
        schedules
            .note_exchange_failure(
                0,
                Family::A,
                1000,
                crate::dns::transport::FailureReason::Connect,
            )
            .expect("open the A incident");
        schedules
            .note_exchange_failure(
                0,
                Family::Aaaa,
                1000,
                crate::dns::transport::FailureReason::Connect,
            )
            .expect("open the AAAA incident");
        let a_incidents = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            gen_a,
            1000,
            1012,
            &Outcome::Positive {
                family: Family::A,
                bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(
                    93, 184, 216, 34,
                ))])
                .expect("bindings"),
                ttl: 120,
            },
        )
        .expect("apply the A positive");
        assert_eq!(
            a_incidents.per_type,
            [
                PerTypeTransition::Recovered { duration: 12 },
                PerTypeTransition::None,
            ],
            "a positive A clears only the A incident, leaving AAAA open"
        );
        let aaaa_incidents = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            gen_aaaa,
            1000,
            1020,
            &Outcome::Positive {
                family: Family::Aaaa,
                bindings: BindingList::from_slice(&[NumericAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x0220, 0x0001, 0, 0, 0, 0x0248,
                ))])
                .expect("bindings"),
                ttl: 120,
            },
        )
        .expect("apply the AAAA positive");
        assert_eq!(
            aaaa_incidents.per_type,
            [
                PerTypeTransition::None,
                PerTypeTransition::Recovered { duration: 20 },
            ],
            "a later positive AAAA clears only the still-open AAAA incident"
        );
    }

    #[test]
    fn apply_nodata_leaves_exchange_incidents_untouched() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let generation = cache.entry(name, Family::A).expect("entry").generation();
        schedules
            .note_exchange_failure(
                0,
                Family::A,
                1000,
                crate::dns::transport::FailureReason::Connect,
            )
            .expect("open the A incident");
        schedules
            .note_exchange_failure(
                0,
                Family::Aaaa,
                1000,
                crate::dns::transport::FailureReason::Connect,
            )
            .expect("open the AAAA incident");
        let incidents = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            1012,
            &Outcome::NoData {
                family: Family::A,
                soa: None,
            },
        )
        .expect("apply");
        assert_eq!(
            incidents.per_type,
            [PerTypeTransition::None, PerTypeTransition::None],
            "a NODATA touches no per-type exchange incident"
        );
        let nxdomain = apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            1020,
            &Outcome::NxDomain { soa: None },
        )
        .expect("apply");
        assert_eq!(
            nxdomain.per_type,
            [
                PerTypeTransition::Recovered { duration: 20 },
                PerTypeTransition::Recovered { duration: 20 },
            ],
            "the incidents survived NODATA untouched and an NXDOMAIN later clears them"
        );
    }

    #[test]
    fn nodata_through_cname_target_without_owner_is_negative() {
        let mut msg = header(20, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 20, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NoData {
                family: Family::A,
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn rejects_over_record_count_bound() {
        let mut msg = header(
            21,
            true,
            0,
            1,
            u16::try_from(MAX_TOTAL_RR + 1).expect("record count boundary fits u16"),
            0,
            0,
        );
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 21, &msg),
            Err(DnsError::ExcessiveRecords {
                total: MAX_TOTAL_RR + 1,
                limit: MAX_TOTAL_RR,
            })
        );
    }
}

mod family {
    use super::*;

    #[test]
    fn rejects_coexist_cname_then_address() {
        let mut msg = header(24, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 200));
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 24, &msg),
            Err(DnsError::CnameCoexist)
        );
    }

    #[test]
    fn rejects_coexist_address_then_cname() {
        let mut msg = header(25, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 60));
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 200));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 25, &msg),
            Err(DnsError::CnameCoexist)
        );
    }

    #[test]
    fn ignored_opposite_family_address_after_cname_yields_empty_noerror_without_soa() {
        let mut msg = header(0x124d, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&aaaa_record(
            "sub.example.org",
            [
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
            60,
        ));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x124d, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn ignored_opposite_family_aaaa_then_cname_yields_empty_noerror_without_soa() {
        let mut msg = header(0x124e, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&aaaa_record(
            "sub.example.org",
            [
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
            60,
        ));
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x124e, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn ignored_opposite_family_aaaa_after_cname_yields_empty_noerror_without_soa() {
        let mut msg = header(0x124f, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&28u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::Aaaa, 0x124f, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn ignored_opposite_family_a_then_cname_when_querying_aaaa_yields_empty_noerror_without_soa() {
        let mut msg = header(0x1250, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&28u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 60));
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::Aaaa, 0x1250, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn accepts_lone_opposite_family_address_without_cname() {
        let mut msg = header(0x1251, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&aaaa_record(
            "sub.example.org",
            [
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
            60,
        ));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1251, &msg);
        assert_ne!(out, Err(DnsError::CnameCoexist));
        assert_eq!(out, Err(DnsError::EmptyNoerrorWithoutSoa));
    }

    #[test]
    fn nxdomain_with_opposite_family_aaaa_at_terminal_is_clean_nxdomain() {
        let mut msg = header(0x1252, true, 3, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&aaaa_record(
            "sub.example.org",
            [
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
            60,
        ));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1252, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NxDomain { soa: None },
            "an NXDOMAIN carrying a wrong-family AAAA at the terminal owner is a clean NxDomain, never TerminalWithoutData"
        );
    }

    #[test]
    fn nxdomain_with_opposite_family_a_at_terminal_is_clean_nxdomain() {
        let mut msg = header(0x1253, true, 3, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&28u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [10, 0, 0, 1], 60));
        let out = parse_response_ws("sub.example.org", Family::Aaaa, 0x1253, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NxDomain { soa: None },
            "an NXDOMAIN carrying a wrong-family A at the terminal owner is a clean NxDomain, never TerminalWithoutData"
        );
    }

    #[test]
    fn nxdomain_with_same_family_a_at_terminal_is_terminal_without_data() {
        let mut msg = header(0x1271, true, 3, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [10, 0, 0, 1], 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1271, &msg),
            Err(DnsError::TerminalWithoutData),
            "an NXDOMAIN carrying a same-family A at the terminal owner is TerminalWithoutData (W1-H1b-F3)"
        );
    }
}

mod wire_names {
    use super::*;

    #[test]
    fn rejects_cname_chain_deeper_than_max_links() {
        let mut msg = header(0x1272, true, 0, 1, 9, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "c1.sub.example.org", 100));
        for i in 1..9 {
            let owner = format!("c{i}.sub.example.org");
            let target = format!("c{}.sub.example.org", i + 1);
            msg.extend_from_slice(&cname_record(&owner, &target, 100));
        }
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1272, &msg),
            Err(DnsError::CnameTooDeep { links: 9 }),
            "a rooted CNAME chain longer than MAX_CNAME_LINKS is rejected (W2-H2b-F6)"
        );
    }

    #[test]
    fn rejects_message_too_long() {
        let msg = vec![0u8; DNS_MSG_LIMIT + 1];
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0x1273, &msg),
            Err(DnsError::MessageTooLong),
            "a response larger than DNS_MSG_LIMIT is refused before parsing (W4-H4b-F2)"
        );
    }

    #[test]
    fn rejects_query_too_long_mid_label() {
        let mut buf = [0u8; 512];
        let name = format!("{}.example.org", "a".repeat(64));
        assert_eq!(
            write_qname(&mut buf, 0, &name),
            Err(DnsError::QueryTooLong),
            "a mid-name label longer than 63 bytes is refused (W4-H4b-F2)"
        );
    }

    #[test]
    fn rejects_query_too_long_tail_label() {
        let mut buf = [0u8; 512];
        let name = format!("example.{}", "a".repeat(64));
        assert_eq!(
            write_qname(&mut buf, 0, &name),
            Err(DnsError::QueryTooLong),
            "a trailing label longer than 63 bytes is refused (W4-H4b-F2)"
        );
    }

    #[test]
    fn excessive_candidates_rejected() {
        let mut msg = header(29, true, 0, 1, 17, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        for octet in 1..=17u8 {
            msg.extend_from_slice(&a_record("sub.example.org", [10, 0, 0, octet], 60));
        }
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 29, &msg),
            Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES
            })
        );
    }

    #[test]
    fn rejects_overlong_label_fail_closed() {
        let mut msg = header(37, true, 0, 1, 0, 0, 0);
        msg.push(64);
        msg.extend_from_slice(&[b'a'; 64]);
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 37, &msg),
            Err(DnsError::ReservedLabelType { offset: 12 })
        );
    }

    #[test]
    fn rejects_name_too_long() {
        let mut msg = header(38, true, 0, 1, 0, 0, 0);
        for _ in 0..4 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 38, &msg),
            Err(DnsError::NameTooLong)
        );
    }

    #[test]
    fn rejects_256_octet_wire_name_including_root() {
        let mut msg = Vec::new();
        for _ in 0..3 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.push(62);
        msg.extend_from_slice(&[b'a'; 62]);
        msg.push(0);
        assert_eq!(read_name(&msg, 0, false), Err(DnsError::NameTooLong));
    }

    #[test]
    fn accepts_255_octet_wire_name_including_root() {
        let mut msg = Vec::new();
        for _ in 0..3 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.push(61);
        msg.extend_from_slice(&[b'a'; 61]);
        msg.push(0);
        let (_, used) = read_name(&msg, 0, false).expect("255-octet wire name must decode");
        assert_eq!(used, 255);
    }

    #[test]
    fn rejects_pointer_not_backward() {
        let mut msg = header(39, true, 0, 1, 0, 0, 0);
        msg.push(0xc0);
        msg.push(0x0c); // self-pointer: target 12 >= decode 12
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 39, &msg),
            Err(DnsError::PointerNotBackward)
        );
    }

    #[test]
    fn rejects_reserved_label_type() {
        let mut msg = header(40, true, 0, 1, 0, 0, 0);
        msg.push(0x41); // 0x41 & 0xc0 == 0x40: reserved label type
        msg.push(b'a');
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 40, &msg),
            Err(DnsError::ReservedLabelType { offset: 12 })
        );
    }

    #[test]
    fn rejects_pointer_cycle() {
        let mut msg = vec![0u8; 4];
        for i in 0..9u8 {
            msg.push(0xc0);
            msg.push(2 + 2 * i);
        }
        assert_eq!(read_name(&msg, 20, false), Err(DnsError::PointerCycle));
    }
}

mod duplicate_cname {
    use super::*;

    #[test]
    fn rejects_conflicting_cname() {
        let mut msg = header(41, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.example.org", 60));
        msg.extend_from_slice(&cname_record("sub.example.org", "b.example.org", 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 41, &msg),
            Err(DnsError::ConflictingCname)
        );
    }

    #[test]
    fn duplicate_identical_cname_long_then_short_takes_earliest_ttl() {
        let mut msg = header(0x1264, true, 0, 1, 3, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 30));
        msg.extend_from_slice(&a_record("a.sub.example.org", [93, 184, 216, 34], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1264, &msg).expect("parse");
        let parsed_ttl = match &out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                *ttl
            }
            other => panic!("expected positive, got {other:?}"),
        };
        assert_eq!(
            parsed_ttl, 30,
            "duplicate short TTL wins over the earlier long TTL"
        );
        assert_eq!(
            positive_freshness_deadline(&out, 1000),
            (1000 + parsed_ttl, 1000 + parsed_ttl + 259_200),
            "cache freshness deadline reflects the earliest supporting CNAME TTL"
        );
    }

    #[test]
    fn duplicate_identical_cname_short_then_long_keeps_earliest_ttl() {
        let mut msg = header(0x1266, true, 0, 1, 3, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 30));
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&a_record("a.sub.example.org", [93, 184, 216, 34], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1266, &msg).expect("parse");
        let parsed_ttl = match &out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                *ttl
            }
            other => panic!("expected positive, got {other:?}"),
        };
        assert_eq!(
            parsed_ttl, 30,
            "duplicate short TTL stays the earliest regardless of order"
        );
        assert_eq!(
            positive_freshness_deadline(&out, 1000),
            (1000 + parsed_ttl, 1000 + parsed_ttl + 259_200),
            "cache freshness deadline reflects the earliest supporting CNAME TTL"
        );
    }

    #[test]
    fn duplicate_identical_cname_multi_link_long_then_short_takes_earliest_ttl() {
        let mut msg = header(0x1267, true, 0, 1, 4, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&cname_record(
            "a.sub.example.org",
            "deep.a.sub.example.org",
            200,
        ));
        msg.extend_from_slice(&cname_record(
            "a.sub.example.org",
            "deep.a.sub.example.org",
            30,
        ));
        msg.extend_from_slice(&a_record("deep.a.sub.example.org", [93, 184, 216, 34], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1267, &msg).expect("parse");
        let parsed_ttl = match &out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                *ttl
            }
            other => panic!("expected positive, got {other:?}"),
        };
        assert_eq!(
            parsed_ttl, 30,
            "duplicate short TTL at a middle link wins over the earlier long TTL"
        );
        assert_eq!(
            positive_freshness_deadline(&out, 1000),
            (1000 + parsed_ttl, 1000 + parsed_ttl + 259_200),
            "cache freshness deadline reflects the earliest supporting CNAME TTL"
        );
    }

    #[test]
    fn duplicate_identical_cname_multi_link_short_then_long_keeps_earliest_ttl() {
        let mut msg = header(0x1268, true, 0, 1, 4, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "a.sub.example.org", 200));
        msg.extend_from_slice(&cname_record(
            "a.sub.example.org",
            "deep.a.sub.example.org",
            30,
        ));
        msg.extend_from_slice(&cname_record(
            "a.sub.example.org",
            "deep.a.sub.example.org",
            200,
        ));
        msg.extend_from_slice(&a_record("deep.a.sub.example.org", [93, 184, 216, 34], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 0x1268, &msg).expect("parse");
        let parsed_ttl = match &out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                *ttl
            }
            other => panic!("expected positive, got {other:?}"),
        };
        assert_eq!(
            parsed_ttl, 30,
            "duplicate short TTL at a middle link stays earliest regardless of order"
        );
        assert_eq!(
            positive_freshness_deadline(&out, 1000),
            (1000 + parsed_ttl, 1000 + parsed_ttl + 259_200),
            "cache freshness deadline reflects the earliest supporting CNAME TTL"
        );
    }
}

mod robustness {
    use super::*;

    #[test]
    fn owners_match_case_insensitively() {
        let mut msg = header(22, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("Sub.Example.Org", "A.Sub.Example.Org", 200));
        msg.extend_from_slice(&a_record("a.sub.example.org", [203, 0, 113, 7], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 22, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn unknown_answer_type_is_skipped_and_does_not_break_parse() {
        let mut msg = header(23, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut unknown = qname_bytes("sub.example.org");
        unknown.extend_from_slice(&99u16.to_be_bytes());
        unknown.extend_from_slice(&1u16.to_be_bytes());
        unknown.extend_from_slice(&60u32.to_be_bytes());
        unknown.extend_from_slice(&4u16.to_be_bytes());
        unknown.extend_from_slice(&[10, 11, 12, 13]);
        msg.extend_from_slice(&unknown);
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        let out = parse_response_ws("sub.example.org", Family::A, 23, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }
}

#[cfg(feature = "alloc-witness")]
mod alloc_witness {
    use super::*;

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn dns_parse_zero_heap_after_positive_control() {
        use crate::alloc::{self, Phase};
        let msg = direct_a("sub.example.org", 30, [93, 184, 216, 34], 120);
        let fq = fqdn("sub.example.org");
        let ((), control) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            control.allocs > 0 && control.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {control:?}"
        );

        eprintln!(
            "size_of Owner={} ResponseWorkspace={}",
            size_of::<Owner>(),
            size_of::<ResponseWorkspace>()
        );
        let (out, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let mut ws = ResponseWorkspace::default();
            let zones = BailiwickZones::single(&fq);
            parse_response(&mut ws, &zones, &fq, Family::A, 30, &msg).expect("parse")
        });
        assert!(
            counts.all_zero(),
            "positive parse must be allocation-free: {counts:?}"
        );
        assert!(matches!(out, Outcome::Positive { .. }));
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn dns_parse_zero_heap_after_negative_control() {
        use crate::alloc::{self, Phase};
        let mut msg = header(31, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let fq = fqdn("sub.example.org");
        let ((), control) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            control.allocs > 0 && control.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {control:?}"
        );

        let (out, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let mut ws = ResponseWorkspace::default();
            let zones = BailiwickZones::single(&fq);
            parse_response(&mut ws, &zones, &fq, Family::A, 31, &msg).expect("parse")
        });
        assert!(
            counts.all_zero(),
            "negative parse must be allocation-free: {counts:?}"
        );
        assert!(matches!(out, Outcome::NxDomain { .. }));
    }
}

mod embedded_dot {
    use super::*;

    #[test]
    fn rejects_embedded_dot_in_question_qname() {
        let mut msg = header(60, true, 0, 1, 0, 0, 0);
        msg.extend_from_slice(&single_label_qname("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 60, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_embedded_dot_in_answer_owner() {
        let mut msg = header(61, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = single_label_qname("sub.example.org");
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&120u32.to_be_bytes());
        owner.extend_from_slice(&4u16.to_be_bytes());
        owner.extend_from_slice(&[93, 184, 216, 34]);
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 61, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_embedded_dot_in_cname_target() {
        let mut msg = header(62, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = qname_bytes("sub.example.org");
        owner.extend_from_slice(&5u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&60u32.to_be_bytes());
        let target = single_label_qname("a.example.org");
        owner.extend_from_slice(
            &u16::try_from(target.len())
                .expect("cname target fits u16")
                .to_be_bytes(),
        );
        owner.extend_from_slice(&target);
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 62, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_embedded_dot_in_terminal_address_owner() {
        let mut msg = header(63, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = single_label_qname("sub.example.org");
        owner.extend_from_slice(&28u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&120u32.to_be_bytes());
        owner.extend_from_slice(&16u16.to_be_bytes());
        owner.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 63, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_embedded_dot_duplicate_owner_key() {
        let mut msg = header(64, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        let mut owner = single_label_qname("sub.example.org");
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&120u32.to_be_bytes());
        owner.extend_from_slice(&4u16.to_be_bytes());
        owner.extend_from_slice(&[140, 82, 121, 5]);
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 64, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_embedded_dot_bailiwick_suffix() {
        let mut msg = header(65, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = qname_bytes("sub.example.org");
        owner.extend_from_slice(&5u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&60u32.to_be_bytes());
        let target = single_label_qname("example.org");
        owner.extend_from_slice(
            &u16::try_from(target.len())
                .expect("cname target fits u16")
                .to_be_bytes(),
        );
        owner.extend_from_slice(&target);
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 65, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_embedded_dot_soa_owner() {
        let mut msg = header(66, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = single_label_qname("example.org");
        owner.extend_from_slice(&6u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&300u32.to_be_bytes());
        let mname = qname_bytes("ns1.example.org");
        let rname = qname_bytes("hostmaster.example.org");
        let rdata_len = mname.len() + rname.len() + 20;
        owner.extend_from_slice(
            &u16::try_from(rdata_len)
                .expect("soa rdata fits u16")
                .to_be_bytes(),
        );
        owner.extend_from_slice(&mname);
        owner.extend_from_slice(&rname);
        for v in [1u32, 3600, 600, 86400, 60] {
            owner.extend_from_slice(&v.to_be_bytes());
        }
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 66, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn rejects_adversarial_embedded_dot_witness() {
        let mut msg = header(67, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&single_label_qname("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = single_label_qname("sub.example.org");
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&120u32.to_be_bytes());
        owner.extend_from_slice(&4u16.to_be_bytes());
        owner.extend_from_slice(&[93, 184, 216, 34]);
        msg.extend_from_slice(&owner);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 67, &msg),
            Err(DnsError::EmbeddedDotInLabel)
        );
    }

    #[test]
    fn accepts_embedded_dot_in_soa_mname_rname() {
        let mut msg = header(68, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut owner = qname_bytes("example.org");
        owner.extend_from_slice(&6u16.to_be_bytes());
        owner.extend_from_slice(&1u16.to_be_bytes());
        owner.extend_from_slice(&300u32.to_be_bytes());
        let mname = single_label_qname("ns1.example.org");
        let rname = single_label_qname("hostmaster.example.org");
        let rdata_len = mname.len() + rname.len() + 20;
        owner.extend_from_slice(
            &u16::try_from(rdata_len)
                .expect("soa rdata fits u16")
                .to_be_bytes(),
        );
        owner.extend_from_slice(&mname);
        owner.extend_from_slice(&rname);
        for v in [1u32, 3600, 600, 86400, 60] {
            owner.extend_from_slice(&v.to_be_bytes());
        }
        msg.extend_from_slice(&owner);
        let out = parse_response_ws("sub.example.org", Family::A, 68, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NxDomain {
                soa: Some(Soa::new(300, 60)),
            }
        );
    }
}
