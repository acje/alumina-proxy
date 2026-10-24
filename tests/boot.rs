use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use alumina::config::{self, ConfigError};
use alumina::inventory::{self, BootInventory, TrafficStorage};
use alumina::preflight::{self, KernelFacts, PreflightError};
use alumina::resolver;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("alumina-boot-{}-{}-{}", tag, process::id(), n));
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, body).expect("write temp fixture");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const VALID_CONFIG: &str = r#"
listen = "0.0.0.0:8080"
startup_unresolved_allowance = 1
resolver = ["1.1.1.1"]
[any_illegal]
scope = "connection"
[allowed_fqdn."example.com:443"]
early_data = { action = "flare_only", scope = "connection" }
[allowed_fqdn."sub.example.org.:443"]
early_data = { action = "flare_only", scope = "connection" }
# trailing comment line: the document-bound test pads this line to the exact limit
"#;

/// One keyed `[allowed_fqdn."<fqdn>:<port>"]` table per allowlisted name.
fn keyed_entry(fqdn: &str) -> String {
    format!(
        "[allowed_fqdn.\"{fqdn}\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n"
    )
}

#[test]
fn config_valid_minimal_parses_without_coercion() {
    let cfg = config::parse_config_document(VALID_CONFIG).expect("valid config");
    assert_eq!(cfg.allowlist().len(), 2);
    assert_eq!(
        cfg.allowlist().get(0).map(alumina::config::Fqdn::as_str),
        Some("example.com")
    );
    assert_eq!(
        cfg.allowlist().get(1).map(alumina::config::Fqdn::as_str),
        Some("sub.example.org")
    );
    assert_eq!(cfg.listen().port(), 8080);
    assert_eq!(cfg.startup_unresolved_allowance(), 1);
}

#[test]
fn config_doc_limit_exact_bound_ok_and_oversize_rejected_without_truncation() {
    let mut doc = VALID_CONFIG.trim_end_matches('\n').to_owned();
    while doc.len() < config::CONFIG_DOC_LIMIT {
        doc.push('#');
    }
    assert_eq!(doc.len(), config::CONFIG_DOC_LIMIT);
    assert!(
        config::parse_config_document(&doc).is_ok(),
        "an exactly-{:?}-byte document must be accepted",
        config::CONFIG_DOC_LIMIT
    );

    let oversized = format!("{doc}x");
    assert_eq!(oversized.len(), config::CONFIG_DOC_LIMIT + 1);
    assert!(matches!(
        config::parse_config_document(&oversized),
        Err(ConfigError::OversizedDocument { .. })
    ));

    let dir = TempDir::new("oversize");
    let path = dir.write("config.toml", &oversized);
    assert!(matches!(
        config::load_config_document(&path.to_string_lossy()),
        Err(ConfigError::OversizedDocument { .. })
    ));
}

#[test]
fn config_all_mandatory_fields_fail_when_missing() {
    for (field, doc) in [
        ("listen", "startup_unresolved_allowance = 0\n"),
        (
            "startup_unresolved_allowance",
            "listen = \"0.0.0.0:8080\"\n",
        ),
        (
            "resolver",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n",
        ),
        (
            "any_illegal",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n",
        ),
    ] {
        assert!(
            matches!(
                config::parse_config_document(doc),
                Err(ConfigError::MissingField(f)) if f == field
            ),
            "config missing {field} must fail with MissingField({field})"
        );
    }
    let absent_allowlist = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n";
    assert!(
        matches!(
            config::parse_config_document(absent_allowlist),
            Err(ConfigError::AllowlistEmpty)
        ),
        "a document with no allowed_fqdn tables offers no name to enforce, so it is AllowlistEmpty"
    );
}

#[test]
fn config_unknown_key_and_unknown_table_fail() {
    assert!(matches!(
        config::parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nbogus = 1\n"
        ),
        Err(ConfigError::UnknownKey(_))
    ));
    assert!(matches!(
        config::parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[bogus]\nx = 1\n"
        ),
        Err(ConfigError::UnknownTable(_))
    ));
    assert!(
        matches!(
            config::parse_config_document(
                "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
            ),
            Err(ConfigError::UnknownTable(_))
        ),
        "the superseded positional [actions] table must be rejected as unknown"
    );
}

#[test]
fn config_duplicate_key_and_duplicate_table_fail() {
    let dup_key =
        "listen = \"0.0.0.0:8080\"\nlisten = \"0.0.0.0:8081\"\nstartup_unresolved_allowance = 0\n";
    assert!(matches!(
        config::parse_config_document(dup_key),
        Err(ConfigError::ParseToml {
            message,
            ..
        }) if !message.is_empty()
    ));

    let dup_table = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
    assert!(
        matches!(
            config::parse_config_document(dup_table),
            Err(ConfigError::ParseToml {
                message,
                ..
            }) if !message.is_empty()
        ),
        "an exactly duplicated allowlist table key is a TOML parse error (table keys are unique), not a validation error"
    );
}

#[test]
fn config_wrong_types_fail_without_coercion() {
    for (name, doc) in [
        (
            "allowance-string",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = \"1\"\n",
        ),
        (
            "allowed-fqdn-string",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\nallowed_fqdn = \"a.example\"\n[any_illegal]\nscope = \"connection\"\n",
        ),
        (
            "allowed-fqdn-integer-entry",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn]\n\"a.example:443\" = 1\n",
        ),
        (
            "allowed-fqdn-boolean-entry",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn]\n\"a.example:443\" = true\n",
        ),
        (
            "early-data-string",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = \"flare_only\"\n",
        ),
        (
            "listen-integer",
            "listen = 8080\nstartup_unresolved_allowance = 0\n",
        ),
    ] {
        assert!(
            matches!(
                config::parse_config_document(doc),
                Err(ConfigError::WrongType(_))
            ),
            "config {name} must fail as WrongType, never coerce"
        );
    }
}

#[test]
fn config_allowlist_empty_and_over_32_fail() {
    let empty = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn]\n";
    assert!(matches!(
        config::parse_config_document(empty),
        Err(ConfigError::AllowlistEmpty)
    ));
    let mut entries = String::new();
    for i in 0..33usize {
        entries.push_str(&keyed_entry(&format!("n{i}.example:443")));
    }
    let doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n{entries}"
    );
    assert!(matches!(
        config::parse_config_document(&doc),
        Err(ConfigError::AllowlistTooMany { got: 33 })
    ));
}

#[test]
fn config_allowlist_dedup_by_full_pair_same_host_different_port_distinct() {
    let dup_exact = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
    assert!(
        matches!(
            config::parse_config_document(dup_exact),
            Err(ConfigError::ParseToml { .. })
        ),
        "an exact duplicate table key is a TOML parse error: table keys are unique"
    );
    let dup_normalized = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"a.example.:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
    assert!(
        matches!(
            config::parse_config_document(dup_normalized),
            Err(ConfigError::DuplicateAllowlistName(_))
        ),
        "distinct keys whose names normalize to the same <fqdn>:<port> pair are a duplicate"
    );
    let dup_same_host_different_port = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:8443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
    let cfg = config::parse_config_document(dup_same_host_different_port)
        .expect("dedup is by the full <fqdn>:<port> pair, so the same host at a second port is a distinct entry");
    assert_eq!(cfg.allowlist().len(), 2);
    assert_eq!(cfg.allowlist().get(0).unwrap().port(), 443);
    assert_eq!(cfg.allowlist().get(1).unwrap().port(), 8443);
}

#[test]
fn config_invalid_fqdn_rejected() {
    for (name, fqdn) in [
        ("uppercase", "Example.COM:443"),
        ("underscore", "bad_name.example:443"),
        ("empty-label", ".example.com:443"),
        ("trailing-hyphen", "bad-.example.com:443"),
        (
            "long-label",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com:443",
        ),
    ] {
        let doc = format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n{}",
            keyed_entry(fqdn)
        );
        assert!(
            config::parse_config_document(&doc).is_err(),
            "FQDN {name} must be rejected"
        );
    }
}

#[test]
fn config_allowlist_requires_fqdn_port_else_invalid_fqdn_exit78() {
    for (name, entry) in [
        ("bare-no-port", "a.example"),
        ("port-zero", "a.example:0"),
        ("port-overflow", "a.example:65536"),
        ("port-leading-zero", "a.example:0443"),
        ("port-non-numeric", "a.example:abc"),
        ("port-empty", "a.example:"),
    ] {
        let doc = format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n{}",
            keyed_entry(entry)
        );
        let doc_name = format!("allowlist entry {name:?} must be rejected");
        let err = config::parse_config_document(&doc).expect_err(&doc_name);
        assert!(
            matches!(&err, ConfigError::InvalidFqdn { .. }),
            "allowlist entry {name:?} must be InvalidFqdn, got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "InvalidFqdn must exit 78");
    }
    let ok_doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n{}{}",
        keyed_entry("a.example:1"),
        keyed_entry("b.example:65535")
    );
    let cfg = config::parse_config_document(&ok_doc).expect("ports 1 and 65535 are valid");
    assert_eq!(cfg.allowlist().len(), 2);
    assert_eq!(cfg.allowlist().get(0).unwrap().port(), 1);
    assert_eq!(cfg.allowlist().get(1).unwrap().port(), 65535);
}

#[test]
fn config_allowance_out_of_range_fails() {
    let eq_len = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n[any_illegal]\nscope = \"connection\"\n{}",
        keyed_entry("a.example:443")
    );
    assert!(matches!(
        config::parse_config_document(&eq_len),
        Err(ConfigError::AllowanceOutOfRange { .. })
    ));
    let negative = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = -1\n[any_illegal]\nscope = \"connection\"\n{}",
        keyed_entry("a.example:443")
    );
    assert!(matches!(
        config::parse_config_document(&negative),
        Err(ConfigError::AllowanceOutOfRange { .. })
    ));
    let zero_ok = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n{}",
        keyed_entry("a.example:443")
    );
    assert!(config::parse_config_document(&zero_ok).is_ok());
}

#[test]
fn config_listen_variants() {
    for (name, listen) in [
        ("no-port", "1.2.3.4"),
        ("port-zero", "1.2.3.4:0"),
        ("port-overflow", "1.2.3.4:65536"),
        ("non-numeric-port", "1.2.3.4:abc"),
        ("unbracketed-ipv6", "2001:db8::1:8080"),
        ("bracketed-no-port", "[2001:db8::1]"),
        ("hostname-listen", "localhost:8080"),
        ("empty", ""),
    ] {
        let doc = format!(
            "listen = \"{listen}\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n{}",
            keyed_entry("a.example:443")
        );
        assert!(
            config::parse_config_document(&doc).is_err(),
            "listen {name} must be rejected"
        );
    }
    let ipv6_ok = format!(
        "listen = \"[2001:db8::1]:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n{}",
        keyed_entry("a.example:443")
    );
    let cfg = config::parse_config_document(&ipv6_ok).expect("bracketed IPv6 listen");
    assert_eq!(cfg.listen().port(), 8080);
    assert_eq!(cfg.listen().ip().to_string(), "2001:db8::1");
}

#[test]
fn config_allowlist_32_max_fits_document_bound() {
    let mut entries = String::with_capacity(4096);
    for i in 0..32usize {
        entries.push_str(&keyed_entry(&format!("{i}.example.com:443")));
    }
    let doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n{entries}"
    );
    assert!(
        doc.len() <= config::CONFIG_DOC_LIMIT,
        "32 keyed entries must fit the {}-byte document bound, got {}",
        config::CONFIG_DOC_LIMIT,
        doc.len()
    );
    let cfg = config::parse_config_document(&doc).expect("32-name allowlist fits");
    assert_eq!(cfg.allowlist().len(), 32);
}

#[test]
fn config_load_missing_file_fails() {
    let dir = TempDir::new("missing");
    assert!(matches!(
        config::load_config_document(&dir.path().join("nope.toml").to_string_lossy()),
        Err(ConfigError::Unreadable { .. })
    ));
}

#[test]
fn config_non_utf8_document_fails_with_dedicated_encoding_error() {
    let dir = TempDir::new("nonutf8");
    let path = dir.write("config.toml", "");
    std::fs::write(&path, [0x66, 0x6f, 0x6f, 0xff, 0xfe]).expect("write invalid UTF-8 fixture");
    let err = config::load_config_document(&path.to_string_lossy());
    assert!(
        matches!(err, Err(ConfigError::NotUtf8 { .. })),
        "invalid UTF-8 config must be a dedicated encoding error, not a parse error"
    );
}

fn resolver_doc(resolver_key: &str) -> String {
    format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n{resolver_key}[any_illegal]\nscope = \"connection\"\n{}",
        keyed_entry("a.example:443")
    )
}

#[test]
fn resolver_from_config_primary_and_count() {
    let cfg =
        config::parse_config_document(&resolver_doc("resolver = [\"1.1.1.1\", \"8.8.8.8\"]\n"))
            .expect("two resolvers valid");
    assert_eq!(cfg.resolver_set().len(), 2);
    assert_eq!(
        cfg.resolver_set().primary().addr().to_string(),
        "1.1.1.1",
        "primary is index 0"
    );
    assert_eq!(cfg.resolver_set().primary().port(), resolver::RESOLVER_PORT);
    assert_eq!(
        cfg.resolver_set()
            .get(1)
            .expect("index 1")
            .addr()
            .to_string(),
        "8.8.8.8"
    );
    assert!(cfg.resolver_set().get(2).is_none());
}

#[test]
fn resolver_invalid_first_cannot_skip_to_later() {
    for bad in ["not-an-address", "224.0.0.1"] {
        let doc = resolver_doc(&format!("resolver = [\"{bad}\", \"8.8.8.8\"]\n"));
        let err = config::parse_config_document(&doc).expect_err(&format!("{bad} first must fail"));
        assert!(
            matches!(&err, ConfigError::InvalidResolver { index, .. } if *index == 0),
            "{bad} first must be InvalidResolver at index 0, got {err:?}"
        );
    }
}

#[test]
fn resolver_missing_empty_and_oversize_rejected() {
    let no_key = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
    assert!(matches!(
        config::parse_config_document(no_key),
        Err(ConfigError::MissingField(f)) if f == "resolver"
    ));
    assert!(matches!(
        config::parse_config_document(&resolver_doc("resolver = []\n")),
        Err(ConfigError::ResolverCountOutOfRange { got: 0 })
    ));
    let over = std::iter::repeat_n("\"1.1.1.1\"", resolver::MAX_RESOLVERS + 1)
        .collect::<Vec<_>>()
        .join(", ");
    assert!(matches!(
        config::parse_config_document(&resolver_doc(&format!("resolver = [{over}]\n"))),
        Err(ConfigError::ResolverCountOutOfRange { got }) if got == resolver::MAX_RESOLVERS + 1
    ));
}

#[test]
fn resolver_rejects_non_unicast_and_zoned_addresses() {
    for (case, addr) in [
        ("broadcast", "255.255.255.255"),
        ("unspecified", "0.0.0.0"),
        ("multicast", "224.0.0.1"),
        ("ipv6-multicast", "ff02::1"),
        ("ipv6-unspecified", "::"),
        ("zone-id", "fe80::1%eth0"),
    ] {
        let doc = resolver_doc(&format!("resolver = [\"{addr}\"]\n"));
        let err =
            config::parse_config_document(&doc).expect_err(&format!("{case} must be rejected"));
        assert!(
            matches!(&err, ConfigError::InvalidResolver { index, value } if *index == 0 && value == addr),
            "{case} must be InvalidResolver, got {err:?}"
        );
    }
}

#[test]
fn resolver_ipv6_unicast_accepted_from_config() {
    let cfg =
        config::parse_config_document(&resolver_doc("resolver = [\"2606:4700:4700::1111\"]\n"))
            .expect("unicast IPv6 resolver");
    assert_eq!(
        cfg.resolver_set().primary().addr().to_string(),
        "2606:4700:4700::1111"
    );
    assert_eq!(cfg.resolver_set().primary().port(), 53);
}

const fn good_facts() -> KernelFacts {
    KernelFacts {
        ruid: 1000,
        euid: 1000,
        suid: 1000,
        fsuid: 1000,
        cap_eff: 0,
        cap_prm: 0,
        cap_amb: 0,
        no_new_privs: true,
    }
}

#[test]
fn preflight_accepts_nonroot_empty_caps_with_no_new_privs() {
    assert!(preflight::check(good_facts()).is_ok());
}

#[test]
fn preflight_rejects_root_real_saved_filesystem_and_effective_uids() {
    for (axis, facts) in [
        (
            "real",
            KernelFacts {
                ruid: 0,
                ..good_facts()
            },
        ),
        (
            "effective",
            KernelFacts {
                euid: 0,
                ..good_facts()
            },
        ),
        (
            "saved",
            KernelFacts {
                suid: 0,
                ..good_facts()
            },
        ),
        (
            "filesystem",
            KernelFacts {
                fsuid: 0,
                ..good_facts()
            },
        ),
    ] {
        assert!(
            matches!(preflight::check(facts), Err(PreflightError::Root)),
            "{axis} UID axis 0 must be rejected (all four != 0)"
        );
    }
}

#[test]
fn preflight_rejects_each_unmet_prerequisite_independently() {
    assert!(matches!(
        preflight::check(KernelFacts {
            euid: 0,
            ..good_facts()
        }),
        Err(PreflightError::Root)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            cap_eff: 1,
            ..good_facts()
        }),
        Err(PreflightError::NonEmptyEffective)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            cap_prm: 1,
            ..good_facts()
        }),
        Err(PreflightError::NonEmptyPermitted)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            cap_amb: 1,
            ..good_facts()
        }),
        Err(PreflightError::NonEmptyAmbient)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            no_new_privs: false,
            ..good_facts()
        }),
        Err(PreflightError::MissingNoNewPrivs)
    ));
}

#[test]
fn preflight_parses_proc_status_fixture() {
    let text = "Name:\talumina\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    let facts = preflight::parse_proc_status(text).expect("parse");
    assert_eq!(facts.euid, 1000);
    assert!(facts.no_new_privs);
    assert!(preflight::check(facts).is_ok());

    let caps = "Name:\talumina\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000001\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    let facts = preflight::parse_proc_status(caps).expect("parse");
    assert_eq!(facts.cap_eff, 1);
    assert!(matches!(
        preflight::check(facts),
        Err(PreflightError::NonEmptyEffective)
    ));
}

#[test]
fn preflight_malformed_proc_status_is_error_not_verdict() {
    assert!(preflight::parse_proc_status("Name:\talumina\nUid:\tnot-a-number\n").is_err());
    assert!(preflight::parse_proc_status("").is_err());
}

#[test]
fn inventory_traffic_storage_is_exactly_128_mib() {
    assert_eq!(
        inventory::TRAFFIC_STORAGE_BYTES,
        512 * 2 * 128 * 1024,
        "512 slots x 2 directional buffers x 128 KiB"
    );
    assert_eq!(inventory::TRAFFIC_STORAGE_BYTES, 134_217_728);
    assert_eq!(inventory::TUNNEL_SLOTS, 512);
    assert_eq!(inventory::BUFFERS_PER_SLOT, 2);
    assert_eq!(inventory::BUFFER_BYTES, 128 * 1024);
}

#[test]
fn inventory_actually_initializes_full_traffic_storage() {
    let storage = TrafficStorage::allocate().unwrap();
    assert_eq!(
        storage.len(),
        inventory::TRAFFIC_STORAGE_BYTES,
        "full 128 MiB must be actually initialized"
    );
    assert_eq!(
        storage.slots().len(),
        inventory::TUNNEL_SLOTS,
        "the retained store holds one per-slot entry per tunnel"
    );
    let mut total = 0;
    for slot in storage.slots() {
        assert_eq!(slot.up.len(), inventory::BUFFER_BYTES);
        assert_eq!(slot.down.len(), inventory::BUFFER_BYTES);
        total += slot.up.len() + slot.down.len();
    }
    assert_eq!(total, inventory::TRAFFIC_STORAGE_BYTES);
    assert!(!storage.is_empty());
    let inv = BootInventory::phase1();
    assert_eq!(
        inv.named_fixed_buffer_bytes(),
        inventory::TRAFFIC_STORAGE_BYTES
            + inventory::SERVING_WORKSPACE_BYTES
            + inventory::DNS_NAMED_BUFFER_BYTES,
        "named-fixed lower bound = traffic 128 MiB + per-slot serving workspaces + DNS named buffers"
    );
    assert_eq!(
        inv.traffic_storage_bytes(),
        inventory::TRAFFIC_STORAGE_BYTES
    );
    assert_eq!(
        inv.serving_workspace_bytes(),
        inventory::SERVING_WORKSPACE_BYTES
    );
    assert_eq!(
        inv.dns_named_buffer_bytes(),
        inventory::DNS_NAMED_BUFFER_BYTES
    );
    assert_eq!(
        inv.transient_scratch_bytes(),
        config::CONFIG_DOC_LIMIT + 1,
        "transient config read buffer is one byte past the document bound"
    );
    assert!(inv.reserved_future_bytes() > 0);
    assert_ne!(inv.named_fixed_buffer_bytes(), inv.reserved_future_bytes());
}

#[test]
fn inventory_reports_retained_vs_transient_vs_reserved_honestly() {
    let inv = BootInventory::phase1();
    assert_eq!(
        inv.named_fixed_buffer_bytes(),
        inventory::TRAFFIC_STORAGE_BYTES
            + inventory::SERVING_WORKSPACE_BYTES
            + inventory::DNS_NAMED_BUFFER_BYTES,
        "named-fixed lower bound = traffic 128 MiB + per-slot serving workspaces + DNS named buffers"
    );
    assert_eq!(
        inv.traffic_storage_bytes(),
        inventory::TRAFFIC_STORAGE_BYTES
    );
    assert_eq!(
        inv.serving_workspace_bytes(),
        inventory::SERVING_WORKSPACE_BYTES
    );
    assert_eq!(
        inv.dns_named_buffer_bytes(),
        inventory::DNS_NAMED_BUFFER_BYTES
    );
    assert_eq!(
        inv.transient_scratch_bytes(),
        config::CONFIG_DOC_LIMIT + 1,
        "transient config read buffer is one byte past the document bound"
    );
    assert!(inv.reserved_future_bytes() > 0);
    assert_ne!(inv.named_fixed_buffer_bytes(), inv.reserved_future_bytes());
    assert!(
        inv.dns_named_buffer_bytes() > 512 + 16 * 1024,
        "DNS named buffers must cover the query buffer plus the message-limit response buffer"
    );
}
