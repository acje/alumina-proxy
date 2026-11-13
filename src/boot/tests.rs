use super::*;

#[path = "../../tests/support/temp_dir.rs"]
mod temp_dir;
use temp_dir::TempDir;

fn good_facts() -> KernelFacts {
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

const VALID_CONFIG: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"example.com:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"sub.example.org.:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";

const FQDN_CONFIG: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1#dns.google\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"example.com:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"sub.example.org.:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";

const PINNED_CONFIG: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1#dns.google#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"example.com:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"sub.example.org.:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";

#[test]
fn boot_with_good_facts_reports_and_stops_at_phase1_boundary() {
    let dir = TempDir::new("good");
    let config_path = dir
        .path()
        .join("config.toml")
        .to_string_lossy()
        .into_owned();
    dir.write("config.toml", VALID_CONFIG);

    let report = run_boot_with_facts(&config_path, good_facts()).expect("boot with good facts");
    assert_eq!(report.config.allowlist().len(), 2);
    assert_eq!(
        report.config.resolver_set().primary().addr().to_string(),
        "1.1.1.1"
    );
    assert_eq!(report.config.resolver_set().primary().port(), 53);
    assert_eq!(report.storage.len(), inventory::TRAFFIC_STORAGE_BYTES);
    assert_eq!(
        report.inventory.named_fixed_buffer_bytes(),
        inventory::TRAFFIC_STORAGE_BYTES
            + inventory::SERVING_WORKSPACE_BYTES
            + inventory::DNS_NAMED_BUFFER_BYTES
    );
}

#[test]
fn boot_rejects_each_stage_with_ex_config78() {
    let dir = TempDir::new("stages");
    let config_path = dir
        .path()
        .join("config.toml")
        .to_string_lossy()
        .into_owned();

    let err =
        run_boot_with_facts(&config_path, good_facts()).expect_err("missing config must fail");
    assert_eq!(err.exit_status(), EX_CONFIG);

    dir.write("config.toml", VALID_CONFIG);
    let err = run_boot_with_facts(
        &config_path,
        KernelFacts {
            euid: 0,
            ..good_facts()
        },
    )
    .expect_err("root must fail preflight");
    assert_eq!(err.exit_status(), EX_CONFIG);
}

#[test]
fn boot_error_carries_ex_config78_across_all_kinds() {
    assert_eq!(EX_CONFIG, 78);
    let cfg_err = config::parse_config_document("bogus").unwrap_err();
    assert_eq!(BootError::Config(cfg_err).exit_status(), EX_CONFIG);
    let invalid_resolver = config::parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"not-an-address\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n",
        )
        .unwrap_err();
    assert_eq!(BootError::Config(invalid_resolver).exit_status(), EX_CONFIG);
    let pre_err = PreflightError::Root;
    assert_eq!(BootError::Preflight(pre_err).exit_status(), EX_CONFIG);
}

#[test]
fn boot_allocation_failure_maps_to_ex_config78() {
    let dir = TempDir::new("allocfault");
    let config_path = dir
        .path()
        .join("config.toml")
        .to_string_lossy()
        .into_owned();
    dir.write("config.toml", VALID_CONFIG);

    crate::inventory::arm_alloc_failure();
    let err = run_boot_with_facts(&config_path, good_facts())
        .expect_err("armed allocation fault must fail boot with StorageUnavailable");
    crate::inventory::clear_alloc_failure();
    assert!(matches!(err, BootError::Storage(_)));
    assert_eq!(err.exit_status(), EX_CONFIG);
}

fn boot_report_for(config_body: &str) -> BootReport {
    let dir = TempDir::new("resolver-warning");
    let config_path = dir
        .path()
        .join("config.toml")
        .to_string_lossy()
        .into_owned();
    dir.write("config.toml", config_body);
    run_boot_with_facts(&config_path, good_facts()).expect("boot succeeds")
}

#[test]
fn ip_only_resolver_streams_one_startup_warning() {
    let report = boot_report_for(VALID_CONFIG);
    let warnings: Vec<_> = report.ip_only_resolvers().collect();
    assert_eq!(warnings.len(), 1, "one IP-only resolver");
    assert_eq!(warnings[0].addr().to_string(), "1.1.1.1");
    assert_eq!(warnings[0].port(), 53);
}

#[test]
fn fqdn_carried_resolver_streams_no_startup_warning() {
    let report = boot_report_for(FQDN_CONFIG);
    assert_eq!(
        report.ip_only_resolvers().count(),
        0,
        "IP#fqdn entry is the golden path: no startup warning"
    );
    assert!(
        report
            .config
            .resolver_set()
            .primary()
            .fqdn()
            .is_some_and(|f| f.as_str() == "dns.google")
    );
}

#[test]
fn unpinned_fqdn_resolver_streams_one_dot_warning() {
    let report = boot_report_for(FQDN_CONFIG);
    let warnings: Vec<_> = report.unpinned_dot_resolvers().collect();
    assert_eq!(warnings.len(), 1, "one unpinned DoT resolver");
    assert_eq!(warnings[0].addr().to_string(), "1.1.1.1");
    assert_eq!(warnings[0].port(), 853);
    assert!(
        warnings[0]
            .fqdn()
            .is_some_and(|f| f.as_str() == "dns.google")
    );
    assert!(warnings[0].pin().is_none());
}

#[test]
fn pinned_resolver_streams_no_dot_warning() {
    let report = boot_report_for(PINNED_CONFIG);
    assert_eq!(
        report.unpinned_dot_resolvers().count(),
        0,
        "pinned IP#fqdn#pin-sha256= entry is usable immediately: no warning"
    );
    assert!(report.config.resolver_set().primary().pin().is_some());
}

#[test]
fn bare_ip_resolver_streams_no_dot_warning() {
    let report = boot_report_for(VALID_CONFIG);
    assert_eq!(
        report.unpinned_dot_resolvers().count(),
        0,
        "bare-IP entry has no FQDN, so it is not an unpinned DoT entry"
    );
}
