use std::fmt;

use crate::config::{self, Config, ConfigError};
use crate::inventory::{self, BootInventory, StorageUnavailable, TrafficStorage};
use crate::preflight::{self, KernelFacts, PreflightError};

pub const EX_CONFIG: i32 = 78;

#[derive(Debug)]
pub enum BootError {
    Config(ConfigError),
    Preflight(PreflightError),
    Storage(StorageUnavailable),
}

impl BootError {
    #[must_use]
    pub const fn exit_status(&self) -> i32 {
        EX_CONFIG
    }
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::Config(err) => write!(f, "{err}"),
            BootError::Preflight(err) => write!(f, "{err}"),
            BootError::Storage(err) => write!(f, "{err}"),
        }
    }
}

#[derive(Debug)]
pub struct BootReport {
    pub config: Config,
    pub storage: TrafficStorage,
    pub inventory: BootInventory,
}

impl BootReport {
    /// Every configured resolver entry that carries no `IP#fqdn` FQDN
    /// metadata. IP-only resolvers remain valid and usable (plain DNS over
    /// `port 53`) but cannot be `SNI`/`SAN`-authenticated for the future `DoT`
    /// handshake (`port 853`, V1); the binary renders each as one stdout
    /// startup warning line.
    pub fn ip_only_resolvers(&self) -> impl Iterator<Item = &crate::resolver::Nameserver> + '_ {
        self.config
            .resolver_set()
            .iter()
            .filter(|ns| ns.fqdn().is_none())
    }

    /// Every configured resolver entry that carries `IP#fqdn` FQDN metadata but
    /// no strict `#pin-sha256=` SPKI pin. Such an entry dials `DoT` (port 853)
    /// and validates its chain against an empty root store, so its handshake
    /// deterministically fails closed until a trust-anchor intake lands; the
    /// binary renders each as one stdout startup warning line so the
    /// misconfiguration is visible at boot rather than as silent permanent
    /// degradation.
    pub fn unpinned_dot_resolvers(
        &self,
    ) -> impl Iterator<Item = &crate::resolver::Nameserver> + '_ {
        self.config
            .resolver_set()
            .iter()
            .filter(|ns| ns.fqdn().is_some() && ns.pin().is_none())
    }
}

/// Runs the complete boot sequence: kernel preflight, configuration load, and
/// traffic-storage allocation. The resolver set is read from the validated
/// config document; no separate platform resolver file is read.
///
/// # Errors
///
/// Returns `Preflight` when a hosting prerequisite fails, `Config` when the
/// configuration document is unreadable, invalid, or carries an invalid
/// resolver set, or `Storage` when traffic storage cannot be allocated.
pub fn run_boot(config_path: &str) -> Result<BootReport, BootError> {
    let facts = preflight::read_kernel_facts().map_err(BootError::Preflight)?;
    run_boot_with_facts(config_path, facts)
}

fn run_boot_with_facts(config_path: &str, facts: KernelFacts) -> Result<BootReport, BootError> {
    preflight::check(facts).map_err(BootError::Preflight)?;
    let config = config::load_config_document(config_path).map_err(BootError::Config)?;
    let storage = TrafficStorage::allocate().map_err(BootError::Storage)?;
    let inventory = inventory::BootInventory::phase1();
    Ok(BootReport {
        config,
        storage,
        inventory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process;

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

    const VALID_CONFIG: &str = "allowlist = [\"example.com:443\", \"sub.example.org.:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\", \"flare_only\"]\nscope = [\"connection\", \"connection\"]\n";

    const FQDN_CONFIG: &str = "allowlist = [\"example.com:443\", \"sub.example.org.:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1#dns.google\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\", \"flare_only\"]\nscope = [\"connection\", \"connection\"]\n";

    const PINNED_CONFIG: &str = "allowlist = [\"example.com:443\", \"sub.example.org.:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1#dns.google#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\", \"flare_only\"]\nscope = [\"connection\", \"connection\"]\n";

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
            "allowlist = [\"a.example:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"not-an-address\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n",
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
}
