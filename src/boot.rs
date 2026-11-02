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
    /// `port 53`) but cannot be `SNI`/`SAN`-authenticated for the `DoT`
    /// handshake (`port 853`, V1); the binary renders each as one stderr
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
    /// binary renders each as one stderr startup warning line so the
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
mod tests;
