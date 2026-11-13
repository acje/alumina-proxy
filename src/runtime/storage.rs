//! Boot-owned serving storage and the canonical startup-readiness rule.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use mio::net::TcpListener;

use crate::config::{ALLOWLIST_MAX, Config, Fqdn};
use crate::dns::cache::grade_key::{EntryGradeKey, EntryGradeMarker, FamilySnapshot};
use crate::dns::cache::{Cache, CacheError, Family, NameIndex};
use crate::dns::incident_report::{
    ClosedWindow, EligibleTransition, IncidentReport, IncidentSnapshot, SummaryCache,
};
use crate::dns::resolver::MAX_RESOLVERS;
use crate::dns::schedule::Schedules;
use crate::dns::transport::{
    EXCHANGE_DEADLINE_SECS, ExchangeClass, FailureReason, IncidentNote, ProbeVerdict,
    PublishedKind, STARTUP_WINDOW_SECS, StartupDns, StartupDnsError, StartupReport, TurnResult,
};
#[cfg(test)]
use crate::enforcement::action::DomainOrdinal;
use crate::enforcement::monitor::DnsAnomalyKind;
use crate::enforcement::state::Enforcement;
use crate::inspection::connect::ConnectRequest;
use crate::log::{Level, LogStore, ResolverProbeSegment, StartupStatus};
#[cfg(test)]
use crate::names::hostname::FixedHostname;
use crate::runtime::tunnel::{
    AdmissionError, AttemptLedger, ConnectPhase, Deadline, DecideError, ResolvedRequest, SlotIndex,
    TunnelIndex, Worker, WorkerClock, WorkerView,
};

/// The explicit far-future boundary for [`ServeStorage::schedule_due_instant`].
/// A schedule due beyond `now0 + this many seconds` is clamped to this
/// boundary instead of collapsing to the current instant, so an extreme or
/// overflowing due can never wake the serving loop spuriously early
/// (alumina-sechd I19). Ten years is far beyond any refresh interval and is
/// always representable on every supported platform.
const SCHEDULE_FAR_FUTURE_SECS: u64 = 365 * 24 * 60 * 60 * 10;

/// Bound on startup drain turns, unchanged by the assurance burst. A decision
/// attempts at most 32 assurance records, 32 unresolved-name records and one
/// summary. Each [`LogStore::drain_sink`] turn retains its existing operation
/// and byte budgets. A blocked or failed sink stops the loop early; a serving
/// decision retains residue, while an exit decision counts it as stranded.
const STARTUP_DRAIN_TURNS: usize = 6;

/// The retained serving storage initialized once before the postboot phase.
/// One worker owns the cache, refresh schedules, and the single DNS transport
/// with its fixed response workspace, plus the fixed tunnel-slot lifecycle and
/// the single clock authority (precise deadline anchor + DNS whole-second
/// epoch) — none of it is constructed per connection or per tunnel. Traffic
/// buffers are boot-owned separately. [`ServeStorage::boot`] is the only
/// construction path, binding the cache size and allowance to one validated
/// allowlist, and [`Self::work_view`] is the only seam that pairs that config
/// and cache for a CONNECT decision.
pub struct ServeStorage {
    cache: Cache,
    schedules: Schedules,
    dns: StartupDns,
    config: Config,
    worker: Worker,
    enforcement: Enforcement,
    origin: Instant,
    now0: u64,
    logs: LogStore,
    /// The per-name DNS incident reporting surface (docs/alumina-proxy.md:79-81):
    /// window state, per-type counters, tunnel-activity slot markers, and
    /// eligible-binding transition tracking, all preallocated at boot.
    incident_report: IncidentReport,
    /// The record family of the outstanding cooperative exchange, captured at
    /// [`Self::start_dns_exchange`] and read before the exchange settles so a
    /// failure or positive publish is attributed to the exact family attempted.
    /// `None` while no serving exchange is in progress.
    active_exchange_family: Option<Family>,
    assurance: [Option<AssuranceState>; ALLOWLIST_MAX],
    assurance_clock: Option<AssuranceClock>,
}

pub(crate) struct AssuranceSnapshot {
    fqdn: Fqdn,
    families: [FamilySnapshot; 2],
    secs: u64,
    boot: Option<AssuranceBoot>,
    key: EntryGradeKey,
}

#[derive(Clone, Copy)]
struct AssuranceState {
    marker: EntryGradeMarker,
    sequence: u64,
}

#[derive(Clone, Copy)]
struct AssuranceClock {
    boot: Instant,
    last: Instant,
    boot_elapsed_secs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssuranceObservation {
    Unchanged,
    Attempted { sequence: u64, enqueued: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssuranceObservationError {
    Cache(CacheError),
    Unseeded,
    BeforeStartup,
    ClockRegressed,
    ClockMismatch,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AssuranceWakeFault {
    ordinal: usize,
    error: AssuranceObservationError,
}

impl AssuranceObservationError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cache(CacheError::NameOutOfRange) => "name_out_of_range",
            Self::Cache(CacheError::BindingCapacityExceeded) => "binding_capacity",
            Self::Cache(CacheError::FamilyMismatch) => "family_mismatch",
            Self::Cache(CacheError::GenerationExhausted) => "generation_exhausted",
            Self::Cache(CacheError::StaleGeneration) => "stale_generation",
            Self::Cache(CacheError::DeadlineOverflow) => "deadline_overflow",
            Self::Cache(CacheError::EvidenceInconsistent) => "evidence_inconsistent",
            Self::Cache(CacheError::InsufficientAssurance) => "insufficient_assurance",
            Self::Unseeded => "unseeded",
            Self::BeforeStartup => "before_startup",
            Self::ClockRegressed => "clock_regressed",
            Self::ClockMismatch => "clock_mismatch",
        }
    }
}

struct AssuranceView<'a> {
    config: &'a Config,
    origin: Instant,
    now0: u64,
    states: &'a mut [Option<AssuranceState>; ALLOWLIST_MAX],
    clock: &'a mut Option<AssuranceClock>,
    logs: &'a mut LogStore,
}

impl AssuranceView<'_> {
    fn observe(
        &mut self,
        cache: &Cache,
        ordinal: usize,
        name: NameIndex,
        secs: u64,
        now: Instant,
    ) -> Result<AssuranceObservation, AssuranceObservationError> {
        if self.config.allowlist().get(ordinal).is_none() || cache.name_index(ordinal) != Some(name)
        {
            return Err(AssuranceObservationError::Cache(CacheError::NameOutOfRange));
        }
        let state = self
            .states
            .get_mut(ordinal)
            .and_then(Option::as_mut)
            .ok_or(AssuranceObservationError::Unseeded)?;
        let clock = self
            .clock
            .as_mut()
            .ok_or(AssuranceObservationError::Unseeded)?;
        let Some(elapsed) = now.checked_duration_since(self.origin) else {
            return Err(AssuranceObservationError::BeforeStartup);
        };
        if now < clock.boot || elapsed.as_secs() < clock.boot_elapsed_secs {
            return Err(AssuranceObservationError::BeforeStartup);
        }
        if now < clock.last {
            return Err(AssuranceObservationError::ClockRegressed);
        }
        if self.now0.saturating_add(elapsed.as_secs()) != secs {
            return Err(AssuranceObservationError::ClockMismatch);
        }
        let snapshot = capture_assurance_from(self.config, cache, ordinal, secs)
            .map_err(AssuranceObservationError::Cache)?;
        clock.last = now;
        if !state.marker.observe(snapshot.key) {
            return Ok(AssuranceObservation::Unchanged);
        }
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        let enqueued =
            self.logs
                .enqueue_assurance(&snapshot, sequence, crate::log::AssurancePhase::Change);
        Ok(AssuranceObservation::Attempted { sequence, enqueued })
    }
}

fn capture_assurance_from(
    config: &Config,
    cache: &Cache,
    ordinal: usize,
    secs: u64,
) -> Result<AssuranceSnapshot, CacheError> {
    let fqdn = config
        .allowlist()
        .get(ordinal)
        .ok_or(CacheError::NameOutOfRange)?;
    let name = cache
        .name_index(ordinal)
        .ok_or(CacheError::NameOutOfRange)?;
    Ok(AssuranceSnapshot {
        fqdn: fqdn.clone(),
        families: [
            cache.family_snapshot(name, Family::A, secs)?,
            cache.family_snapshot(name, Family::Aaaa, secs)?,
        ],
        secs,
        boot: None,
        key: cache.grade_key(name, secs)?,
    })
}

#[derive(Clone, Copy)]
pub(crate) struct AssuranceBoot {
    pub(crate) status: StartupStatus,
    pub(crate) attempted: [bool; 2],
    pub(crate) results: [Option<Result<PublishedKind, FailureReason>>; 2],
}

impl AssuranceSnapshot {
    pub(crate) const fn fqdn(&self) -> &Fqdn {
        &self.fqdn
    }

    pub(crate) const fn secs(&self) -> u64 {
        self.secs
    }

    pub(crate) const fn boot(&self) -> Option<AssuranceBoot> {
        self.boot
    }

    pub(crate) const fn family(&self, family: Family) -> &FamilySnapshot {
        match family {
            Family::A => &self.families[0],
            Family::Aaaa => &self.families[1],
        }
    }
}

/// How serving begins when the startup window closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingMode {
    /// Every configured name is usable.
    Full,
    /// At least one name is unresolved and within the configured allowance.
    Degraded,
}

/// The terminal startup-readiness decision from the canonical rule
/// (docs/alumina-proxy.md:65): open the listener when the unresolved count is at most the
/// configured allowance, else exit with status 75; a first-observed SIGTERM
/// short-circuits the window as [`Self::Terminated`], which never binds or
/// attaches a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupDecision {
    Serve(ServingMode),
    Exit75 { unresolved: u32 },
    Terminated,
}

impl StartupDecision {
    const fn status(self) -> StartupStatus {
        match self {
            Self::Serve(ServingMode::Full) => StartupStatus::Full,
            Self::Serve(ServingMode::Degraded) => StartupStatus::Degraded,
            Self::Exit75 { .. } => StartupStatus::Failed,
            Self::Terminated => StartupStatus::Terminated,
        }
    }
}

/// The outcome of the boot-owned startup window: the listener-carrying
/// startup state and the single DNS-window exchange report. The bound
/// listener lives only inside the [`StartupState::Serve`] arm.
pub struct StartupOutcome {
    /// The startup state for the window. A serving arm carries the bound
    /// CONNECT listener; exit-75 and terminated arms carry none.
    pub state: StartupState,
    /// The single DNS-window exchange report: the canonical counts
    /// and the per-name outcome set of the startup window.
    pub report: StartupReport,
}

/// A fatal startup failure: a DNS transport/storage error, a readiness
/// evaluation error, or a listener bind failure. Counted per-exchange network
/// failures never abort resolution and are carried by [`StartupReport`]
/// instead.
#[derive(Debug)]
pub enum StartupError {
    Dns(StartupDnsError),
    Cache(CacheError),
    Listener {
        kind: io::ErrorKind,
        detail: &'static str,
    },
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Dns(err) => write!(f, "startup: {err}"),
            StartupError::Cache(err) => write!(f, "startup readiness: {err}"),
            StartupError::Listener { kind, detail } => {
                write!(f, "startup listener ({detail}): {kind}")
            }
        }
    }
}

impl From<StartupDnsError> for StartupError {
    fn from(err: StartupDnsError) -> Self {
        StartupError::Dns(err)
    }
}

impl From<CacheError> for StartupError {
    fn from(err: CacheError) -> Self {
        StartupError::Cache(err)
    }
}

impl ServeStorage {
    /// Constructs the boot-owned cache, schedules, worker, and DNS transport
    /// over a parsed allowlist, capturing the single process-clock origin at
    /// boot. All retained serving state is allocated here, before the startup
    /// DNS window opens; the config is the sole allowance and listener
    /// authority for the life of the storage, and the worker's clock is
    /// re-anchored to the DNS window's exact origin and epoch when the window
    /// runs ([`Self::run_startup`]).
    ///
    /// # Errors
    ///
    /// Returns the underlying storage error when the cache, schedules, or DNS
    /// poll registry cannot be created.
    pub fn boot(config: &Config) -> Result<ServeStorage, StartupDnsError> {
        let name_count = config.allowlist().len();
        let logs = LogStore::new().map_err(StartupDnsError::from)?;
        let cache = Cache::for_config(config).map_err(StartupDnsError::from)?;
        let schedules = Schedules::new(name_count).map_err(StartupDnsError::from)?;
        let mut dns = StartupDns::new()?;
        dns.configure_bailiwick(config)?;
        let origin = Instant::now();
        let worker = Worker::boot(WorkerClock::new(origin, 0));
        let enforcement = Enforcement::new(*config.control(), config.gates());
        Ok(ServeStorage {
            cache,
            schedules,
            dns,
            config: config.clone(),
            worker,
            enforcement,
            origin,
            now0: 0,
            logs,
            incident_report: IncidentReport::new(),
            active_exchange_family: None,
            assurance: [None; ALLOWLIST_MAX],
            assurance_clock: None,
        })
    }

    /// The single owned config/cache/clock view used for CONNECT decisions: a
    /// [`crate::runtime::tunnel::WorkerView`] bound to this storage's own config, cache,
    /// and clock authority, so no code can pair an unrelated config or clock
    /// with this cache (1cws M4r/M2r; destination-binding, docs/alumina-proxy.md:145).
    #[must_use]
    pub const fn work_view(&self) -> WorkerView<'_> {
        WorkerView::new(&self.config, &self.cache, self.worker.clock())
    }

    #[cfg(test)]
    pub(crate) fn capture_assurance(
        &self,
        ordinal: usize,
        now: Instant,
    ) -> Result<AssuranceSnapshot, CacheError> {
        let secs = self.cache_secs(now);
        self.capture_assurance_secs(ordinal, secs)
    }

    fn capture_assurance_secs(
        &self,
        ordinal: usize,
        secs: u64,
    ) -> Result<AssuranceSnapshot, CacheError> {
        capture_assurance_from(&self.config, &self.cache, ordinal, secs)
    }

    #[cfg(test)]
    pub(crate) fn emit_assurance(
        &mut self,
        ordinal: usize,
        now: Instant,
    ) -> Result<AssuranceObservation, AssuranceObservationError> {
        let secs = self.cache_secs(now);
        let name = self
            .cache
            .name_index(ordinal)
            .ok_or(AssuranceObservationError::Cache(CacheError::NameOutOfRange))?;
        let mut view = AssuranceView {
            config: &self.config,
            origin: self.origin,
            now0: self.now0,
            states: &mut self.assurance,
            clock: &mut self.assurance_clock,
            logs: &mut self.logs,
        };
        view.observe(&self.cache, ordinal, name, secs, now)
    }

    /// The whole-second DNS/cache serving clock, mounted on the same origin
    /// and epoch the startup window wrote receipts on: `now0` plus whole
    /// seconds since the window origin. The single origin+offset continuity
    /// that keeps cache freshness comparable in serving (1cws M2r).
    pub(crate) fn cache_secs(&self, now: Instant) -> u64 {
        self.now0
            .saturating_add(now.saturating_duration_since(self.origin).as_secs())
    }

    pub(crate) fn assurance_wake(
        &self,
        now: Instant,
    ) -> Result<Option<Instant>, AssuranceWakeFault> {
        let Some(first) = self.assurance.iter().position(Option::is_some) else {
            return Ok(None);
        };
        let fault = |error| AssuranceWakeFault {
            ordinal: first,
            error,
        };
        let clock = self
            .assurance_clock
            .ok_or_else(|| fault(AssuranceObservationError::Unseeded))?;
        let elapsed = now
            .checked_duration_since(self.origin)
            .ok_or_else(|| fault(AssuranceObservationError::BeforeStartup))?;
        if now < clock.boot || elapsed.as_secs() < clock.boot_elapsed_secs {
            return Err(fault(AssuranceObservationError::BeforeStartup));
        }
        if now < clock.last {
            return Err(fault(AssuranceObservationError::ClockRegressed));
        }
        let secs = self.now0.saturating_add(elapsed.as_secs());
        let mut earliest: Option<Instant> = None;
        for ordinal in 0..self.config.allowlist().len() {
            let Some(state) = self.assurance[ordinal] else {
                continue;
            };
            let fault = |error| AssuranceWakeFault {
                ordinal,
                error: AssuranceObservationError::Cache(error),
            };
            let name = self
                .cache
                .name_index(ordinal)
                .ok_or_else(|| fault(CacheError::NameOutOfRange))?;
            for family in Family::ALL {
                let Some(deadline) = self
                    .cache
                    .retained_evidential_deadline(name, family)
                    .map_err(fault)?
                else {
                    continue;
                };
                let observed_secs = secs.max(deadline);
                let mut preview = state.marker;
                if !preview.observe(self.cache.grade_key(name, observed_secs).map_err(fault)?) {
                    continue;
                }
                let wake = if deadline <= secs {
                    now
                } else {
                    let offset = deadline
                        .checked_sub(self.now0)
                        .ok_or_else(|| fault(CacheError::DeadlineOverflow))?;
                    self.origin
                        .checked_add(Duration::from_secs(offset))
                        .ok_or_else(|| fault(CacheError::DeadlineOverflow))?
                };
                earliest = Some(earliest.map_or(wake, |current| current.min(wake)));
            }
        }
        Ok(earliest)
    }

    pub(crate) fn report_assurance_wake_fault(&mut self, now: Instant, fault: AssuranceWakeFault) {
        let secs = self.cache_secs(now);
        self.logs
            .dns_assurance_fault(secs, fault.ordinal, "expiry", fault.error.as_str());
    }

    pub(crate) fn observe_assurance_expiry(&mut self, now: Instant) {
        let secs = self.cache_secs(now);
        let mut view = AssuranceView {
            config: &self.config,
            origin: self.origin,
            now0: self.now0,
            states: &mut self.assurance,
            clock: &mut self.assurance_clock,
            logs: &mut self.logs,
        };
        for ordinal in 0..self.config.allowlist().len() {
            if view.states[ordinal].is_none() {
                continue;
            }
            let result = self
                .cache
                .name_index(ordinal)
                .ok_or(AssuranceObservationError::Cache(CacheError::NameOutOfRange))
                .and_then(|name| view.observe(&self.cache, ordinal, name, secs, now));
            if let Err(error) = result {
                view.logs
                    .dns_assurance_fault(secs, ordinal, "expiry", error.as_str());
            }
        }
    }

    /// The absolute wall instant at which a due whole-second schedule value
    /// fires, relative to the mounted clock origin. A due beyond the
    /// documented far-future boundary is clamped to that boundary rather than
    /// collapsing to "now", so an extreme or overflowing schedule never wakes
    /// the loop spuriously early (alumina-sechd I19).
    pub(crate) fn schedule_due_instant(&self, due: u64) -> Instant {
        let secs = due.saturating_sub(self.now0).min(SCHEDULE_FAR_FUTURE_SECS);
        self.origin + Duration::from_secs(secs)
    }

    /// The absolute wake moment a shared owner folds for one due serving
    /// refresh, projected purely on the serving clock and schedule with no
    /// mutation and no transport lease. `None` while an exchange is already
    /// in flight (its own deadline already bounds the wait, and the owner
    /// folds [`Self::dns`]'s exchange deadline separately), or when no slot
    /// is currently selectable — nothing scheduled, or only a consumed
    /// pending slot. Otherwise the mapped instant: an overdue due wakes
    /// `now` directly, or after the bounded 100 ms anti-spin floor while the
    /// post-boot probing sweep is active or the caller is suspended; a
    /// future due always maps exactly, even under sweep or suspension, so a
    /// suspended owner still wakes when the refresh becomes due.
    pub(crate) fn refresh_wake(&self, now: Instant, overdue_suspended: bool) -> Option<Instant> {
        if self.dns.has_active_exchange() {
            return None;
        }
        let due = self.schedules.next_selectable_due(self.cache_secs(now))?;
        let wake = self.schedule_due_instant(due);
        if wake <= now {
            if self.dns.sweep_active() || overdue_suspended {
                Some(now + Duration::from_millis(100))
            } else {
                Some(now)
            }
        } else {
            Some(wake)
        }
    }

    /// Re-anchors the retained worker and cache-seconds authority to the exact
    /// origin and DNS epoch a startup window (or a test) establishes. Called
    /// by [`Self::run_startup_within`] after `resolve_window` so serving
    /// keeps the window's own elapsed base.
    pub(crate) const fn mount_clock(&mut self, origin: Instant, now0: u64) {
        self.origin = origin;
        self.now0 = now0;
        self.worker.set_clock(WorkerClock::new(origin, now0));
    }

    /// The retained cache, read-only.
    #[must_use]
    pub const fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Test-only mutable cache handle, so a real-runtime regression can
    /// advance the other family's generation after an actual start.
    #[cfg(all(test, feature = "alloc-witness"))]
    pub(crate) const fn cache_mut(&mut self) -> &mut Cache {
        &mut self.cache
    }

    /// The retained parsed configuration, read-only.
    pub(crate) const fn config(&self) -> &Config {
        &self.config
    }

    /// The retained refresh schedules, read-only.
    #[must_use]
    pub const fn schedules(&self) -> &Schedules {
        &self.schedules
    }

    /// The retained refresh schedules, mutable for the owner's startup
    /// selection and backoff bookkeeping.
    pub(crate) const fn schedules_mut(&mut self) -> &mut Schedules {
        &mut self.schedules
    }

    /// The retained DNS transport with its fixed response workspace.
    #[must_use]
    pub const fn dns(&self) -> &StartupDns {
        &self.dns
    }

    /// The retained DNS transport, mutable so the shared-readiness owner can
    /// run cooperative refresh turns on the single retained source.
    pub(crate) const fn dns_mut(&mut self) -> &mut StartupDns {
        &mut self.dns
    }

    /// The boot-owned log store, mutable for record emission and sink drains.
    pub(crate) const fn logs_mut(&mut self) -> &mut LogStore {
        &mut self.logs
    }

    /// The boot-owned log store, shared for next-drain scheduling.
    pub(crate) const fn logs(&self) -> &LogStore {
        &self.logs
    }

    /// The per-name incident reporting surface, mutable for the serving loop's
    /// window/activity/eligible-state recording.
    pub(crate) const fn incident_report_mut(&mut self) -> &mut IncidentReport {
        &mut self.incident_report
    }

    pub(crate) const fn enforcement(&self) -> &Enforcement {
        &self.enforcement
    }

    pub(crate) const fn enforcement_mut(&mut self) -> &mut Enforcement {
        &mut self.enforcement
    }

    /// The ordinal of a connection already authorized as the exact
    /// `<fqdn>:<port>` pair, derived from the slot's `approved` hostname and
    /// `approved_port` together. Enforcement attribution (early-data
    /// Block-Domain, the domain sweep, JA4 baselines) must key on the pair, so
    /// a same-hostname different-port allowlist entry gets its own ordinal and
    /// a configured Block on one port can never over-close or under-close the
    /// other (alumina-9t6w B1). Shares the single allowlist-pair predicate with
    /// the worker decision (alumina-sechd L14).
    #[cfg(test)]
    pub(crate) fn ordinal_for_pair(
        &self,
        hostname: &FixedHostname,
        port: u16,
    ) -> Option<DomainOrdinal> {
        let index = self.config.allowlist_position(hostname.as_str(), port)?;
        self.enforcement.control().ordinal(index)
    }

    #[cfg(test)]
    pub(crate) fn publish_test_a(&mut self, ordinal: usize) {
        use crate::dns::cache::{Generation, StagedPositive};
        use crate::eligibility::NumericAddr;
        use std::net::Ipv4Addr;
        let name = self
            .cache
            .name_index(ordinal)
            .expect("admitted name ordinal");
        let addrs = [NumericAddr::V4(Ipv4Addr::from([1, 1, 1, 1]))];
        let staged = StagedPositive::stage(name, Family::A, Generation::INITIAL, &addrs, 1_000, 10)
            .expect("stage A binding");
        self.cache
            .publish_positive(&staged)
            .expect("publish A binding");
    }

    #[cfg(test)]
    pub(crate) fn publish_test_addr(
        &mut self,
        ordinal: usize,
        addr: crate::eligibility::NumericAddr,
        family: Family,
    ) {
        use crate::dns::cache::{Generation, StagedPositive};
        let name = self
            .cache
            .name_index(ordinal)
            .expect("admitted name ordinal");
        let receipt = self.cache_secs(Instant::now());
        let staged =
            StagedPositive::stage(name, family, Generation::INITIAL, &[addr], receipt, 600)
                .expect("stage binding");
        self.cache
            .publish_positive(&staged)
            .expect("publish binding");
    }

    /// Whole-record log drops so far, saturating at `u64::MAX`: the
    /// documented dropped-record metric (docs/alumina-proxy.md:193).
    #[must_use]
    pub const fn log_dropped(&self) -> u64 {
        self.logs.dropped()
    }

    /// Arms the production stdout sink (fd 1 nonblocking). The binary calls
    /// this once after boot, before any serving stdout write; the library and
    /// tests never flip the descriptor (H2).
    ///
    /// # Errors
    ///
    /// Returns the log-store error, wrapped as `StartupDnsError`, when fd 1
    /// cannot be switched to nonblocking or otherwise armed for the sink.
    pub fn prepare_stdout_log_sink(&mut self) -> Result<(), StartupDnsError> {
        self.logs.prepare_stdout().map_err(StartupDnsError::from)
    }

    /// Emits one stdout-only fatal record and performs one bounded drain, then
    /// lets the process exit: the only post-sink-switch channel for a
    /// process-fatal failure, so an attach/serve/listener failure never blocks
    /// on a separate stalled stderr descriptor (docs/alumina-proxy.md:149, B1). The
    /// message is formatted directly into the fixed slot, so a fatal path
    /// performs no heap allocation beyond what the slot itself already owns.
    ///
    /// The drain is best-effort under the per-turn sink budget; a stalled or
    /// closed stdout never delays the exit verdict.
    pub fn emit_fatal_and_drain(&mut self, args: std::fmt::Arguments<'_>) {
        let secs = self.cache_secs(Instant::now());
        self.logs.fatal(secs, args);
        self.logs.drain_sink();
    }

    pub(crate) fn report_monitor_if_due(&mut self, now: Instant, force: bool) -> bool {
        let secs = self.cache_secs(now);
        let due = force || self.enforcement.monitor_due(secs);
        if !due {
            return false;
        }
        {
            let monitor = self.enforcement.monitor_mut();
            self.logs.monitor_summary(secs, monitor);
        }
        if force {
            self.enforcement.mark_forced_monitor_reported();
        } else {
            self.enforcement.mark_monitor_reported(secs);
        }
        true
    }

    /// The per-family incident snapshot for one allowlist name, read from the
    /// schedule's current `TypeIncident` state: the opened-at second, latest
    /// failure reason, and the paired configured-resolver origin from the
    /// saved per-family failure table (never a live current-actor lookup) for
    /// each family currently in incident, `None` otherwise. Used to seed the
    /// incident report's sticky per-window snapshot when a window opens, so the
    /// closing summary reflects the window's actual incident activity even when
    /// the incident recovers at the boundary turn.
    fn incident_snapshot(&self, ordinal: usize) -> [IncidentSnapshot; 2] {
        let mut snap = [None, None];
        for (i, family) in Family::ALL.iter().copied().enumerate() {
            snap[i] = match self.schedules.incident(ordinal, family) {
                Some(crate::dns::schedule::TypeIncident::Open { opened_at, reason }) => {
                    let origin = self.dns.last_failure_origin(ordinal, family);
                    Some((opened_at, reason.as_str(), origin))
                }
                _ => None,
            };
        }
        snap
    }

    /// The per-turn incident reporting pass (docs/alumina-proxy.md:79-81): opens
    /// windows for names already in incident (including incidents opened before
    /// serving began), rotates every open window at its 3600-second boundary,
    /// drains closed-window error summaries, folds eligible-binding transitions
    /// into immediate error/info records, and closes the window on full
    /// hostname incident recovery with an info-level final partial summary.
    /// Best-effort under the log-drop policy; window counters reset at rotation
    /// even when enqueueing fails.
    pub(crate) fn report_incident_if_due(&mut self, now: Instant) {
        let secs = self.cache_secs(now);
        let name_count = self.config.allowlist().len();
        for ordinal in 0..name_count {
            let in_incident = Family::ALL.iter().any(|&family| {
                matches!(
                    self.schedules.incident(ordinal, family),
                    Some(crate::dns::schedule::TypeIncident::Open { .. })
                )
            });
            if in_incident {
                let snapshot = self.incident_snapshot(ordinal);
                self.incident_report
                    .note_incident_open(ordinal, secs, snapshot);
            }
        }
        self.incident_report.rotate_all_if_due(secs);
        for ordinal in 0..name_count {
            if let Some(closed) = self.incident_report.take_pending_summary(ordinal) {
                self.emit_incident_summary(ordinal, closed, Level::Error);
            }
        }
        for ordinal in 0..name_count {
            let Some(name_index) = self.cache.name_index(ordinal) else {
                continue;
            };
            let result = usable_name(&self.cache, name_index, secs);
            self.reconcile_incident_eligibility(ordinal, secs, result);
        }
        for ordinal in 0..name_count {
            let both_closed = Family::ALL.iter().all(|&family| {
                matches!(
                    self.schedules.incident(ordinal, family),
                    Some(crate::dns::schedule::TypeIncident::Closed)
                )
            });
            // L1: a full recovery coinciding with the boundary turn closes a
            // zero-duration partial window ([secs, secs)); its info summary is
            // vacuous (all counters 0, no meaningful partial window) and is
            // suppressed.
            if both_closed
                && let Some(closed) = self.incident_report.close_window(ordinal, secs)
                && closed.duration() > 0
            {
                self.emit_incident_summary(ordinal, closed, Level::Info);
            }
        }
    }

    fn reconcile_incident_eligibility(
        &mut self,
        ordinal: usize,
        secs: u64,
        result: Result<bool, CacheError>,
    ) {
        match result {
            Ok(has_eligible) => {
                if let Some(event) = self
                    .incident_report
                    .note_eligible_state(ordinal, has_eligible)
                {
                    self.emit_eligible(ordinal, secs, event);
                }
            }
            Err(error) => self.logs.dns_assurance_fault(
                secs,
                ordinal,
                "incident",
                AssuranceObservationError::Cache(error).as_str(),
            ),
        }
    }

    /// Emits one incident summary record for a closed window, after sampling
    /// the shared record second and folding the live cache facts
    /// (docs/alumina-proxy.md:80).
    fn emit_incident_summary(&mut self, ordinal: usize, closed: ClosedWindow, level: Level) {
        let Some(fqdn) = self.config.allowlist().get(ordinal) else {
            return;
        };
        let Some(name_index) = self.cache.name_index(ordinal) else {
            return;
        };
        let secs = self.cache_secs(Instant::now());
        let mut cache = [SummaryCache {
            addrs: 0,
            state: "empty",
            freshness: None,
            retirement: None,
        }; 2];
        for (i, family) in Family::ALL.iter().copied().enumerate() {
            let Ok(entry) = self.cache.entry(name_index, family) else {
                continue;
            };
            let (freshness, retirement) = entry.deadlines();
            cache[i] = SummaryCache {
                addrs: entry.bindings().len() as u64,
                state: entry.state(secs).as_str(),
                freshness,
                retirement,
            };
        }
        let summary = closed.to_summary(secs, cache);
        self.logs
            .incident_summary(secs, fqdn.as_str(), level, &summary);
    }

    /// Emits one typed eligible-binding transition record for a hostname:
    /// `Lost` is the immediate error when it loses its eligible bindings,
    /// `Recovered` the info when they return (docs/alumina-proxy.md:79).
    fn emit_eligible(&mut self, ordinal: usize, secs: u64, event: EligibleTransition) {
        if let Some(fqdn) = self.config.allowlist().get(ordinal) {
            self.logs.incident_eligible(secs, fqdn.as_str(), event);
        }
    }

    /// One cooperative DNS turn on the single retained transport: advances the
    /// outstanding exchange to its next phase when the shared owner has
    /// observed freshness or its deadline, folding the cache and refresh
    /// schedules into the existing subscription. Returns `None` while no
    /// exchange is in progress, so an idle owner treats it as no work rather
    /// than an error.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS exchange or transport error.
    pub(crate) fn advance_dns(&mut self) -> Result<Option<TurnResult>, StartupDnsError> {
        let Some(ordinal) = self.dns.active_ordinal() else {
            return Ok(None);
        };
        let family = self.active_exchange_family;
        let fqdn = self
            .config
            .allowlist()
            .get(ordinal)
            .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
        let mut view = AssuranceView {
            config: &self.config,
            origin: self.origin,
            now0: self.now0,
            states: &mut self.assurance,
            clock: &mut self.assurance_clock,
            logs: &mut self.logs,
        };
        let mut observer = |phase, cache: &Cache, name, secs, now| {
            if let Err(err) = view.observe(cache, ordinal, name, secs, now) {
                let phase = match phase {
                    crate::dns::ObservationPhase::BeforeCommit => "before",
                    crate::dns::ObservationPhase::AfterCommit => "after",
                };
                view.logs
                    .dns_assurance_fault(secs, ordinal, phase, err.as_str());
            }
        };
        let result = self.dns.advance_exchange_observed(
            fqdn,
            &mut self.cache,
            &mut self.schedules,
            &mut observer,
        )?;
        self.drain_common_six();
        self.drain_incident_notes();
        let secs = self.cache_secs(Instant::now());
        if let Some(family) = family {
            match &result {
                TurnResult::Failed(reason) => {
                    let origin = self.dns.last_failure_origin(ordinal, family);
                    self.incident_report.note_exchange_failure(
                        ordinal,
                        family,
                        secs,
                        reason.as_str(),
                        origin,
                    );
                }
                TurnResult::Published(PublishedKind::ResolvedPositive) => {
                    self.incident_report.note_positive(ordinal, family, secs);
                }
                _ => {}
            }
        }
        if !matches!(result, TurnResult::Pending) {
            self.active_exchange_family = None;
        }
        Ok(Some(result))
    }

    /// One serving-loop DNS turn: captures the per-event actor identity and
    /// resolver, advances through the shared [`Self::advance_dns`], and emits
    /// the per-failure `exchange_failed` record only when the advance settled
    /// as `Failed`.
    pub(crate) fn advance_dns_serving(&mut self) -> Result<Option<TurnResult>, StartupDnsError> {
        let identity = self.dns.active_identity();
        let resolver = self.dns.current_resolver_index();
        let result = self.advance_dns()?;
        if let Some(TurnResult::Failed(reason)) = &result {
            self.note_exchange_failed(identity, *reason, resolver);
        }
        Ok(result)
    }

    /// Emits the per-failure `exchange_failed` record for a counted
    /// serving-loop exchange failure, with the per-event resolver origin.
    fn note_exchange_failed(
        &mut self,
        identity: Option<(usize, Family)>,
        reason: FailureReason,
        resolver: Option<u8>,
    ) {
        let (name, origin) = match identity {
            Some((ordinal, _)) => (
                self.config.allowlist().get(ordinal).map(Fqdn::as_str),
                resolver,
            ),
            None => (None, None),
        };
        let secs = self.cache_secs(Instant::now());
        self.logs
            .exchange_failed(secs, name, reason.as_str(), origin);
    }

    /// The six ordered post-exchange monitor drains shared by the serving
    /// advance and the startup window: resolver crossings, DNS anomalies, the
    /// `DoT`-to-plain downgrade, probe relocations, expired pin certificates,
    /// and incident transitions, in the protocol order.
    fn drain_common_six(&mut self) {
        self.drain_resolver_transitions();
        self.drain_dns_anomalies();
        self.drain_downgrade_to_plain();
        self.drain_probe_relocations();
        self.drain_expired_pin_certs();
        self.drain_incident_transitions();
    }

    /// Folds any degraded-mode enter/exit crossings the DNS transport
    /// accumulated back into the enforcement monitor as distinct `rd` facts,
    /// one per crossing. The transport drains to zero, so a later drain never
    /// double-counts an earlier crossing.
    fn drain_resolver_transitions(&mut self) {
        let transitions = self.dns.take_resolver_transitions();
        for _ in 0..transitions {
            self.enforcement.note_fact_resolver_degraded();
        }
    }

    /// Folds every accumulated DNS anomaly the transport noted into the
    /// monitor anomaly surface, one fact per detection. The transport drains to
    /// zero, so a later drain never double-counts an earlier detection.
    fn drain_dns_anomalies(&mut self) {
        let anomalies = self.dns.take_dns_anomalies();
        for (index, count) in anomalies.iter().copied().enumerate() {
            let Some(kind) = DnsAnomalyKind::from_index(index) else {
                continue;
            };
            for _ in 0..count {
                self.enforcement.note_fact_dns_anomaly(kind);
            }
        }
    }

    /// Folds every DoT→plain downgrade relocation the DNS transport noted into
    /// the monitor `dp` fact, one fact per downgrade. The transport drains to
    /// zero, so a later drain never double-counts an earlier downgrade.
    fn drain_downgrade_to_plain(&mut self) {
        let downgrades = self.dns.take_downgrade_to_plain();
        for _ in 0..downgrades {
            self.enforcement.note_fact_downgrade_to_plain();
        }
    }

    /// Folds every post-window probe-sweep relocation the DNS transport noted
    /// into the monitor `pr` fact, one fact per relocation. The transport
    /// drains to zero, so a later drain never double-counts an earlier
    /// relocation.
    fn drain_probe_relocations(&mut self) {
        let relocations = self.dns.take_probe_relocations();
        for _ in 0..relocations {
            self.enforcement.note_fact_probe_relocation();
        }
    }

    /// Folds every pin-branch certificate outside its validity window the DNS
    /// transport noted into the monitor `ep` fact, one fact per certificate.
    /// The transport drains to zero, so a later drain never double-counts an
    /// earlier detection.
    fn drain_expired_pin_certs(&mut self) {
        let expired = self.dns.take_expired_pin_certs();
        for _ in 0..expired {
            self.enforcement.note_fact_expired_pin_cert();
        }
    }

    /// Folds the sustained-negative incident opens and closes the DNS transport
    /// accumulated into the monitor `sn=` level: each open raises the level by
    /// one, each close lowers it by one. The transport drains to zero, so a
    /// later drain never double-counts an earlier transition.
    fn drain_incident_transitions(&mut self) {
        let (opens, closes) = self.dns.take_incident_transitions();
        for _ in 0..opens {
            self.enforcement.note_incident_open();
        }
        for _ in 0..closes {
            self.enforcement.note_incident_close();
        }
    }

    /// Emits the per-type exchange-failure incident open and recovery records
    /// the DNS transport accumulated (docs/alumina-proxy.md:79): the allowlist
    /// FQDN is recovered from the ordinal captured before the exchange settled.
    /// Startup suppression already filtered the notes, so every note drained
    /// here is a serving incident. The transport drains to zero, so a later
    /// drain never re-emits an earlier note.
    fn drain_incident_notes(&mut self) {
        let secs = self.cache_secs(Instant::now());
        for note in self.dns.take_incident_notes() {
            let Some(note) = note else {
                continue;
            };
            let (ordinal, family) = match note {
                IncidentNote::Open {
                    ordinal, family, ..
                }
                | IncidentNote::Recovered {
                    ordinal, family, ..
                } => (ordinal, family),
            };
            let Some(fqdn) = self.config.allowlist().get(ordinal) else {
                continue;
            };
            match note {
                IncidentNote::Open {
                    reason, resolver, ..
                } => {
                    self.logs
                        .incident_open(secs, fqdn.as_str(), family, reason.as_str(), resolver);
                    let snapshot = self.incident_snapshot(ordinal);
                    self.incident_report
                        .note_incident_open(ordinal, secs, snapshot);
                }
                IncidentNote::Recovered {
                    duration, resolver, ..
                } => {
                    self.logs
                        .incident_recovered(secs, fqdn.as_str(), family, duration, resolver);
                }
            }
        }
    }

    /// Emits the single per-window `startup_warning` for the first counted
    /// exchange failure, looking the name up from the allowlist internally so
    /// a shared owner never holds a config borrow across a log mutation.
    pub(crate) fn startup_warning_first(
        &mut self,
        secs: u64,
        ordinal: usize,
        family: Family,
        reason: &'static str,
    ) {
        if let Some(name) = self.config.allowlist().get(ordinal) {
            let context = self
                .cache
                .name_index(ordinal)
                .and_then(|index| self.cache.negative_lease_flags(index, secs));
            self.logs
                .startup_warning_ctx(secs, name.as_str(), family, reason, context);
        }
    }

    /// Starts a cooperative DNS exchange on the retained transport for the
    /// named allowlist entry, dialing the currently active resolver. The
    /// exchange draws a fresh transaction id, records its class and deadline
    /// without waiting for network readiness; subsequent
    /// [`Self::advance_dns`] turns conclude it. The caller supplies the
    /// [`ExchangeClass`] so a serving refresh, a startup-window exchange, and a
    /// probe are each classified at start — a forgotten class is
    /// unrepresentable.
    ///
    /// # Errors
    ///
    /// Returns `ExchangeActive` when an exchange is already in progress and
    /// `Cache` when the ordinal is outside the allowlist.
    pub(crate) fn start_dns_exchange(
        &mut self,
        ordinal: usize,
        family: Family,
        deadline: Instant,
        class: ExchangeClass,
    ) -> Result<(), StartupDnsError> {
        let fqdn = self
            .config
            .allowlist()
            .get(ordinal)
            .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
        let name_index = self
            .cache
            .name_index(ordinal)
            .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
        let pair = self.cache.generations_before_query(name_index, family)?;
        self.active_exchange_family = Some(family);
        self.dns
            .start_exchange(fqdn, family, ordinal, deadline, pair, class)?;
        let secs = self.cache_secs(Instant::now());
        self.incident_report
            .note_exchange_attempt(ordinal, family, secs);
        Ok(())
    }

    /// Starts a due serving refresh when the retained DNS transport is idle:
    /// owned refresh admission. A refresh is suppressed while a post-window
    /// probe sweep owns the transport between probes — the sweep restores the
    /// pre-sweep active resolver after each probe, and an interleaved refresh
    /// would corrupt that restore (the suppression is bounded, at most
    /// `MAX_RESOLVERS − 1` probes at `EXCHANGE_DEADLINE_SECS` each, once at
    /// boot, latched by `sweep_ran`, so it can never starve refresh
    /// scheduling) — and while a serving exchange is already in flight. The
    /// clock sample is taken after those guards, exactly once, and a separate
    /// fresh exchange deadline is minted only after `select_due` returns a
    /// token, so selection failure leaves the due table untouched.
    ///
    /// # Errors
    ///
    /// Returns the typed [`StartupDnsError`]: a selection error
    /// (`ScheduleError::DeadlineOverflow` when the start-rate guard
    /// overflows) surfaces before any due-table mutation, leaving the
    /// schedule untouched. Once a token is selected, subsequent errors
    /// propagate from [`Self::start_dns_exchange`] without rolling the
    /// selection back: the `active_exchange_family` marker is set before the
    /// fallible DNS start and the attempt report is recorded only on success,
    /// while the resolution and cache lookups that precede the marker leave it
    /// untouched.
    fn start_due_serving_refresh(&mut self) -> Result<(), StartupDnsError> {
        if self.dns.sweep_active() || self.dns.has_active_exchange() {
            return Ok(());
        }
        let secs = self.dns.now_u64();
        let Some(selected) = self
            .schedules
            .select_due(secs)
            .map_err(StartupDnsError::from)?
        else {
            return Ok(());
        };
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        self.start_dns_exchange(
            selected.name(),
            selected.family(),
            deadline,
            ExchangeClass::Serving,
        )
    }

    /// Advances the post-window probe sweep one step on the retained transport:
    /// begins the sweep on the first call, starts the next probe once the
    /// previous concludes, and emits the single `resolver_probe` record when no
    /// unprobed resolver remains. The sweep never relocates a healthy active
    /// transport — the pre-sweep active resolver is restored after each probe —
    /// and is mutually exclusive with failback (docs/alumina-proxy.md:67).
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS exchange or transport error.
    fn step_sweep(&mut self) -> Result<(), StartupDnsError> {
        self.dns.maybe_begin_sweep();
        if !self.dns.sweep_active() || self.dns.has_active_exchange() {
            return Ok(());
        }
        let fqdn = self
            .config
            .allowlist()
            .get(0)
            .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
        if self.dns.sweep_next_probe(fqdn)? {
            let verdicts = self.dns.take_sweep_verdicts();
            self.emit_resolver_probe(verdicts);
        }
        Ok(())
    }

    /// Advances the bounded corroboration exchange one step on the retained
    /// transport: begins the single cross-check against a different configured
    /// resolver when a sustained-negative incident opened for an admitted name
    /// and the transport is idle. The corroboration is a pure-sensor probe that
    /// never mutates the cache or schedule; a conflict advances the active
    /// resolver's degradation and relocates a degraded active resolver, while a
    /// consistent negative restores it (alox18). Runs before refresh scheduling
    /// so the corroboration owns the transport between exchanges.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS exchange or transport error.
    fn step_corroboration(&mut self) -> Result<(), StartupDnsError> {
        if self.dns.has_active_exchange() {
            return Ok(());
        }
        let Some(ordinal) = self.dns.corroboration_pending_ordinal() else {
            return Ok(());
        };
        let fqdn = self
            .config
            .allowlist()
            .get(ordinal)
            .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
        self.dns.step_corroboration(fqdn)?;
        Ok(())
    }

    /// Emits the single `resolver_probe` record once the sweep concludes: one
    /// inline segment per configured resolver in index order, carrying its
    /// address and FQDN/pin presence plus the accumulated verdict. The record
    /// is written allocation-free into the fixed 2 KiB slot and drained once
    /// (docs/alumina-proxy.md:67).
    #[expect(
        clippy::expect_used,
        reason = "resolver index is below MAX_RESOLVERS=5, which fits u32"
    )]
    fn emit_resolver_probe(&mut self, verdicts: [ProbeVerdict; MAX_RESOLVERS]) {
        let Some(set) = self.dns.resolvers() else {
            return;
        };
        let secs = self.cache_secs(Instant::now());
        let mut segments = [ResolverProbeSegment {
            index: 0,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            fqdn: None,
            pin: false,
            verdict: ProbeVerdict::NotProbed,
        }; MAX_RESOLVERS];
        let mut count = 0usize;
        for (index, ns) in set.iter().enumerate() {
            segments[count] = ResolverProbeSegment {
                index: u32::try_from(index).expect("resolver index fits u32"),
                addr: ns.addr(),
                fqdn: ns.fqdn(),
                pin: ns.pin().is_some(),
                verdict: verdicts[index],
            };
            count += 1;
        }
        self.logs.resolver_probe(secs, &segments[..count]);
        self.logs.drain_sink();
    }

    /// Admits a new actual connection into a retained slot at the accept
    /// instant, capturing its absolute setup deadline and fixing the
    /// accept-reported `peer` on the pending setup. Slot lifecycle actions are
    /// private to actual accept/connect/close event processing.
    ///
    /// # Errors
    ///
    /// `SlotCapacity` or `PendingCapacity`, mapped to HTTP 503 + close
    /// (docs/alumina-proxy.md:193).
    pub(crate) fn accept(
        &mut self,
        now: Instant,
        peer: IpAddr,
    ) -> Result<SlotIndex, AdmissionError> {
        self.worker.admit(now, peer)
    }

    /// The single exact-pair resolution of an already-validated CONNECT for
    /// one decision: binds the request to the allowlist position computed once
    /// from this storage's config, so the serving block precheck, `decide`,
    /// peer freshness and report attribution all share one resolution
    /// (alumina-sechd L14). Decision-scoped and borrowing the caller's local
    /// request, never copying it. See [`ResolvedRequest`].
    pub(crate) fn resolve_request<'a>(
        &'a self,
        request: &'a ConnectRequest,
    ) -> ResolvedRequest<'a> {
        self.work_view().resolve(request)
    }

    /// The one owned CONNECT decision for an admitted slot: consumes the
    /// caller-minted `resolved` context and reads the setup deadline and the
    /// attempt ledger from the slot and cache seconds from this storage's
    /// clock authority. Does not consume the handle; the event processor still
    /// needs it to graduate or release.
    ///
    /// # Errors
    ///
    /// `NotInSetup` for a stale handle (unreachable by the handle discipline)
    /// or the underlying current-cache lookup error.
    pub(crate) fn decide(
        &self,
        slot: &SlotIndex,
        resolved: &ResolvedRequest<'_>,
        now: Instant,
    ) -> Result<ConnectPhase, DecideError> {
        self.worker.decide(slot, resolved, now)
    }

    /// Records one failed attempt on the granted in-setup slot, advancing its
    /// slot-carried attempt ledger. See [`crate::runtime::tunnel::Worker::record_attempt`].
    pub(crate) const fn record_attempt(
        &mut self,
        slot: &SlotIndex,
        family: Family,
    ) -> Result<AttemptLedger, DecideError> {
        self.worker.record_attempt(slot, family)
    }

    /// Graduates an admitted slot to established work once the successful
    /// CONNECT response completed, returning the established handle.
    pub(crate) fn finish_setup(&mut self, slot: SlotIndex) -> TunnelIndex {
        self.worker.finish_setup(slot)
    }

    /// Releases an in-setup slot, consuming its handle.
    pub(crate) fn release(&mut self, slot: SlotIndex) {
        self.worker.release(slot);
    }

    /// Releases an established tunnel, consuming its handle.
    pub(crate) fn release_tunnel(&mut self, tunnel: TunnelIndex) {
        self.worker.release_tunnel(tunnel);
    }

    /// The absolute setup deadline of an admitted slot.
    pub(crate) const fn setup_deadline(&self, slot: &SlotIndex) -> Option<Deadline> {
        self.worker.setup_deadline(slot)
    }

    /// The fixed slot index underlying an admitted handle, for the actual
    /// event processor to key its per-slot state.
    pub(crate) const fn slot_index(slot: &SlotIndex) -> usize {
        Worker::slot_index(slot)
    }

    /// Counts currently in setup, from the retained worker's slot states.
    pub(crate) const fn pending(&self) -> usize {
        self.worker.pending()
    }

    /// Counts currently occupied, from the retained worker's slot states.
    pub(crate) const fn occupied(&self) -> usize {
        self.worker.occupied()
    }

    /// Applies the canonical startup-readiness rule over the resolved cache:
    /// every admitted name is counted once as usable or unresolved; all usable
    /// is [`ServingMode::Full`], unresolved within the configured allowance is
    /// [`ServingMode::Degraded`], otherwise exit with status 75.
    ///
    /// # Errors
    ///
    /// Propagates `NameOutOfRange` from an entry lookup; names derived from
    /// `cache.name_index` within `cache.name_count()` are always admitted.
    pub fn startup_decision(&self, now: u64) -> Result<StartupDecision, CacheError> {
        let mut unresolved = 0u32;
        for ordinal in 0..self.cache.name_count() {
            let name = self
                .cache
                .name_index(ordinal)
                .ok_or(CacheError::NameOutOfRange)?;
            if !usable_name(&self.cache, name, now)? {
                unresolved += 1;
            }
        }
        if unresolved == 0 {
            Ok(StartupDecision::Serve(ServingMode::Full))
        } else if u64::from(unresolved) <= u64::from(self.config.startup_unresolved_allowance()) {
            Ok(StartupDecision::Serve(ServingMode::Degraded))
        } else {
            Ok(StartupDecision::Exit75 { unresolved })
        }
    }

    /// Runs the boot-owned startup DNS window with the production-fixed
    /// 90-second deadline and evaluates the canonical readiness rule once when
    /// it returns: every name usable (or a late retry succeeding) opens the
    /// listener early as [`ServingMode::Full`]; a return at the deadline with
    /// unresolved names decides [`ServingMode::Degraded`] or exit 75 from the
    /// final cache. The window is fixed here and never a public parameter;
    /// [`Self::run_startup_within`] is the only shortened-window path and it is
    /// crate-private for the loopback test seam.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS/readiness error, or `Listener` when
    /// the configured listen socket cannot be bound.
    pub fn run_startup(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
    ) -> Result<StartupOutcome, StartupError> {
        self.run_startup_within(nameserver, now0, Duration::from_secs(STARTUP_WINDOW_SECS))
    }

    /// The startup-window core shared by [`Self::run_startup`] and the
    /// crate's shortened-window loopback tests. The readiness decision is
    /// taken at the single window deadline this core owns, expressed in `now0`
    /// seconds plus the elapsed whole seconds since the window opened, so no
    /// second clock anchor decides the outcome.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS/readiness error, or `Listener` when
    /// the configured listen socket cannot be bound.
    pub(crate) fn run_startup_within(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<StartupOutcome, StartupError> {
        let (report, decision_seconds) = self.dns.resolve_window(
            crate::dns::transport::WindowInputs {
                config: &self.config,
                cache: &mut self.cache,
                schedules: &mut self.schedules,
                nameserver,
                now0,
                window,
            },
            &mut self.logs,
        )?;
        self.drain_common_six();
        self.settle_startup(now0, report, decision_seconds, false)
    }

    /// Mounts the window clock, applies the readiness decision (or the typed
    /// terminated outcome when the owner observed a first SIGTERM during the
    /// window), binds the listener only for a serving decision, and emits the
    /// startup `startup_name` / `startup_final` records. Shared by the blocking
    /// storage seam and the shared-owner window so both produce the identical
    /// typed report and listener rules.
    pub(crate) fn settle_startup(
        &mut self,
        now0: u64,
        report: StartupReport,
        decision_seconds: u64,
        terminated: bool,
    ) -> Result<StartupOutcome, StartupError> {
        self.mount_clock(self.dns.window_start(), now0);
        let secs = now0.saturating_add(decision_seconds);
        let decision = if terminated {
            StartupDecision::Terminated
        } else {
            self.startup_decision(secs)?
        };
        let state = match decision {
            StartupDecision::Serve(mode) => StartupState::Serve {
                mode,
                listener: self.bind_listener()?,
            },
            StartupDecision::Exit75 { unresolved } => StartupState::Exit75 { unresolved },
            StartupDecision::Terminated => StartupState::Terminated,
        };
        let status = decision.status();
        match status {
            StartupStatus::Terminated => {}
            StartupStatus::Full | StartupStatus::Degraded | StartupStatus::Failed => {
                let boot = Instant::now();
                self.assurance_clock = Some(AssuranceClock {
                    boot,
                    last: boot,
                    boot_elapsed_secs: decision_seconds,
                });
                for (ordinal, fqdn) in self.config.allowlist().iter().enumerate() {
                    let boot = AssuranceBoot {
                        status,
                        attempted: report.attempted[ordinal],
                        results: report.family_results[ordinal],
                    };
                    match self.capture_assurance_secs(ordinal, secs) {
                        Ok(mut snapshot) => {
                            self.assurance[ordinal] = Some(AssuranceState {
                                marker: EntryGradeMarker::new(snapshot.key),
                                sequence: 0,
                            });
                            snapshot.boot = Some(boot);
                            self.logs.enqueue_assurance(
                                &snapshot,
                                0,
                                crate::log::AssurancePhase::Boot,
                            );
                        }
                        Err(_) => {
                            self.logs.enqueue_assurance_unknown(fqdn, secs, boot);
                        }
                    }
                }
            }
        }
        self.emit_startup_records(secs, &report, decision);
        Ok(StartupOutcome { state, report })
    }

    /// Emits the startup log records through the boot-owned log store and
    /// drains them to the sink under a bounded turn loop. Each unresolved name
    /// is first emitted as its own
    /// `startup_name` record carrying the full FQDN, outcome and reason; the
    /// `startup_final` summary record then carries the canonical counts plus
    /// `names_dropped` (docs/alumina-proxy.md:193,236). The split keeps every
    /// valid configuration's startup result inside the encoded-entry limit by
    /// construction. The first-failure warning is NOT replayed here: the window
    /// seam (`startup_dns.rs` `resolve_window`) enqueues exactly one warning at
    /// the first counted exchange failure inside the window, so emitting again
    /// at end-of-window would duplicate it (no end-window replay,
    /// docs/alumina-proxy.md:67).
    #[expect(
        clippy::expect_used,
        reason = "allowlist ordinal is below ALLOWLIST_MAX=32, which fits u32"
    )]
    fn emit_startup_records(
        &mut self,
        secs: u64,
        report: &StartupReport,
        decision: StartupDecision,
    ) {
        use crate::config::ALLOWLIST_MAX;
        use crate::dns::transport::NameOutcome;
        use crate::log::{FinalCounts, StartupUnresolved};
        let allowlist = self.config.allowlist();
        let names = allowlist.len() as u64;
        let status = decision.status();
        let mut embedded = [StartupUnresolved {
            ordinal: 0,
            name: "",
            outcome: NameOutcome::default(),
        }; ALLOWLIST_MAX];
        let mut unresolved_count = 0usize;
        for (ordinal, name) in allowlist.iter().enumerate() {
            if report.outcomes[ordinal] != NameOutcome::Resolved {
                embedded[unresolved_count] = StartupUnresolved {
                    ordinal: u32::try_from(ordinal).expect("allowlist ordinal fits u32"),
                    name: name.as_str(),
                    outcome: report.outcomes[ordinal],
                };
                unresolved_count += 1;
            }
        }
        let mut names_dropped = 0u64;
        for un in &embedded[..unresolved_count] {
            if !self.logs.startup_name(secs, *un) {
                names_dropped += 1;
            }
        }
        self.logs.startup_final(
            secs,
            status,
            FinalCounts {
                allowance: u64::from(self.config.startup_unresolved_allowance()),
                usable: u64::from(report.resolved_names),
                unresolved: names.saturating_sub(u64::from(report.resolved_names)),
                exchanges: u64::from(report.exchanges),
                failed: u64::from(report.failed),
                not_attempted: u64::from(report.not_attempted),
                dropped: self.logs.dropped(),
                names_dropped,
            },
        );
        self.drain_startup_records(matches!(
            decision,
            StartupDecision::Exit75 { .. } | StartupDecision::Terminated
        ));
    }

    /// Delivers the records just enqueued at the point where no tunnel, DNS or
    /// deadline work exists to delay: `drain_sink` carries only
    /// [`crate::log::SINK_MAX_OPS`] fragments per turn, so the readiness
    /// records are drained in up to [`STARTUP_DRAIN_TURNS`] bounded turns,
    /// stopping early when the sink stalls (`WouldBlock`) or latches failed.
    /// On a decision that ends the process (`Exit75`, `Terminated`) nothing
    /// later can deliver a remaining record, so the residue is counted as
    /// stranded rather than destroyed uncounted (docs/alumina-proxy.md:197,
    /// L18); a serving decision leaves it queued for the serving loop's next
    /// drain.
    fn drain_startup_records(&mut self, exiting: bool) {
        let mut turns = 0usize;
        while turns < STARTUP_DRAIN_TURNS && self.logs.sink_ready() {
            self.logs.drain_sink();
            turns += 1;
        }
        if exiting {
            self.logs.strand_queued();
        }
    }

    fn bind_listener(&mut self) -> Result<TcpListener, StartupError> {
        let addr = SocketAddr::new(self.config.listen().ip(), self.config.listen().port());
        TcpListener::bind(addr).map_err(|err| StartupError::Listener {
            kind: err.kind(),
            detail: "connect listener bind",
        })
    }
}

fn usable_name(cache: &Cache, name: NameIndex, now: u64) -> Result<bool, CacheError> {
    cache.is_name_admissible(name, now)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod startup_integration;

impl StartupOutcome {
    /// The terminal readiness decision for the startup window.
    pub const fn decision(&self) -> StartupDecision {
        match &self.state {
            StartupState::Serve { mode, .. } => StartupDecision::Serve(*mode),
            StartupState::Exit75 { unresolved } => StartupDecision::Exit75 {
                unresolved: *unresolved,
            },
            StartupState::Terminated => StartupDecision::Terminated,
        }
    }

    /// The bound CONNECT listener when a serving decision was taken; `None`
    /// for exit 75 or a terminated window.
    pub const fn listener(&self) -> Option<&TcpListener> {
        match &self.state {
            StartupState::Serve { listener, .. } => Some(listener),
            StartupState::Exit75 { .. } | StartupState::Terminated => None,
        }
    }

    /// Moves the bound listener out, consuming the outcome.
    pub fn into_listener(self) -> Option<TcpListener> {
        match self.state {
            StartupState::Serve { listener, .. } => Some(listener),
            StartupState::Exit75 { .. } | StartupState::Terminated => None,
        }
    }
}

/// The startup state of the boot-owned window: `Serve` with the serving
/// mode and its bound CONNECT listener, `Exit75` with the unresolved
/// count, or `Terminated`.
#[derive(Debug)]
pub enum StartupState {
    Serve {
        mode: ServingMode,
        listener: TcpListener,
    },
    Exit75 {
        unresolved: u32,
    },
    Terminated,
}

impl ServeStorage {
    /// Consolidates the DNS lifecycle selection for one serving turn into a
    /// single storage-owned step: cancels a retained startup exchange, then
    /// advances the post-window probe sweep, then the corroboration exchange,
    /// then starts a due serving refresh — the exact boot sequence the owner
    /// previously threaded across three calls. The transport remains the sole
    /// failover/failback/probe algorithm owner; this method only selects which
    /// lifecycle kinds start and their priority, and hides no wait, budget, or
    /// numeric policy.
    pub(crate) fn prepare_serving_dns_turn(&mut self) -> Result<(), StartupDnsError> {
        self.dns.cancel_retained_startup_exchange();
        self.step_sweep()?;
        self.step_corroboration()?;
        self.start_due_serving_refresh()?;
        Ok(())
    }
}

#[cfg(test)]
mod assurance_bridge_tests {
    use super::{AssuranceSnapshot, CacheError, ServeStorage};
    use crate::log::AssurancePhase;
    use std::time::{Duration, Instant};

    #[test]
    fn invalid_preconnect_seed_remains_error_and_joins_responder() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let started = Instant::now();
                assert_eq!(
                    invalid_preconnect_seed(),
                    Err(CacheError::EvidenceInconsistent)
                );
                assert!(started.elapsed() < Duration::from_secs(3));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn invalid_preconnect_seed() -> Result<(), CacheError> {
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::tests::{Step, spawn_bounded_responder};
        use crate::eligibility::NumericAddr;

        let _responder = spawn_bounded_responder(vec![vec![Step::PositiveA {
            ttl: 60,
            octets: [9, 9, 9, 9],
        }]]);
        let mut storage = storage();
        let name = storage.cache.name_index(0).unwrap();
        let proof =
            Evidence::new(false, false, false, ResolverSource::UNKNOWN, Some(1), 1000).unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            60,
            Some(proof),
        )?;
        storage.cache.publish_positive(&staged)
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn actual_owner_expiry_then_recovery_uses_one_clock_and_no_allocation() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(actual_owner_expiry_then_recovery_body)
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "alloc-witness")]
    fn actual_owner_expiry_then_recovery_body() {
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::tests::{Step, spawn_bounded_responder};
        use crate::dns::transport::{ExchangeClass, StartupReport, TurnResult};
        use crate::eligibility::NumericAddr;
        use std::io::Read;
        use std::net::SocketAddr;
        use std::os::unix::net::UnixStream;

        let responder = spawn_bounded_responder(vec![vec![
            Step::Stall(Duration::from_millis(1300)),
            Step::PositiveAAd {
                ttl: 60,
                octets: [9, 9, 9, 9],
            },
        ]]);
        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
        storage
            .dns
            .begin_window(peer, *storage.config.resolver_set(), 1000, Duration::ZERO)
            .unwrap();
        let name = storage.cache.name_index(0).unwrap();
        let old =
            Evidence::new(false, false, false, ResolverSource::UNKNOWN, Some(1), 1000).unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            1,
            Some(old),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        let startup = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            startup.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        assert_eq!(storage.dns.now_u64(), 1000);
        assert!(
            storage
                .cache
                .family_snapshot(name, Family::A, 1000)
                .unwrap()
                .retained()
                .unwrap()
                .time_valid()
        );
        storage.logs.drain_sink();
        let mut bytes = [0u8; 16384];
        let n = reader.read(&mut bytes).unwrap();
        assert!(
            std::str::from_utf8(&bytes[..n])
                .unwrap()
                .contains("phase=boot")
        );
        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        storage
            .start_dns_exchange(0, Family::A, deadline, ExchangeClass::Serving)
            .unwrap();
        let (terminal, counts) =
            crate::alloc::run_phase(crate::alloc::Phase::BackgroundRefresh, || {
                loop {
                    match storage.advance_dns_serving().unwrap() {
                        Some(TurnResult::Pending) => {
                            storage.dns.wait_dns_readiness(deadline).unwrap();
                        }
                        Some(result) => break result,
                        None => panic!("serving exchange vanished"),
                    }
                }
            });
        assert!(matches!(terminal, TurnResult::Published(_)), "{terminal:?}");
        assert!(counts.all_zero(), "{counts:?}");
        let returned = Instant::now();
        let observed = storage.assurance_clock.unwrap().last;
        assert!(started <= observed && observed <= returned);
        let secs = storage.cache_secs(observed);
        assert_eq!(
            secs,
            crate::runtime::tunnel::WorkerClock::new(storage.origin, storage.now0)
                .cache_secs(observed)
        );
        assert!((1001..1060).contains(&secs), "{secs}");
        assert_expiry_recovery_frames(&mut storage, &mut reader, &mut bytes, secs);
        assert_eq!(storage.assurance[0].unwrap().sequence, 2);
        responder.finish().unwrap();
    }

    #[cfg(feature = "alloc-witness")]
    fn assert_expiry_recovery_frames(
        storage: &mut ServeStorage,
        reader: &mut std::os::unix::net::UnixStream,
        bytes: &mut [u8; 16384],
        secs: u64,
    ) {
        use std::io::Read as _;
        storage.logs.drain_sink();
        let n = reader.read(bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        let frames: Vec<_> = text
            .lines()
            .filter(|line| line.contains("kind=dns_assurance "))
            .collect();
        assert_eq!(frames.len(), 2, "{text}");
        for (frame, (seq, valid)) in frames.iter().zip([(1, 0), (2, 1)]) {
            assert!(
                frame.contains(&format!("secs={secs} seq={seq} phase=change")),
                "{frame}"
            );
            assert!(frame.contains("a_current=\"trusted\""), "{frame}");
            assert!(frame.contains("a_required=\"resolver_trusted\""), "{frame}");
            assert!(frame.contains("a_outcome=\"positive\""), "{frame}");
            assert!(frame.contains("a_retained_kind=\"positive\""), "{frame}");
            assert!(frame.contains("a_retained_class=\"trusted\""), "{frame}");
            assert!(
                frame.contains(&format!("a_retained_time_valid={valid}")),
                "{frame}"
            );
        }
    }

    #[test]
    fn actual_owner_negative_publications_are_atomic() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                actual_owner_negative_case(true);
                actual_owner_negative_case(false);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn actual_owner_negative_case(nx: bool) {
        use crate::dns::cache::Family;
        use crate::dns::transport::tests::{Step, spawn_bounded_responder};
        use crate::dns::transport::{ExchangeClass, StartupReport, TurnResult};
        use std::io::Read;
        use std::net::SocketAddr;
        use std::os::unix::net::UnixStream;

        let step = if nx {
            Step::NxdomainWithSoa { ttl: 60, min: 60 }
        } else {
            Step::NodataWithSoa { ttl: 60, min: 60 }
        };
        let responder = spawn_bounded_responder(vec![vec![step]]);
        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
        storage
            .dns
            .begin_window(peer, *storage.config.resolver_set(), 1000, Duration::ZERO)
            .unwrap();
        storage.publish_test_a(0);
        let startup = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            startup.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        storage.logs.drain_sink();
        let mut bytes = [0u8; 16384];
        let boot_len = reader.read(&mut bytes).unwrap();
        assert!(boot_len > 0);
        assert!(
            std::str::from_utf8(&bytes[..boot_len])
                .unwrap()
                .contains("kind=")
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        storage
            .start_dns_exchange(0, Family::Aaaa, deadline, ExchangeClass::Serving)
            .unwrap();
        loop {
            match storage.advance_dns_serving().unwrap() {
                Some(TurnResult::Pending) => {
                    storage.dns.wait_dns_readiness(deadline).unwrap();
                }
                Some(TurnResult::Published(_)) => break,
                other => panic!("negative publication failed: {other:?}"),
            }
        }
        storage.logs.drain_sink();
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        let frames: Vec<_> = text
            .lines()
            .filter(|line| line.contains("kind=dns_assurance "))
            .collect();
        assert_eq!(frames.len(), 1, "{text}");
        let frame = frames[0];
        assert!(frame.contains("seq=1 phase=change"), "{frame}");
        if nx {
            assert!(
                frame.contains("a_outcome=\"nx\"") && frame.contains("aaaa_outcome=\"nx\""),
                "{frame}"
            );
            assert!(
                frame.contains("a_retained_kind=\"nx\"")
                    && frame.contains("aaaa_retained_kind=\"nx\""),
                "{frame}"
            );
        } else {
            assert!(
                frame.contains("a_outcome=\"positive\"")
                    && frame.contains("aaaa_outcome=\"nodata\""),
                "{frame}"
            );
            assert!(
                frame.contains("a_retained=\"none\"")
                    && frame.contains("aaaa_retained_kind=\"nodata\""),
                "{frame}"
            );
        }
        responder.finish().unwrap();
    }

    #[test]
    fn actual_owner_same_grade_address_refresh_and_nx_are_silent() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(actual_owner_silent_refresh_body)
            .unwrap()
            .join()
            .unwrap();
    }

    fn actual_owner_silent_refresh_body() {
        use crate::dns::cache::Family;
        use crate::dns::transport::StartupReport;
        use crate::dns::transport::tests::{Step, spawn_bounded_responder};
        use std::io::Read;
        use std::net::SocketAddr;
        use std::os::unix::net::UnixStream;

        let responder = spawn_bounded_responder(vec![vec![
            Step::PositiveA {
                ttl: 60,
                octets: [8, 8, 8, 8],
            },
            Step::PositiveAaaa {
                ttl: 60,
                octets: [
                    0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                ],
            },
            Step::PositiveA {
                ttl: 60,
                octets: [9, 9, 9, 9],
            },
            Step::NxdomainWithSoa { ttl: 60, min: 60 },
        ]]);
        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
        storage
            .dns
            .begin_window(peer, *storage.config.resolver_set(), 1000, Duration::ZERO)
            .unwrap();
        storage.publish_test_a(0);
        let startup = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            startup.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        storage.logs.drain_sink();
        let mut bytes = [0u8; 16384];
        let boot_len = reader.read(&mut bytes).unwrap();
        assert!(boot_len > 0);
        assert!(
            std::str::from_utf8(&bytes[..boot_len])
                .unwrap()
                .contains("kind=")
        );
        let name = storage.cache.name_index(0).unwrap();
        drive_silent_refreshes(&mut storage, name);
        storage.logs.drain_sink();
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        let frames: Vec<_> = text
            .lines()
            .filter(|line| line.contains("kind=dns_assurance "))
            .collect();
        assert_eq!(frames.len(), 1, "{text}");
        assert!(frames[0].contains("seq=1 phase=change"), "{text}");
        let now = storage.cache_secs(Instant::now());
        assert!(
            storage
                .cache
                .negative_projection(name, Family::A, now)
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .cache
                .negative_projection(name, Family::Aaaa, now)
                .unwrap()
                .is_some()
        );
        responder.finish().unwrap();
    }

    fn drive_silent_refreshes(storage: &mut ServeStorage, name: crate::dns::cache::NameIndex) {
        use crate::dns::cache::Family;
        use crate::dns::transport::{ExchangeClass, TurnResult};
        use crate::eligibility::NumericAddr;
        let mut first_generation = None;
        for (index, family) in [Family::A, Family::Aaaa, Family::A, Family::A]
            .into_iter()
            .enumerate()
        {
            let deadline = Instant::now() + Duration::from_secs(5);
            storage
                .start_dns_exchange(0, family, deadline, ExchangeClass::Serving)
                .unwrap();
            loop {
                match storage.advance_dns_serving().unwrap() {
                    Some(TurnResult::Pending) => {
                        storage.dns.wait_dns_readiness(deadline).unwrap();
                    }
                    Some(TurnResult::Published(_)) => break,
                    other => panic!("publication failed: {other:?}"),
                }
            }
            match index {
                0 => {
                    first_generation =
                        Some(storage.cache.entry(name, Family::A).unwrap().generation());
                }
                2 => {
                    let entry = storage.cache.entry(name, Family::A).unwrap();
                    assert_ne!(Some(entry.generation()), first_generation);
                    assert_eq!(entry.bindings(), &[NumericAddr::V4([9, 9, 9, 9].into())]);
                    assert_eq!(storage.assurance[0].unwrap().sequence, 1);
                }
                3 => assert_eq!(storage.assurance[0].unwrap().sequence, 1),
                _ => {}
            }
        }
    }

    fn storage() -> ServeStorage {
        let doc = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";
        let config = crate::config::parse_config_document(doc).expect("valid owner config");
        let mut storage = ServeStorage::boot(&config).expect("boot owner storage");
        storage.mount_clock(Instant::now(), 1_700_000_000);
        storage
    }

    fn at(storage: &ServeStorage, secs: u64) -> Instant {
        let base = storage
            .assurance_clock
            .map_or(storage.origin, |clock| clock.boot);
        base + Duration::from_secs(secs.saturating_sub(storage.cache_secs(base)))
    }

    #[test]
    fn earlier_observation_cannot_rewind_expired_proof_or_spend_sequence() {
        use super::{AssuranceObservation, AssuranceObservationError};
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let name = storage.cache.name_index(0).unwrap();
        let proof =
            Evidence::new(false, false, false, ResolverSource::UNKNOWN, Some(10), 1000).unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            10,
            Some(proof),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        let tick = storage.origin + Duration::from_secs(10);
        let expiry = tick + Duration::from_millis(900);
        assert_eq!(
            storage.emit_assurance(0, expiry),
            Ok(AssuranceObservation::Attempted {
                sequence: 1,
                enqueued: true
            })
        );
        let before_len = storage.logs.len();
        let before_drop = storage.logs.dropped();
        let before_seq = storage.assurance[0].as_ref().unwrap().sequence;
        let before_frame = storage.logs.last_record_bytes().unwrap().to_vec();
        let before_cache = storage.cache;
        let wake_fault = storage
            .assurance_wake(tick + Duration::from_millis(100))
            .unwrap_err();
        assert_eq!(wake_fault.ordinal, 0);
        assert_eq!(wake_fault.error, AssuranceObservationError::ClockRegressed);
        let rewind = storage.emit_assurance(0, tick + Duration::from_millis(100));
        assert_eq!(
            rewind,
            Err(AssuranceObservationError::ClockRegressed),
            "an earlier same-second observation must not resurrect expired proof or consume sequence"
        );
        assert_eq!(
            storage.emit_assurance(0, tick - Duration::from_secs(1)),
            Err(AssuranceObservationError::ClockRegressed),
            "the earlier valid-proof second cannot resurrect the expired proof"
        );
        let before_boot = storage
            .assurance_clock
            .unwrap()
            .boot
            .checked_sub(Duration::from_nanos(1))
            .unwrap();
        assert_eq!(
            storage.emit_assurance(0, before_boot),
            Err(AssuranceObservationError::BeforeStartup)
        );
        let before_origin = storage.origin.checked_sub(Duration::from_nanos(1)).unwrap();
        assert_eq!(
            storage.emit_assurance(0, before_origin),
            Err(AssuranceObservationError::BeforeStartup)
        );
        assert_eq!(storage.assurance[0].as_ref().unwrap().sequence, before_seq);
        assert_eq!(storage.logs.len(), before_len);
        assert_eq!(storage.logs.dropped(), before_drop);
        assert_eq!(storage.logs.last_record_bytes().unwrap(), before_frame);
        assert_eq!(storage.cache, before_cache);
        assert_eq!(storage.assurance_clock.unwrap().last, expiry);
        assert_eq!(
            storage.emit_assurance(0, expiry),
            Ok(AssuranceObservation::Unchanged),
            "rejection leaves the expired marker unchanged"
        );
    }

    #[test]
    fn observation_before_decision_second_is_rejected_even_at_saturated_epoch() {
        use super::AssuranceObservationError;
        use crate::dns::transport::StartupReport;
        use std::os::unix::net::UnixStream;
        let mut storage = storage();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        storage
            .settle_startup(u64::MAX, StartupReport::default(), 1000, false)
            .unwrap();
        let earlier = storage.origin + Duration::from_secs(999);
        assert!(earlier > storage.assurance_clock.unwrap().boot);
        let before_seq = storage.assurance[0].as_ref().unwrap().sequence;
        let before_len = storage.logs.len();
        let before_drop = storage.logs.dropped();
        assert_eq!(
            storage.emit_assurance(0, earlier),
            Err(AssuranceObservationError::BeforeStartup),
            "saturated epoch must not hide an instant before the decision second"
        );
        assert_eq!(storage.assurance[0].as_ref().unwrap().sequence, before_seq);
        assert_eq!(storage.logs.len(), before_len);
        assert_eq!(storage.logs.dropped(), before_drop);
    }

    #[test]
    fn pre_and_post_publication_share_the_exact_owner_instant() {
        use super::AssuranceObservation;
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::os::unix::net::UnixStream;
        let mut storage = storage();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        let observed = at(&storage, 1020);
        assert_eq!(
            storage.emit_assurance(0, observed),
            Ok(AssuranceObservation::Unchanged)
        );
        let name = storage.cache.name_index(0).unwrap();
        let proof = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(300),
            1020,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1020,
            300,
            Some(proof),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        assert_eq!(
            storage.emit_assurance(0, observed),
            Ok(AssuranceObservation::Attempted {
                sequence: 1,
                enqueued: true
            })
        );
        let frame = std::str::from_utf8(storage.logs.last_record_bytes().unwrap()).unwrap();
        assert!(frame.contains("secs=1020 seq=1 phase=change"), "{frame}");
        assert_eq!(
            storage.emit_assurance(0, observed),
            Ok(AssuranceObservation::Unchanged)
        );
        assert_eq!(storage.assurance_clock.unwrap().last, observed);
    }

    #[test]
    fn boot_seeded_observation_is_silent_before_trusted_proof_expiry() {
        use super::{AssuranceObservation, AssuranceObservationError};
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let name = storage.cache.name_index(0).unwrap();
        let proof =
            Evidence::new(false, false, false, ResolverSource::UNKNOWN, Some(10), 1000).unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            10,
            Some(proof),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1000)),
            Ok(AssuranceObservation::Unchanged)
        );
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1009)),
            Ok(AssuranceObservation::Unchanged)
        );
        assert_seeded_expiry_transition(&mut storage);
        exercise_full_queue_expiry_recovery(&mut storage, name);
        let mut bytes = [0u8; 8192];
        assert!(reader.read(&mut bytes).unwrap() > 0);
        storage.logs.drain_sink();
        assert!(!storage.logs.is_full());
        let generation = storage.cache.entry(name, Family::A).unwrap().generation();
        let plain = Evidence::new(
            false,
            false,
            false,
            ResolverSource::UNKNOWN,
            Some(300),
            1030,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            generation,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1030,
            300,
            Some(plain),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1031)),
            Ok(AssuranceObservation::Attempted {
                sequence: 3,
                enqueued: true
            })
        );
        let frame = std::str::from_utf8(storage.logs.last_record_bytes().unwrap()).unwrap();
        assert!(
            frame.contains("secs=1031 seq=3 phase=change"),
            "sequence gap represents dropped attempt: {frame}"
        );
        let count = storage.logs.len();
        assert_eq!(
            storage.emit_assurance(1, at(&storage, 1031)),
            Err(AssuranceObservationError::Cache(CacheError::NameOutOfRange))
        );
        assert_eq!(
            storage.logs.len(),
            count,
            "invalid lookup must not queue or mutate"
        );
    }

    fn assert_seeded_expiry_transition(storage: &mut ServeStorage) {
        use super::AssuranceObservation;
        assert_eq!(
            storage.emit_assurance(0, at(storage, 1010)),
            Ok(AssuranceObservation::Attempted {
                sequence: 1,
                enqueued: true
            })
        );
        let frame = std::str::from_utf8(storage.logs.last_record_bytes().unwrap()).unwrap();
        assert!(
            frame.contains("secs=1010 seq=1 phase=change")
                && frame.contains("a_current=\"trusted\"")
                && frame.contains("a_retained_time_valid=0"),
            "{frame}"
        );
        assert_eq!(
            storage.emit_assurance(0, at(storage, 1011)),
            Ok(AssuranceObservation::Unchanged)
        );
    }

    fn exercise_full_queue_expiry_recovery(
        storage: &mut ServeStorage,
        name: crate::dns::cache::NameIndex,
    ) {
        use super::AssuranceObservation;
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, StagedPositive};
        use crate::eligibility::NumericAddr;
        while !storage.logs.is_full() {
            storage
                .logs
                .startup_warning_ctx(1011, "alpha.example.org", Family::A, "timeout", None);
        }
        let before_dropped = storage.logs.dropped();
        let generation = storage.cache.entry(name, Family::A).unwrap().generation();
        let strong = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(300),
            1020,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            generation,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1020,
            300,
            Some(strong),
        )
        .unwrap();
        let event_at = at(storage, 1021);
        assert_eq!(
            storage.emit_assurance(0, event_at),
            Ok(AssuranceObservation::Unchanged)
        );
        storage.cache.publish_positive(&staged).unwrap();
        assert_eq!(
            storage.emit_assurance(0, event_at),
            Ok(AssuranceObservation::Attempted {
                sequence: 2,
                enqueued: false
            })
        );
        assert_eq!(storage.logs.dropped(), before_dropped + 1);
        assert_eq!(
            storage.emit_assurance(0, at(storage, 1022)),
            Ok(AssuranceObservation::Unchanged)
        );
        assert_eq!(
            storage.logs.dropped(),
            before_dropped + 1,
            "no retry after a dropped observation"
        );
    }

    #[test]
    fn unseeded_and_invalid_observations_are_distinct_errors() {
        use super::AssuranceObservationError;
        let mut storage = storage();
        let before = storage.logs.len();
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1000)),
            Err(AssuranceObservationError::Unseeded)
        );
        assert_eq!(
            storage.emit_assurance(1, at(&storage, 1000)),
            Err(AssuranceObservationError::Cache(CacheError::NameOutOfRange))
        );
        assert_eq!(storage.logs.len(), before);
        assert!(storage.assurance[0].is_none());
    }

    #[test]
    fn invalid_cache_snapshot_never_seeds_a_fabricated_marker() {
        use super::AssuranceObservationError;
        use crate::dns::cache::Cache;
        use crate::dns::transport::StartupReport;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;
        let doc = "listen = \"127.0.0.1:9\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"beta.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";
        let config = crate::config::parse_config_document(doc).unwrap();
        let mut storage = ServeStorage::boot(&config).unwrap();
        storage.cache = Cache::new(1).unwrap();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert!(storage.assurance[0].is_some());
        assert!(
            storage.assurance[1].is_none(),
            "failed capture is not an empty observation"
        );
        let mut bytes = [0u8; 8192];
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        assert!(
            text.lines()
                .any(|line| line.contains("beta.example.org")
                    && line.contains("cache_snapshot=unknown")),
            "{text}"
        );
        let before = storage.assurance[0].as_ref().unwrap().sequence;
        let before_clock = storage.assurance_clock.unwrap().last;
        assert_eq!(
            storage.emit_assurance(1, at(&storage, 2000)),
            Err(AssuranceObservationError::Cache(CacheError::NameOutOfRange))
        );
        assert_eq!(storage.assurance[0].as_ref().unwrap().sequence, before);
        assert!(storage.assurance[1].is_none());
        assert_eq!(storage.assurance_clock.unwrap().last, before_clock);
        assert_eq!(
            storage.emit_assurance(0, before_clock),
            Ok(super::AssuranceObservation::Unchanged)
        );
    }

    #[test]
    fn failed_listener_does_not_seed_assurance_state() {
        use super::{AssuranceObservationError, StartupError};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        let guard = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = guard.local_addr().unwrap().port();
        let doc = format!(
            "listen = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
        );
        let config = crate::config::parse_config_document(&doc).unwrap();
        let mut storage = ServeStorage::boot(&config).unwrap();
        let name = storage.cache.name_index(0).unwrap();
        let staged = StagedPositive::stage(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            60,
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        assert!(matches!(
            storage.settle_startup(1000, StartupReport::default(), 0, false),
            Err(StartupError::Listener { .. })
        ));
        assert!(storage.assurance[0].is_none());
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1000)),
            Err(AssuranceObservationError::Unseeded)
        );
        assert_eq!(storage.logs.len(), 0);
    }

    #[test]
    fn boot_full_queue_still_seeds_unresolved_entry_without_retry() {
        use super::AssuranceObservation;
        use crate::dns::cache::Family;
        use crate::dns::transport::StartupReport;
        use std::os::unix::net::UnixStream;
        let mut storage = storage();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        while !storage.logs.is_full() {
            storage
                .logs
                .startup_warning_ctx(1000, "alpha.example.org", Family::A, "timeout", None);
        }
        let before = storage.logs.dropped();
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Exit75 { unresolved: 1 }
        );
        assert!(
            storage.logs.dropped() > before,
            "the initial frame was attempted against a full queue"
        );
        assert_eq!(storage.assurance[0].as_ref().unwrap().sequence, 0);
        let after = storage.logs.dropped();
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1000)),
            Ok(AssuranceObservation::Unchanged)
        );
        assert_eq!(
            storage.logs.dropped(),
            after,
            "the dropped initial attempt is not retried"
        );
    }

    #[test]
    fn sequence_saturates_without_wrap_for_distinct_observations() {
        use super::AssuranceObservation;
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::os::unix::net::UnixStream;
        let mut storage = storage();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        storage.assurance[0].as_mut().unwrap().sequence = u64::MAX - 1;
        let name = storage.cache.name_index(0).unwrap();
        let strong = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(300),
            1010,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1010,
            300,
            Some(strong),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1011)),
            Ok(AssuranceObservation::Attempted {
                sequence: u64::MAX,
                enqueued: true
            })
        );
        let generation = storage.cache.entry(name, Family::A).unwrap().generation();
        let plain = Evidence::new(
            false,
            false,
            false,
            ResolverSource::UNKNOWN,
            Some(300),
            1020,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            generation,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1020,
            300,
            Some(plain),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1021)),
            Ok(AssuranceObservation::Attempted {
                sequence: u64::MAX,
                enqueued: true
            })
        );
        let frame = std::str::from_utf8(storage.logs.last_record_bytes().unwrap()).unwrap();
        assert!(
            frame.contains("seq=18446744073709551615") && !frame.contains("seq=0 "),
            "{frame}"
        );
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1022)),
            Ok(AssuranceObservation::Unchanged)
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn seeded_real_owner_observation_spends_zero_allocations() {
        use super::{AssuranceClock, AssuranceObservation, AssuranceState};
        use crate::alloc::{Phase, run_phase};
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::os::unix::net::UnixStream;
        let mut storage = storage();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        let name = storage.cache.name_index(0).unwrap();
        let proof = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(300),
            1010,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1010,
            300,
            Some(proof),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        let now = at(&storage, 1011);
        let (result, counts) = run_phase(Phase::Logging, || storage.emit_assurance(0, now));
        assert_eq!(
            result,
            Ok(AssuranceObservation::Attempted {
                sequence: 1,
                enqueued: true
            })
        );
        assert!(
            counts.all_zero(),
            "owner capture, marker and enqueue: {counts:?}"
        );
        println!(
            "owner_bytes={} state_slot_bytes={} fixed_32_state_bytes={} snapshot_bytes={} optional_clock_bytes={}",
            std::mem::size_of::<ServeStorage>(),
            std::mem::size_of::<Option<AssuranceState>>(),
            std::mem::size_of::<[Option<AssuranceState>; 32]>(),
            std::mem::size_of::<AssuranceSnapshot>(),
            std::mem::size_of::<Option<AssuranceClock>>()
        );
    }

    #[test]
    fn assurance_snapshot_fits_existing_record_slot() {
        let bytes = std::mem::size_of::<AssuranceSnapshot>();
        println!(
            "snapshot_bytes={} snapshot_align={} fqdn_bytes={} family_snapshot_bytes={}",
            bytes,
            std::mem::align_of::<AssuranceSnapshot>(),
            std::mem::size_of::<crate::config::Fqdn>(),
            std::mem::size_of::<crate::dns::cache::grade_key::FamilySnapshot>()
        );
        assert!(bytes <= crate::log::SLOT_BYTES);
    }

    #[test]
    fn owner_assurance_bridge_preserves_owner_identity_and_errors() {
        let mut storage = storage();
        let snapshot = storage.capture_assurance(0, Instant::now()).unwrap();
        assert!(
            storage
                .logs
                .enqueue_assurance(&snapshot, 7, AssurancePhase::Boot)
        );
        let record = std::str::from_utf8(storage.logs().last_record_bytes().unwrap()).unwrap();
        assert!(record.contains("alpha.example.org"));
        assert!(record.contains("seq=7 phase=boot"));
        let len = storage.logs().len();
        let dropped = storage.logs().dropped();
        assert!(matches!(
            storage.capture_assurance(1, Instant::now()),
            Err(CacheError::NameOutOfRange)
        ));
        assert_eq!(storage.logs().len(), len);
        assert_eq!(storage.logs().dropped(), dropped);
    }

    #[test]
    fn assurance_record_preserves_observed_proof_after_expiry_and_mutation() {
        use crate::dns::cache::evidence::{Evidence, ProofClass, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::eligibility::NumericAddr;
        use std::time::Duration;

        let mut storage = storage();
        let origin = Instant::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap();
        storage.mount_clock(origin, 1000);
        let name = storage.cache().name_index(0).unwrap();
        let evidence = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(30),
            1000,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            name,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            30,
            Some(evidence),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        storage
            .cache
            .evict_nodata_evidenced(name, Family::Aaaa, evidence)
            .unwrap();
        let observed_at = origin + Duration::from_secs(5);
        let clock = crate::runtime::tunnel::WorkerClock::new(origin, 1000);
        let secs = clock.cache_secs(observed_at);
        assert_eq!(secs, 1005);
        assert_eq!(
            storage
                .cache()
                .family_snapshot(name, Family::A, secs)
                .unwrap()
                .current(),
            Some(ProofClass::Delegated)
        );
        assert!(clock.cache_secs(Instant::now()) >= 1030);
        let snapshot = storage.capture_assurance(0, observed_at).unwrap();
        storage.cache.evict_nodata(name, Family::A).unwrap();
        storage.cache.evict_nodata(name, Family::Aaaa).unwrap();
        assert!(
            storage
                .logs
                .enqueue_assurance(&snapshot, 7, AssurancePhase::Boot)
        );
        let record = std::str::from_utf8(storage.logs().last_record_bytes().unwrap()).unwrap();
        assert!(
            record.contains(" secs=1005 "),
            "captured second must survive: {record}"
        );
        assert!(
            record.contains("a_current=\"delegated\""),
            "captured proof must survive: {record}"
        );
        assert!(
            record.contains("aaaa_current=\"delegated\""),
            "captured sibling proof must survive: {record}"
        );
        assert!(
            record.contains("aaaa_outcome=\"nodata\""),
            "captured sibling outcome must survive: {record}"
        );
    }

    #[test]
    fn widest_boot_frame_including_retained_proofs_fits_slot() {
        use crate::dns::cache::Family;
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Generation, StagedPositive};
        use crate::dns::transport::FailureReason;
        use crate::eligibility::NumericAddr;
        use std::net::{Ipv4Addr, Ipv6Addr};
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let doc = format!(
            "listen = \"127.0.0.1:9\"\nstartup_unresolved_allowance = 0\nrecursive_dnssec_policy = \"root_validating_no_stale\"\nresolver = [\"1.1.1.1#r.example.org#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"8.8.8.8#r.example.org#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"9.9.9.9#r.example.org#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"8.8.4.4#r.example.org#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"1.0.0.1#r.example.org#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"{name}:65535\"]\ndns_assurance = \"resolver_authenticated\"\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        );
        let config = crate::config::parse_config_document(&doc).unwrap();
        let mut storage = ServeStorage::boot(&config).unwrap();
        assert_eq!(name.len(), crate::names::hostname::FQDN_MAX_LEN);
        let start = u64::MAX - 300_000;
        let evidence = Evidence::new(
            false,
            true,
            false,
            ResolverSource::index(4).unwrap(),
            Some(300),
            start,
        )
        .unwrap();
        let index = storage.cache.name_index(0).unwrap();
        for family in Family::ALL {
            let addresses: Vec<_> = (1..=16)
                .map(|i| match family {
                    Family::A => NumericAddr::V4(Ipv4Addr::new(8, 8, 8, i)),
                    Family::Aaaa => NumericAddr::V6(Ipv6Addr::new(
                        0x2606,
                        0x4700,
                        0x4700,
                        0,
                        0,
                        0,
                        0,
                        u16::from(i),
                    )),
                })
                .collect();
            let staged = StagedPositive::stage_with_evidence(
                index,
                family,
                Generation::INITIAL,
                &addresses,
                start,
                300,
                Some(evidence),
            )
            .unwrap();
            storage.cache.publish_positive(&staged).unwrap();
        }
        let mut snapshot = storage.capture_assurance_secs(0, start + 5).unwrap();
        snapshot.boot = Some(super::AssuranceBoot {
            status: crate::log::StartupStatus::Degraded,
            attempted: [true; 2],
            results: [Some(Err(FailureReason::InsufficientAssurance)); 2],
        });
        storage.logs.saturate_dropped_for_test();
        assert!(
            storage
                .logs
                .enqueue_assurance(&snapshot, u64::MAX, AssurancePhase::Boot)
        );
        assert_eq!(storage.logs.dropped(), u64::MAX);
        let frame = storage.logs().last_record_bytes().unwrap();
        let text = std::str::from_utf8(frame).unwrap();
        assert!(
            text.contains("a_retained_class=\"authenticated\"")
                && text.contains("aaaa_retained_class=\"authenticated\"")
        );
        assert!(
            text.contains("a_reason=\"insufficient_assurance\"")
                && text.contains("aaaa_reason=\"insufficient_assurance\"")
        );
        for family in ["a", "aaaa"] {
            assert!(text.contains(&format!("{family}_required=\"resolver_authenticated\"")));
            assert!(text.contains(&format!("{family}_current=\"authenticated\"")));
            assert!(text.contains(&format!("{family}_usable=16")));
            assert!(text.contains(&format!("{family}_retained_source=4")));
        }
        assert!(
            text.contains("seq=18446744073709551615")
                && text.contains(&format!("secs={}", start + 5))
        );
        assert!(text.contains(&name) && text.contains("port=65535") && text.ends_with('\n'));
        assert!(frame.len() <= crate::log::SLOT_BYTES);
        println!("widest_boot_frame_bytes={}", frame.len());
    }

    #[test]
    fn boot_frame_uses_readiness_second_for_retained_expiry() {
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let index = storage.cache.name_index(0).unwrap();
        let evidence = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(3),
            1000,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            index,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            3,
            Some(evidence),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 5, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        let mut bytes = [0u8; 8192];
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        let frame = text
            .lines()
            .find(|line| line.contains("kind=dns_assurance"))
            .unwrap();
        assert!(
            frame.contains("secs=1005") && frame.contains("a_retained_time_valid=0"),
            "decision clock, not a resampled clock: {frame}"
        );
        assert!(
            frame.contains("a_current=\"trusted\"")
                && frame.contains("a_retained_class=\"delegated\""),
            "current and retained facts remain distinct: {frame}"
        );
    }

    #[test]
    fn boot_failure_conclusion_does_not_replace_valid_retained_proof() {
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::dns::transport::{FailureReason, StartupReport};
        use crate::eligibility::NumericAddr;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        storage.config = storage.config.clone().with_kernel_assigned_test_listener();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let index = storage.cache.name_index(0).unwrap();
        let proof = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(30),
            1000,
        )
        .unwrap();
        let staged = StagedPositive::stage_with_evidence(
            index,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            30,
            Some(proof),
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        let mut report = StartupReport::default();
        report.attempted[0] = [true, false];
        report.family_results[0][0] = Some(Err(FailureReason::InsufficientAssurance));
        let outcome = storage.settle_startup(1000, report, 5, false).unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        let mut bytes = [0u8; 8192];
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        let frame = text
            .lines()
            .find(|line| line.contains("kind=dns_assurance"))
            .unwrap();
        assert!(
            frame.contains("a_last=\"failed\" a_reason=\"insufficient_assurance\""),
            "{frame}"
        );
        assert!(
            frame.contains("a_current=\"delegated\"") && frame.contains("a_retained_time_valid=1"),
            "{frame}"
        );
        assert!(
            frame.contains("aaaa_attempted=0 aaaa_last=\"none\""),
            "{frame}"
        );
    }

    #[test]
    fn unknown_boot_snapshot_is_explicit_and_does_not_invent_family_facts() {
        use crate::dns::transport::FailureReason;
        let mut storage = storage();
        let fqdn = storage.config.allowlist().get(0).unwrap().clone();
        let boot = super::AssuranceBoot {
            status: crate::log::StartupStatus::Failed,
            attempted: [true, false],
            results: [Some(Err(FailureReason::Timeout)), None],
        };
        assert!(
            storage
                .logs
                .enqueue_assurance_unknown(&fqdn, u64::MAX, boot)
        );
        let text = std::str::from_utf8(storage.logs.last_record_bytes().unwrap()).unwrap();
        assert!(
            text.contains("cache_snapshot=unknown") && text.contains("secs=18446744073709551615"),
            "{text}"
        );
        assert!(
            text.contains("a_attempted=1 a_last=\"failed\" a_reason=\"timeout\""),
            "{text}"
        );
        assert!(
            text.contains("aaaa_attempted=0 aaaa_last=\"none\"") && !text.contains("a_current="),
            "{text}"
        );
    }

    #[test]
    fn startup_decision_and_boot_frame_saturate_at_clock_limit() {
        use crate::dns::cache::Family;
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Generation, StagedPositive};
        use crate::dns::transport::StartupReport;
        use crate::eligibility::NumericAddr;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let index = storage.cache.name_index(0).unwrap();
        let staged = StagedPositive::stage(
            index,
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V4([8, 8, 8, 8].into())],
            1000,
            30,
        )
        .unwrap();
        storage.cache.publish_positive(&staged).unwrap();
        assert!(
            storage.cache.is_name_admissible(index, 0).unwrap(),
            "wrapping the clock would spuriously revive the old binding"
        );
        let proof = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(0).unwrap(),
            Some(9),
            u64::MAX - 10,
        )
        .unwrap();
        storage
            .cache
            .evict_nodata_evidenced(index, Family::Aaaa, proof)
            .unwrap();
        let outcome = storage
            .settle_startup(u64::MAX, StartupReport::default(), 1, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Exit75 { unresolved: 1 }
        );
        let mut bytes = [0u8; 8192];
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        let frame = text
            .lines()
            .find(|line| line.contains("kind=dns_assurance"))
            .unwrap();
        assert!(
            frame.contains("secs=18446744073709551615"),
            "no clock wrap: {frame}"
        );
        assert!(
            frame.contains("a_current=\"none\"") && frame.contains("aaaa_retained_time_valid=0"),
            "expired binding and proof must not revive: {frame}"
        );
    }

    #[test]
    fn full_log_ring_does_not_change_boot_decision() {
        use crate::dns::cache::Family;
        use crate::dns::transport::StartupReport;
        use std::io::{self, Write as _};
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        let (_reader, mut writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let mut blocked = false;
        for _ in 0..4096 {
            match writer.write(&[0u8; 4096]) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(err) => panic!("fill socket: {err}"),
            }
        }
        assert!(blocked, "socket must be full before settlement");
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        while !storage.logs.is_full() {
            storage
                .logs
                .startup_warning_ctx(0, "alpha.example.org", Family::A, "timeout", None);
        }
        let before = storage.logs.dropped();
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Exit75 { unresolved: 1 }
        );
        assert_eq!(
            storage.logs.dropped() - before,
            crate::log::QUEUE_SLOTS as u64 + 3,
            "all previously queued records and the boot, unresolved-name and reserved summary attempts are counted"
        );
        assert!(
            !storage.logs.sink_has_failed(),
            "backpressure is not a hard sink failure"
        );
        assert_eq!(storage.logs.len(), 0, "exit strands the held queue");
    }

    #[test]
    fn hard_sink_failure_keeps_decision_and_latches_error() {
        use crate::dns::transport::StartupReport;
        use std::os::unix::net::UnixStream;
        let mut storage = storage();
        let (reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        drop(reader);
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Exit75 { unresolved: 1 }
        );
        assert!(
            storage.logs.sink_has_failed(),
            "hard failure must remain latched for the owner"
        );
        assert_eq!(
            storage.logs.dropped(),
            3,
            "boot, startup name and final records are counted"
        );
        assert_eq!(storage.logs.len(), 0);
    }

    #[test]
    fn terminated_startup_emits_no_assurance_boot_records() {
        use super::AssuranceObservationError;
        use crate::dns::transport::StartupReport;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        let mut storage = storage();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 0, true)
            .unwrap();
        assert_eq!(outcome.decision(), super::StartupDecision::Terminated);
        assert!(outcome.listener().is_none());
        let mut bytes = [0u8; 8192];
        let n = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..n]).unwrap();
        assert!(
            text.contains("kind=startup_final") && text.contains("status=\"terminated\""),
            "{text}"
        );
        assert!(!text.contains("kind=dns_assurance"), "{text}");
        assert_eq!(storage.logs.dropped(), 0);
        assert!(storage.assurance[0].is_none());
        assert_eq!(
            storage.emit_assurance(0, at(&storage, 1000)),
            Err(AssuranceObservationError::Unseeded)
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn owner_assurance_bridge_spends_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        let mut storage = storage();
        let now = Instant::now();
        let (result, counts) = run_phase(Phase::Logging, || {
            let snapshot = storage.capture_assurance(0, now)?;
            Ok::<bool, CacheError>(storage.logs.enqueue_assurance(
                &snapshot,
                7,
                AssurancePhase::Boot,
            ))
        });
        assert_eq!(result, Ok(true));
        assert!(counts.all_zero(), "owner bridge allocations: {counts:?}");
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn initial_assurance_real_settlement_32_entries_spends_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::dns::transport::{FailureReason, StartupReport};
        use std::fmt::Write as _;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        let mut doc = String::from(
            "listen = \"127.0.0.1:9\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
        );
        for i in 0..32 {
            write!(doc, "[allowed_fqdn.\"n{i}.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n").unwrap();
        }
        let config = crate::config::parse_config_document(&doc).unwrap();
        let mut storage = ServeStorage::boot(&config).unwrap();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        let report = StartupReport {
            attempted: [[true; 2]; 32],
            family_results: [[Some(Err(FailureReason::InsufficientAssurance)); 2]; 32],
            ..StartupReport::default()
        };
        let (result, counts) = run_phase(Phase::Logging, || {
            storage.settle_startup(9, report, 0, false)
        });
        assert!(result.is_ok());
        assert!(counts.all_zero(), "boot settlement: {counts:?}");
        let mut bytes = vec![0u8; 65536];
        let len = reader.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..len]).unwrap();
        let frames = text
            .lines()
            .filter(|line| line.contains("kind=dns_assurance"))
            .count();
        assert!(frames > 0 && frames <= 32);
        assert_eq!(
            text.lines().count() as u64 + storage.logs.dropped(),
            65,
            "32 boot attempts, 32 startup names and one summary must be emitted or counted as stranded"
        );
        println!(
            "boot_snapshot_bytes={} boot_context_bytes={} max_real_frame_bytes={}",
            std::mem::size_of::<AssuranceSnapshot>(),
            std::mem::size_of::<super::AssuranceBoot>(),
            text.lines()
                .filter(|line| line.contains("kind=dns_assurance"))
                .map(|line| line.len() + 1)
                .max()
                .unwrap()
        );
    }

    #[cfg(feature = "alloc-witness")]
    fn seed_expiry_families(storage: &mut ServeStorage) {
        use crate::dns::cache::evidence::{Evidence, ResolverSource};
        use crate::dns::cache::{Family, Generation, StagedPositive};
        use crate::eligibility::NumericAddr;
        let proof =
            Evidence::new(false, false, false, ResolverSource::UNKNOWN, Some(1), 1000).unwrap();
        for ordinal in 0..32 {
            let name = storage.cache.name_index(ordinal).unwrap();
            for (family, address) in [
                (Family::A, NumericAddr::V4([8, 8, 8, 8].into())),
                (
                    Family::Aaaa,
                    NumericAddr::V6(
                        [
                            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                        ]
                        .into(),
                    ),
                ),
            ] {
                let staged = StagedPositive::stage_with_evidence(
                    name,
                    family,
                    Generation::INITIAL,
                    &[address],
                    1000,
                    1,
                    Some(proof),
                )
                .unwrap();
                storage.cache.publish_positive(&staged).unwrap();
                assert!(
                    storage
                        .cache
                        .family_retained(name, family, 1000)
                        .unwrap()
                        .unwrap()
                        .time_valid()
                );
            }
        }
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn expiry_fold_32_entries_64_families_is_bounded_and_allocation_free() {
        use crate::alloc::{Phase, run_phase};
        use crate::dns::transport::StartupReport;
        use std::fmt::Write as _;
        use std::os::unix::net::UnixStream;

        let mut doc = String::from(
            "listen = \"127.0.0.1:9\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
        );
        for i in 0..32 {
            write!(doc, "[allowed_fqdn.\"n{i}.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n").unwrap();
        }
        let config = crate::config::parse_config_document(&doc)
            .unwrap()
            .with_kernel_assigned_test_listener();
        let mut storage = ServeStorage::boot(&config).unwrap();
        let (_reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        storage.logs = crate::log::LogStore::with_fd(&writer).unwrap();
        storage
            .dns
            .begin_window(
                std::net::SocketAddr::from(([127, 0, 0, 1], 9)),
                *config.resolver_set(),
                1000,
                Duration::ZERO,
            )
            .unwrap();
        seed_expiry_families(&mut storage);
        let outcome = storage
            .settle_startup(1000, StartupReport::default(), 0, false)
            .unwrap();
        assert_eq!(
            outcome.decision(),
            super::StartupDecision::Serve(super::ServingMode::Full)
        );
        assert_eq!(storage.assurance.iter().flatten().count(), 32);
        let before = Instant::now();
        let deadline = storage.assurance_wake(before).unwrap().unwrap();
        assert!(deadline > before);
        std::thread::sleep(deadline.saturating_duration_since(before) + Duration::from_millis(25));
        let actual = Instant::now();
        let started = Instant::now();
        let (wake, plan_counts) = run_phase(Phase::Serving, || storage.assurance_wake(actual));
        let planning = started.elapsed();
        assert_eq!(wake.unwrap(), Some(actual));
        assert!(
            plan_counts.all_zero(),
            "64-family wake plan allocated: {plan_counts:?}"
        );
        let started = Instant::now();
        let ((), observe_counts) =
            run_phase(Phase::Serving, || storage.observe_assurance_expiry(actual));
        let observation = started.elapsed();
        assert!(
            observe_counts.all_zero(),
            "32-entry expiry observation allocated: {observe_counts:?}"
        );
        assert!(
            storage
                .assurance
                .iter()
                .flatten()
                .all(|state| state.sequence == 1)
        );
        assert!(storage.assurance_wake(Instant::now()).unwrap().is_none());
        println!(
            "expiry_seeded_entries=32 expiry_seeded_families=64 wake_plan_us={} observe_us={}",
            planning.as_micros(),
            observation.as_micros()
        );
    }
}
