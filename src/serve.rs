//! Boot-owned serving storage and the canonical startup-readiness rule.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use mio::net::TcpListener;

use crate::cache::{Cache, CacheError, Family, NameIndex};
use crate::config::{Config, FixedHostname, Fqdn};
use crate::connect::ConnectRequest;
use crate::enforcement::action::DomainOrdinal;
use crate::enforcement::monitor::DnsAnomalyKind;
use crate::enforcement::state::Enforcement;
use crate::incident_report::{
    ClosedWindow, EligibleTransition, IncidentReport, IncidentSnapshot, IncidentSummary,
    TypeSummary,
};
use crate::log::{Level, LogStore, ResolverProbeSegment};
use crate::resolver::MAX_RESOLVERS;
use crate::schedule::Schedules;
use crate::startup_dns::{
    FailureReason, IncidentNote, ProbeVerdict, PublishedKind, STARTUP_WINDOW_SECS, StartupDns,
    StartupDnsError, StartupReport, TurnResult,
};
use crate::worker::{
    AdmissionError, AttemptLedger, ConnectPhase, Deadline, DecideError, SlotIndex, TunnelIndex,
    Worker, WorkerClock, WorkerView,
};

/// The explicit far-future boundary for [`ServeStorage::schedule_due_instant`].
/// A schedule due beyond `now0 + this many seconds` is clamped to this
/// boundary instead of collapsing to the current instant, so an extreme or
/// overflowing due can never wake the serving loop spuriously early
/// (alumina-sechd I19). Ten years is far beyond any refresh interval and is
/// always representable on every supported platform.
const SCHEDULE_FAR_FUTURE_SECS: u64 = 365 * 24 * 60 * 60 * 10;

/// Bound on the startup drain turns: the readiness decision enqueues one
/// `startup_name` record per unresolved name — at most `ALLOWLIST_MAX` (32) —
/// plus the one `startup_final` summary, so at most 33 records, and one
/// [`LogStore::drain_sink`] turn carries at most `SINK_MAX_OPS` (16) gathered
/// fragments or `SINK_MAX_BYTES` (64 KiB), whichever binds first. The worst
/// case is therefore
/// `max(ceil(33 / 16), ceil(33 x 8 KiB / 64 KiB)) = max(3, 5) = 5` turns; this
/// cap keeps one further turn of slack for a partial write that ends a turn
/// mid-record. A sink that makes no progress at all stops the loop earlier
/// (`WouldBlock`/failed) instead of spending the cap, and the real emission
/// (32 names of at most 380 B plus the summary, ~13 KiB) needs three.
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

/// The outcome of the boot-owned startup window: the readiness decision, the
/// single DNS-window exchange report, and the listener opened exactly when a
/// serving decision is taken.
pub struct StartupOutcome {
    /// The terminal decision, or the early [`ServingMode::Full`] decision when
    /// every name was usable and the listener opened immediately.
    pub decision: StartupDecision,
    /// The single 90-second DNS-window exchange report.
    pub report: StartupReport,
    /// The bound CONNECT listener for a serving decision; `None` for exit 75.
    pub listener: Option<TcpListener>,
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
        let cache = Cache::new(name_count).map_err(StartupDnsError::from)?;
        let schedules = Schedules::new(name_count).map_err(StartupDnsError::from)?;
        let dns = StartupDns::new()?;
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
        })
    }

    /// The single owned config/cache/clock view used for CONNECT decisions: a
    /// [`crate::worker::WorkerView`] bound to this storage's own config, cache,
    /// and clock authority, so no code can pair an unrelated config or clock
    /// with this cache (1cws M4r/M2r; destination-binding, docs/alumina-proxy.md:145).
    pub const fn work_view(&self) -> WorkerView<'_> {
        WorkerView::new(&self.config, &self.cache, self.worker.clock())
    }

    /// The whole-second DNS/cache serving clock, mounted on the same origin
    /// and epoch the startup window wrote receipts on: `now0` plus whole
    /// seconds since the window origin. The single origin+offset continuity
    /// that keeps cache freshness comparable in serving (1cws M2r).
    pub(crate) fn cache_secs(&self, now: Instant) -> u64 {
        self.now0
            .saturating_add(now.saturating_duration_since(self.origin).as_secs())
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
    pub const fn cache(&self) -> &Cache {
        &self.cache
    }

    /// The retained parsed configuration, read-only.
    pub(crate) const fn config(&self) -> &Config {
        &self.config
    }

    /// The retained refresh schedules, read-only.
    pub const fn schedules(&self) -> &Schedules {
        &self.schedules
    }

    /// The retained refresh schedules, mutable for the owner's startup
    /// selection and backoff bookkeeping.
    pub(crate) const fn schedules_mut(&mut self) -> &mut Schedules {
        &mut self.schedules
    }

    /// The retained DNS transport with its fixed response workspace.
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

    /// The ordinal of a CONNECT that matches an allowlist entry **exactly**,
    /// entry hostname and entry port together. A same-hostname different-port
    /// request is such a miss (no ordinal), so it is authoritatively denied by
    /// `decide` as `HostNotAllowlisted` rather than routed by bare hostname
    /// (alumina-9t6w B1). Resolution shares the single allowlist-pair predicate
    /// with the worker decision (alumina-sechd L14).
    pub(crate) fn ordinal_for_request(&self, request: &ConnectRequest) -> Option<DomainOrdinal> {
        let index = self
            .config
            .allowlist_position(request.hostname(), request.port())?;
        self.enforcement.control().ordinal(index)
    }

    /// The ordinal of a connection already authorized as the exact
    /// `<fqdn>:<port>` pair, derived from the slot's `approved` hostname and
    /// `approved_port` together. Enforcement attribution (early-data
    /// Block-Domain, the domain sweep, JA4 baselines) must key on the pair, so
    /// a same-hostname different-port allowlist entry gets its own ordinal and
    /// a configured Block on one port can never over-close or under-close the
    /// other (alumina-9t6w B1). Shares the single allowlist-pair predicate with
    /// the worker decision (alumina-sechd L14).
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
        use crate::cache::{Generation, StagedPositive};
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
        use crate::cache::{Generation, StagedPositive};
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
    /// schedule's current `TypeIncident` state: the opened-at second and latest
    /// failure reason for each family currently in incident, `None` otherwise.
    /// Used to seed the incident report's sticky per-window snapshot when a
    /// window opens, so the closing summary reflects the window's actual
    /// incident activity even when the incident recovers at the boundary turn.
    fn incident_snapshot(&self, ordinal: usize) -> [IncidentSnapshot; 2] {
        let mut snap = [None, None];
        for (i, family) in Family::ALL.iter().copied().enumerate() {
            snap[i] = match self.schedules.incident(ordinal, family) {
                Some(crate::schedule::TypeIncident::Open { opened_at, reason }) => {
                    Some((opened_at, reason.as_str()))
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
                    Some(crate::schedule::TypeIncident::Open { .. })
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
            let has_eligible = usable_name(&self.cache, name_index, secs).unwrap_or(false);
            match self
                .incident_report
                .note_eligible_state(ordinal, has_eligible)
            {
                Some(EligibleTransition::Lost) => self.emit_eligible_loss(ordinal, secs),
                Some(EligibleTransition::Recovered) => self.emit_eligible_recovered(ordinal, secs),
                None => {}
            }
        }
        for ordinal in 0..name_count {
            let both_closed = Family::ALL.iter().all(|&family| {
                matches!(
                    self.schedules.incident(ordinal, family),
                    Some(crate::schedule::TypeIncident::Closed)
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

    /// Emits one incident summary record for a closed window, folding the
    /// schedule's incident state and the cache entry snapshot for each family
    /// into the window counters (docs/alumina-proxy.md:80).
    fn emit_incident_summary(&mut self, ordinal: usize, closed: ClosedWindow, level: Level) {
        let Some(fqdn) = self.config.allowlist().get(ordinal) else {
            return;
        };
        let Some(name_index) = self.cache.name_index(ordinal) else {
            return;
        };
        let secs = self.cache_secs(Instant::now());
        let mut types = [TypeSummary::EMPTY; 2];
        for (i, family) in Family::ALL.iter().copied().enumerate() {
            // M1: the per-type incident fields come from the snapshot captured
            // into the closed window at rotation/close, not from the schedule
            // read live at emission — so a recovery coinciding with the window
            // boundary still reports the window's actual incident activity.
            let (start, reason) = match closed.incident[i] {
                Some((opened_at, reason)) => (Some(opened_at), Some(reason)),
                None => (None, None),
            };
            let (addrs, state, freshness, retirement) = self
                .cache
                .entry(name_index, family)
                .map_or((0, "empty", None, None), |entry| {
                    let (freshness, retirement) = entry.deadlines();
                    (
                        entry.bindings().len() as u64,
                        entry.state(secs).as_str(),
                        // L2: report remaining seconds until the freshness and
                        // retirement deadlines (docs/alumina-proxy.md:80), not
                        // the absolute monotonic deadlines.
                        freshness.map(|f| f.saturating_sub(secs)),
                        retirement.map(|r| r.saturating_sub(secs)),
                    )
                });
            types[i] = TypeSummary {
                start,
                elapsed: start.map_or(0, |s| closed.window_end.saturating_sub(s)),
                reason,
                last_positive: closed.last_positive[i],
                attempts: closed.per_type[i].attempts.value,
                failures: closed.per_type[i].failures.value,
                addrs,
                state,
                freshness,
                retirement,
            };
        }
        let summary = IncidentSummary {
            window_start: closed.window_start,
            window_end: closed.window_end,
            duration: closed.duration(),
            skipped: closed.skipped,
            overflow: closed.overflow,
            types,
            tunnels: closed.activity.tunnels.value,
            bytes: closed.activity.bytes.value,
            stale: closed.activity.stale.value,
        };
        self.logs
            .incident_summary(secs, fqdn.as_str(), level, &summary);
    }

    /// Emits the immediate error for a hostname that lost its eligible
    /// bindings (docs/alumina-proxy.md:79).
    fn emit_eligible_loss(&mut self, ordinal: usize, secs: u64) {
        if let Some(fqdn) = self.config.allowlist().get(ordinal) {
            self.logs.incident_eligible_loss(secs, fqdn.as_str());
        }
    }

    /// Emits the info notification for a hostname whose eligible bindings
    /// recovered (docs/alumina-proxy.md:79).
    fn emit_eligible_recovered(&mut self, ordinal: usize, secs: u64) {
        if let Some(fqdn) = self.config.allowlist().get(ordinal) {
            self.logs.incident_eligible_recovered(secs, fqdn.as_str());
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
        let result = self
            .dns
            .advance_exchange(fqdn, &mut self.cache, &mut self.schedules)?;
        self.drain_resolver_transitions();
        self.drain_dns_anomalies();
        self.drain_downgrade_to_plain();
        self.drain_probe_relocations();
        self.drain_expired_pin_certs();
        self.drain_incident_transitions();
        self.drain_incident_notes();
        let secs = self.cache_secs(Instant::now());
        if let Some(family) = family {
            match &result {
                TurnResult::Failed(reason) => {
                    self.incident_report.note_exchange_failure(
                        ordinal,
                        family,
                        secs,
                        reason.as_str(),
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

    /// Emits the per-failure `exchange_failed` record for a counted
    /// serving-loop exchange failure (G6-C04): the allowlist name is recovered
    /// from the ordinal captured before the advance settled the exchange. The
    /// startup window surfaces its own failures through the `startup_name` /
    /// `startup_final` records, so this serving-loop-only emission never
    /// duplicates that surface.
    pub(crate) fn note_exchange_failed(&mut self, ordinal: Option<usize>, reason: FailureReason) {
        let name = ordinal
            .and_then(|o| self.config.allowlist().get(o))
            .map(Fqdn::as_str);
        let secs = self.cache_secs(Instant::now());
        self.logs.exchange_failed(secs, name, reason.as_str());
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
                IncidentNote::Open { reason, .. } => {
                    self.logs
                        .incident_open(secs, fqdn.as_str(), family, reason.as_str());
                    let snapshot = self.incident_snapshot(ordinal);
                    self.incident_report
                        .note_incident_open(ordinal, secs, snapshot);
                }
                IncidentNote::Recovered { duration, .. } => {
                    self.logs
                        .incident_recovered(secs, fqdn.as_str(), family, duration);
                }
            }
        }
    }

    /// Emits the single per-window `startup_warning` for the first counted
    /// exchange failure, looking the name up from the allowlist internally so
    /// a shared owner never holds a config borrow across a log mutation.
    pub(crate) fn startup_warning_first(&mut self, secs: u64, ordinal: usize, family: Family) {
        if let Some(name) = self.config.allowlist().get(ordinal) {
            self.logs.startup_warning(secs, name.as_str(), family);
        }
    }

    /// Starts a cooperative DNS exchange on the retained transport for the
    /// named allowlist entry, dialing the currently active resolver. The
    /// exchange draws a fresh transaction id and records its deadline without
    /// waiting for network readiness; subsequent [`Self::advance_dns`] turns
    /// conclude it.
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
        let generation = self
            .cache
            .entry(name_index, family)
            .map_err(StartupDnsError::Cache)?
            .generation();
        self.active_exchange_family = Some(family);
        self.dns
            .start_exchange(fqdn, family, ordinal, deadline, generation)?;
        let secs = self.cache_secs(Instant::now());
        self.incident_report
            .note_exchange_attempt(ordinal, family, secs);
        Ok(())
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
    pub(crate) fn step_sweep(&mut self) -> Result<(), StartupDnsError> {
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
    pub(crate) fn step_corroboration(&mut self) -> Result<(), StartupDnsError> {
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
    /// instant, capturing its absolute setup deadline. Slot lifecycle actions
    /// are private to actual accept/connect/close event processing.
    ///
    /// # Errors
    ///
    /// `SlotCapacity` or `PendingCapacity`, mapped to HTTP 503 + close
    /// (docs/alumina-proxy.md:193).
    pub(crate) fn accept(&mut self, now: Instant) -> Result<SlotIndex, AdmissionError> {
        self.worker.admit(now)
    }

    /// The one owned CONNECT decision for an admitted slot: reads the setup
    /// deadline and the attempt ledger from the slot and cache seconds from
    /// this storage's clock authority. Does not consume the handle; the event
    /// processor still needs it to graduate or release.
    ///
    /// # Errors
    ///
    /// `NotInSetup` for a stale handle (unreachable by the handle discipline)
    /// or the underlying current-cache lookup error.
    pub(crate) fn decide(
        &self,
        slot: &SlotIndex,
        request: &ConnectRequest,
        now: Instant,
    ) -> Result<ConnectPhase, DecideError> {
        self.worker.decide(&self.work_view(), slot, request, now)
    }

    /// Records one failed attempt on the granted in-setup slot, advancing its
    /// slot-carried attempt ledger. See [`crate::worker::Worker::record_attempt`].
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
            crate::startup_dns::WindowInputs {
                config: &self.config,
                cache: &mut self.cache,
                schedules: &mut self.schedules,
                nameserver,
                now0,
                window,
            },
            &mut self.logs,
        )?;
        self.drain_resolver_transitions();
        self.drain_dns_anomalies();
        self.drain_downgrade_to_plain();
        self.drain_probe_relocations();
        self.drain_expired_pin_certs();
        self.drain_incident_transitions();
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
        let decision = if terminated {
            StartupDecision::Terminated
        } else {
            self.startup_decision(now0 + decision_seconds)?
        };
        let listener = match decision {
            StartupDecision::Serve(_) => Some(self.bind_listener()?),
            StartupDecision::Exit75 { .. } | StartupDecision::Terminated => None,
        };
        self.emit_startup_records(now0 + decision_seconds, &report, decision);
        Ok(StartupOutcome {
            decision,
            report,
            listener,
        })
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
        use crate::log::{FinalCounts, StartupStatus, StartupUnresolved};
        use crate::startup_dns::NameOutcome;
        let allowlist = self.config.allowlist();
        let names = allowlist.len() as u64;
        let status = match decision {
            StartupDecision::Serve(ServingMode::Full) => StartupStatus::Full,
            StartupDecision::Serve(ServingMode::Degraded) => StartupStatus::Degraded,
            StartupDecision::Exit75 { .. } => StartupStatus::Failed,
            StartupDecision::Terminated => StartupStatus::Terminated,
        };
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

/// A name is usable when either family holds an eligible non-retired positive
/// binding (canonical docs/alumina-proxy.md:65); validated negatives and unattempted
/// names are unresolved.
fn usable_name(cache: &Cache, name: NameIndex, now: u64) -> Result<bool, CacheError> {
    for family in Family::ALL {
        let entry = cache.entry(name, family)?;
        if entry.servable(now) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Generation, StagedPositive};
    use crate::eligibility::NumericAddr;
    use std::fmt::Write as _;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const FRESH: u64 = 1000;
    const TTL: u64 = 10;
    const RETIREMENT: u64 = FRESH + TTL + crate::cache::STALE_GRACE;

    fn idx(cache: &Cache, ordinal: usize) -> NameIndex {
        cache.name_index(ordinal).expect("admitted name ordinal")
    }

    fn v4(octets: [u8; 4]) -> NumericAddr {
        NumericAddr::V4(Ipv4Addr::from(octets))
    }

    fn v6(octets: [u8; 16]) -> NumericAddr {
        NumericAddr::V6(Ipv6Addr::from(octets))
    }

    fn config_with_allowance(count: usize, allowance: u8) -> Config {
        let names = match count {
            1 => vec!["alpha.example.org:443"],
            2 => vec!["alpha.example.org:443", "beta.example.org:443"],
            3 => vec![
                "alpha.example.org:443",
                "beta.example.org:443",
                "gamma.example.org:443",
            ],
            _ => panic!("test allowlist helper supports 1..=3 names"),
        };
        let mut doc = format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = {allowance}\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n"
        );
        for name in names {
            let _ = write!(
                doc,
                "[allowed_fqdn.\"{name}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
            );
        }
        crate::config::parse_config_document(&doc).expect("valid test config")
    }

    fn booted(count: usize, allowance: u8) -> ServeStorage {
        ServeStorage::boot(&config_with_allowance(count, allowance)).expect("boot serving storage")
    }

    fn with_boot_stack(body: impl FnOnce() + Send + 'static) {
        let t = std::thread::Builder::new()
            .name("boot-test".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn boot thread");
        t.join().expect("boot thread");
    }

    fn publish_a(cache: &mut Cache, ordinal: usize, receipt: u64, ttl: u64) {
        let name = cache.name_index(ordinal).expect("admitted name ordinal");
        let addrs = [v4([1, 1, 1, 1])];
        let staged =
            StagedPositive::stage(name, Family::A, Generation::INITIAL, &addrs, receipt, ttl)
                .expect("stage A binding");
        cache.publish_positive(&staged).expect("publish A binding");
    }

    fn publish_aaaa(cache: &mut Cache, ordinal: usize, receipt: u64, ttl: u64) {
        let name = cache.name_index(ordinal).expect("admitted name ordinal");
        let addrs = [v6([
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x11, 0x11,
        ])];
        let staged = StagedPositive::stage(
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &addrs,
            receipt,
            ttl,
        )
        .expect("stage AAAA binding");
        cache
            .publish_positive(&staged)
            .expect("publish AAAA binding");
    }

    #[test]
    fn empty_cache_names_are_unresolved() {
        let cache = Cache::new(1).unwrap();
        assert_eq!(usable_name(&cache, idx(&cache, 0), 0), Ok(false));
    }

    #[test]
    fn fresh_positive_binding_makes_name_usable() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH), Ok(true));
    }

    #[test]
    fn stale_positive_binding_remains_usable() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        let stale = FRESH + TTL + 1;
        assert!(stale < RETIREMENT);
        assert_eq!(usable_name(&cache, idx(&cache, 0), stale), Ok(true));
    }

    #[test]
    fn retired_binding_is_unresolved() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        assert_eq!(usable_name(&cache, idx(&cache, 0), RETIREMENT), Ok(false));
    }

    #[test]
    fn drain_dns_anomalies_accumulates_into_the_enforcement_monitor() {
        let mut storage = booted(1, 0);
        storage
            .dns
            .note_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
        storage
            .dns
            .note_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
        storage
            .dns
            .note_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
        storage.dns.note_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
        storage.drain_dns_anomalies();
        assert_eq!(
            storage
                .enforcement
                .monitor()
                .facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation),
            2
        );
        assert_eq!(
            storage
                .enforcement
                .monitor()
                .facts_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch),
            1
        );
        assert_eq!(
            storage
                .enforcement
                .monitor()
                .facts_dns_anomaly(DnsAnomalyKind::ExtremeTtl),
            1
        );
        storage.drain_dns_anomalies();
        assert_eq!(
            storage
                .enforcement
                .monitor()
                .facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation),
            2,
            "a second drain must not double-count a drained anomaly"
        );
    }

    #[test]
    fn either_family_positive_makes_name_usable() {
        let mut cache = Cache::new(1).unwrap();
        publish_aaaa(&mut cache, 0, FRESH, TTL);
        assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH + 5), Ok(true));
    }

    #[test]
    fn nxdomain_eviction_makes_name_unresolved() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        cache.evict_nxdomain(idx(&cache, 0)).unwrap();
        assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH + 5), Ok(false));
    }

    #[test]
    fn all_names_usable_decides_full_serve() {
        let mut storage = booted(2, 0);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        publish_a(&mut storage.cache, 1, FRESH, TTL);
        assert_eq!(
            storage.startup_decision(FRESH + 5),
            Ok(StartupDecision::Serve(ServingMode::Full))
        );
    }

    #[test]
    fn unresolved_within_allowance_serves_degraded() {
        let mut storage = booted(2, 1);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        let decision = storage.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
    }

    #[test]
    fn allowance_zero_requires_every_name_usable() {
        let mut storage = booted(2, 0);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        let decision = storage.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
    }

    #[test]
    fn trailing_unresolved_name_counts_against_allowance() {
        with_boot_stack(|| {
            let mut strict = booted(2, 0);
            publish_a(&mut strict.cache, 0, FRESH, TTL);
            let decision = strict.startup_decision(FRESH + 5).unwrap();
            assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
            let mut tolerant = booted(2, 1);
            publish_a(&mut tolerant.cache, 0, FRESH, TTL);
            let decision = tolerant.startup_decision(FRESH + 5).unwrap();
            assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
        });
    }

    #[test]
    fn trailing_last_name_unresolved_is_counted() {
        with_boot_stack(|| {
            let mut strict = booted(3, 0);
            publish_a(&mut strict.cache, 0, FRESH, TTL);
            publish_a(&mut strict.cache, 1, FRESH, TTL);
            let decision = strict.startup_decision(FRESH + 5).unwrap();
            assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
            let mut tolerant = booted(3, 1);
            publish_a(&mut tolerant.cache, 0, FRESH, TTL);
            publish_a(&mut tolerant.cache, 1, FRESH, TTL);
            let decision = tolerant.startup_decision(FRESH + 5).unwrap();
            assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
        });
    }

    #[test]
    fn retired_everywhere_is_exit75_with_exact_unresolved_count() {
        let mut storage = booted(2, 1);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        publish_a(&mut storage.cache, 1, FRESH, TTL);
        let decision = storage.startup_decision(RETIREMENT).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 2 });
    }

    #[test]
    fn binding_published_strictly_before_deadline_counts_at_the_snapshot() {
        let mut storage = booted(1, 0);
        publish_a(&mut storage.cache, 0, 1089, 1);
        assert_eq!(
            storage.startup_decision(1090).unwrap(),
            StartupDecision::Serve(ServingMode::Full)
        );
    }

    #[test]
    fn serve_storage_boot_corresponds_allowlist_at_boundary() {
        let config = config_with_allowance(2, 1);
        let storage = ServeStorage::boot(&config).expect("boot serving storage");
        assert_eq!(storage.cache().name_count(), config.allowlist().len());
        assert_eq!(storage.schedules().name_count(), config.allowlist().len());
        assert_eq!(
            storage.cache().name_count(),
            storage.schedules().name_count()
        );
    }

    #[test]
    fn work_view_is_bound_to_the_owning_storages_state() {
        use crate::connect::{ConnectParser, Feed};
        use crate::worker::{ConnectPhase, Deadline};
        use std::time::Instant;
        let mut storage = booted(1, 0);
        publish_a(&mut storage.cache, 0, FRESH + 5, TTL);
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(1);
        let mut parser = ConnectParser::new();
        let head = b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n";
        match parser.feed(head).expect("valid connect head") {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let req = *parser
            .result()
            .copied()
            .expect("connect result present")
            .as_ref()
            .expect("valid connect request");
        let slot = storage.accept(t0).expect("admitted via the owned seam");
        let phase = storage
            .decide(&slot, &req, now)
            .expect("decision via the owned seam");
        assert!(
            matches!(
                phase,
                ConnectPhase::Peer {
                    family: Family::A,
                    ..
                }
            ),
            "the owned seam must authorize this storage's own cache: {phase:?}"
        );
        assert_eq!(phase.status(), 200);
        assert_eq!(
            storage.setup_deadline(&slot),
            Some(Deadline::setup(t0)),
            "the accepted slot carries its own setup deadline"
        );
        storage.release(slot);
        assert_eq!(storage.occupied(), 0);
    }

    #[test]
    fn storage_cache_secs_is_mounted_on_the_dns_epoch() {
        use std::time::Instant;
        const DNS_EPOCH: u64 = 1_700_000_000;
        let mut storage = booted(1, 0);
        let origin = Instant::now();
        storage.mount_clock(origin, DNS_EPOCH);
        let later = origin + Duration::from_secs(7);
        assert_eq!(
            storage.cache_secs(later),
            DNS_EPOCH + 7,
            "serving cache seconds must continue from the mounted DNS epoch"
        );
        assert_eq!(
            storage.cache_secs(origin),
            DNS_EPOCH,
            "the mounted origin evaluates to the epoch itself, not zero"
        );
    }

    #[test]
    fn storage_decide_reads_slot_deadline_and_epoch_scale() {
        use crate::connect::{ConnectParser, Feed};
        use crate::worker::ConnectPhase;
        use std::time::Instant;
        const DNS_EPOCH: u64 = 1_700_000_000;
        let mut storage = booted(1, 0);
        storage.mount_clock(Instant::now(), DNS_EPOCH);
        publish_a(&mut storage.cache, 0, DNS_EPOCH + 1, 1);
        let t0 = Instant::now();
        let slot = storage.accept(t0).expect("admitted");
        let mut parser = ConnectParser::new();
        let head = b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n";
        match parser.feed(head).expect("valid connect head") {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let req = *parser
            .result()
            .copied()
            .expect("connect result present")
            .as_ref()
            .expect("valid connect request");
        let phase = storage.decide(&slot, &req, t0).expect("decision");
        assert!(
            matches!(
                phase,
                ConnectPhase::Peer {
                    family: Family::A,
                    ..
                }
            ),
            "fresh on the DNS scale must authorize the peer: {phase:?}"
        );
        let ConnectPhase::Peer {
            connect_deadline, ..
        } = phase
        else {
            panic!("expected Peer");
        };
        assert_eq!(
            connect_deadline.limit(),
            t0 + Duration::from_secs(crate::worker::CONNECT_DEADLINE_SECS),
            "the per-attempt deadline clips to the slot's setup deadline from its own fresh span"
        );
        storage.release(slot);
        assert_eq!(storage.occupied(), 0);
    }

    #[test]
    fn monitor_report_emits_at_whole_second_cadence_clears_on_commit_and_admits_ring_full_summary()
    {
        use crate::enforcement::action::FirstSlot;
        use crate::enforcement::policy::{AnyIllegalCause, Violation};
        use std::time::Instant;
        const DNS_EPOCH: u64 = 1_700_000_000;
        let mut storage = booted(1, 0);
        let origin = Instant::now();
        storage.mount_clock(origin, DNS_EPOCH);

        assert!(
            !storage.report_monitor_if_due(origin, false),
            "a clean monitor is never due"
        );

        let secs = storage.cache_secs(origin);
        storage.enforcement_mut().decide(
            &mut FirstSlot::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            secs,
        );
        assert!(
            storage.report_monitor_if_due(origin, false),
            "a dirty monitor is due at the whole-second boundary"
        );
        assert_eq!(
            storage.enforcement().monitor().report_drops(),
            0,
            "an unforced successful commit is not detail loss"
        );
        assert!(
            !storage.report_monitor_if_due(origin, false),
            "the same second suppresses the re-emission"
        );
        let one_second = origin + Duration::from_secs(1);
        assert!(
            !storage.report_monitor_if_due(one_second, false),
            "H1: no new event between seconds, a committed aggregate is not due again"
        );

        let secs = storage.cache_secs(one_second);
        storage.enforcement_mut().decide(
            &mut FirstSlot::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            secs,
        );
        assert!(
            storage.report_monitor_if_due(one_second, false),
            "a fresh event re-dirties the aggregate at the next whole second"
        );

        {
            let ring = storage.logs_mut();
            for _ in 0..(crate::log::QUEUE_SLOTS) {
                ring.startup_warning(DNS_EPOCH, "sub.example.org", Family::A);
            }
        }
        let next = one_second + Duration::from_secs(1);
        let secs = storage.cache_secs(next);
        storage.enforcement_mut().decide(
            &mut FirstSlot::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            secs,
        );
        assert!(
            storage.report_monitor_if_due(next, false),
            "a ring-full summary is still due at the next whole second"
        );
        assert_eq!(
            storage.enforcement().monitor().report_drops(),
            0,
            "SP-010: the reserved summary is admitted on the full ring, so no detail loss"
        );
        assert!(
            !storage.report_monitor_if_due(next + Duration::from_secs(1), false),
            "SP-010: the admitted summary clears the aggregate, so no re-emission without a fresh event"
        );
    }

    #[cfg(all(test, feature = "alloc-witness"))]
    #[test]
    fn startup_split_emission_over_full_allowlist_spends_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::config::ALLOWLIST_MAX;
        use crate::startup_dns::{FailureReason, NameOutcome, StartupReport};
        let mut doc = String::from(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
        );
        for ordinal in 0..ALLOWLIST_MAX {
            let _ = write!(
                doc,
                "[allowed_fqdn.\"n{ordinal}.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
            );
        }
        let config = crate::config::parse_config_document(&doc).expect("32-name config");
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let report = StartupReport {
            exchanges: 64,
            failed: 64,
            cancelled: 0,
            not_attempted: 0,
            resolved_names: 0,
            outcomes: [NameOutcome::Failed(FailureReason::Timeout); ALLOWLIST_MAX],
            first_failure: None,
        };
        let ((), counts) = run_phase(Phase::Logging, || {
            storage.emit_startup_records(9, &report, StartupDecision::Serve(ServingMode::Degraded));
        });
        assert!(
            counts.all_zero(),
            "32 startup_name attempts + the summary record allocate nothing: {counts:?}"
        );
        assert_eq!(
            storage.logs().dropped(),
            0,
            "the full-allowlist split enqueues all 33 records"
        );
    }

    #[cfg(all(test, feature = "alloc-witness"))]
    #[test]
    fn monitor_detection_report_and_drain_paths_spend_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::enforcement::action::FirstSlot;
        use crate::enforcement::policy::{AnyIllegalCause, Violation};
        const DNS_EPOCH: u64 = 1_700_000_000;
        let mut storage = booted(1, 0);
        storage.mount_clock(Instant::now(), DNS_EPOCH);
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let ((), counts) = run_phase(Phase::Serving, || {
            for _ in 0..256 {
                storage.enforcement_mut().decide(
                    &mut FirstSlot::new(),
                    Violation::AnyIllegal { cause },
                    DNS_EPOCH,
                );
            }
        });
        assert!(
            counts.all_zero(),
            "the detection fold (facts + first-slot action) allocates nothing: {counts:?}"
        );
        let ((), counts) = run_phase(Phase::Logging, || {
            for _ in 0..4 {
                let now = Instant::now();
                storage.report_monitor_if_due(now, false);
                storage.logs_mut().drain_sink();
            }
        });
        assert!(
            counts.all_zero(),
            "the summary report encode + ring + sink drain allocate nothing: {counts:?}"
        );
    }

    #[cfg(all(test, feature = "alloc-witness"))]
    #[test]
    fn monitor_nonempty_detail_ring_report_and_drain_spend_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::enforcement::action::Scope;
        use crate::enforcement::monitor::{CapturedDetail, CapturedFact, SlotCapture};
        use crate::enforcement::policy::{AnyIllegalCause, Effect};
        const DNS_EPOCH: u64 = 1_700_000_000;
        let mut storage = booted(1, 0);
        storage.mount_clock(Instant::now(), DNS_EPOCH);
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for slot in 0..crate::enforcement::monitor::CAPTURE_DETAIL_LEN {
            storage
                .enforcement_mut()
                .note_consumed_capture(SlotCapture {
                    slot,
                    generation: slot as u64,
                    detail: Some(CapturedDetail {
                        fact: CapturedFact::AnyIllegal(cause),
                        effect,
                    }),
                });
        }
        assert_eq!(
            storage.enforcement().monitor().capture_detail_len(),
            crate::enforcement::monitor::CAPTURE_DETAIL_LEN,
            "the witness populates a nonempty correlated-detail ring"
        );
        let ((), counts) = run_phase(Phase::Logging, || {
            for _ in 0..4 {
                let now = Instant::now();
                storage.report_monitor_if_due(now, false);
                storage.logs_mut().drain_sink();
            }
        });
        assert!(
            counts.all_zero(),
            "the correlated-detail x-segment encode + drain allocate nothing on a populated ring: {counts:?}"
        );
    }

    fn connect_request(head: &[u8]) -> crate::connect::ConnectRequest {
        use crate::connect::{ConnectParser, Feed};
        let mut parser = ConnectParser::new();
        match parser.feed(head).expect("valid connect head") {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        *parser
            .result()
            .copied()
            .expect("connect result present")
            .as_ref()
            .expect("valid connect request")
    }

    #[test]
    fn ordinal_for_request_resolves_exact_port_via_shared_allowlist_position_only() {
        let storage = booted(2, 1);
        let exact = connect_request(b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n");
        assert_eq!(
            storage.ordinal_for_request(&exact),
            storage.enforcement().control().ordinal(0),
            "the exact allowlist pair resolves to its entry ordinal"
        );
        let other_port = connect_request(b"CONNECT alpha.example.org:8443 HTTP/1.1\r\n\r\n");
        assert_eq!(
            storage.ordinal_for_request(&other_port),
            None,
            "same hostname on an unlisted port resolves to no ordinal (9t6w B1)"
        );
    }

    #[test]
    fn schedule_due_instant_saturates_instead_of_collapsing_to_now() {
        use std::time::Instant;
        let storage = booted(1, 0);
        let far = storage.schedule_due_instant(u64::MAX);
        assert!(
            far > Instant::now(),
            "overflow must saturate to the farthest instant, never collapse to now"
        );
    }

    #[test]
    fn report_incident_if_due_emits_window_summary_through_real_path() {
        let mut storage = booted(1, 0);
        let origin = Instant::now();
        storage.mount_clock(origin, 1000);
        // Open the A incident and its reporting window at secs 1000.
        storage
            .schedules_mut()
            .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
            .expect("open A incident");
        storage.report_incident_if_due(origin);
        // A second failure inside the window updates the latest reason.
        storage
            .schedules_mut()
            .note_exchange_failure(0, Family::A, 2000, FailureReason::Connect)
            .expect("update A incident");
        // The 3600s boundary rotation must emit the error summary for the
        // closed window through the real orchestration path (M2).
        storage.report_incident_if_due(origin + Duration::from_secs(3600));
        let record = storage
            .logs()
            .last_record_bytes()
            .expect("incident summary record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=incident_summary") && text.contains("level=error"),
            "the boundary rotation must emit the error summary: {text}"
        );
        assert!(
            text.contains("window_start=1000")
                && text.contains("window_end=4600")
                && text.contains("duration=3600"),
            "the summary must span the full closed window: {text}"
        );
        assert!(
            text.contains("types=\"a\"") && text.contains("a_start=1000"),
            "the summary must report the window's A incident: {text}"
        );
        assert!(
            text.contains("a_reason=\"connect\""),
            "the summary must carry the latest failure reason: {text}"
        );
    }

    #[test]
    fn boundary_recovery_coincidence_reports_window_incident_activity() {
        let mut storage = booted(1, 0);
        let origin = Instant::now();
        storage.mount_clock(origin, 1000);
        // Open the A incident and its reporting window at secs 1000.
        storage
            .schedules_mut()
            .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
            .expect("open A incident");
        storage.report_incident_if_due(origin);
        // A full recovery detected at the boundary turn: both incidents clear.
        storage
            .schedules_mut()
            .clear_exchange_incident(0, Family::A, 1000 + 3600)
            .expect("clear A incident");
        storage.report_incident_if_due(origin + Duration::from_secs(3600));
        // M1: the window's error summary must reflect the window's actual A
        // incident activity even though the incident recovered at the boundary
        // turn; L1: the zero-duration info summary must be suppressed, so the
        // error summary is the last record.
        let record = storage
            .logs()
            .last_record_bytes()
            .expect("incident summary record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=incident_summary") && text.contains("level=error"),
            "the boundary rotation must emit the error summary: {text}"
        );
        assert!(
            text.contains("types=\"a\"") && text.contains("a_start=1000"),
            "the error summary must report the window's A incident, not types=none: {text}"
        );
        assert!(
            text.contains("window_start=1000") && text.contains("window_end=4600"),
            "the error summary must span the full closed window: {text}"
        );
    }

    #[test]
    fn summary_reports_remaining_freshness_and_retirement_deadlines() {
        let mut storage = booted(1, 0);
        let origin = Instant::now();
        storage.mount_clock(origin, 1000);
        // A binding with receipt 1000 and TTL 10: freshness deadline 1010,
        // retirement deadline 1010 + STALE_GRACE = 260210.
        storage.publish_test_a(0);
        storage
            .schedules_mut()
            .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
            .expect("open A incident");
        storage.report_incident_if_due(origin);
        // Full recovery closes the partial window at secs 1500.
        storage
            .schedules_mut()
            .clear_exchange_incident(0, Family::A, 1500)
            .expect("clear A incident");
        storage.report_incident_if_due(origin + Duration::from_secs(500));
        let record = storage
            .logs()
            .last_record_bytes()
            .expect("info summary record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=incident_summary") && text.contains("level=info"),
            "the recovery must emit the info summary: {text}"
        );
        // L2: the deadlines are reported as remaining seconds (deadline - secs),
        // not the absolute monotonic deadlines. The summary's secs is the
        // emission-time clock read (1000 here): freshness 1010 - 1000 = 10,
        // retirement 260210 - 1000 = 259210.
        assert!(
            text.contains("a_freshness=10") && text.contains("a_retirement=259210"),
            "a_freshness/a_retirement must be remaining seconds, not absolute: {text}"
        );
    }
}

#[cfg(test)]
mod startup_integration {
    use super::{LogStore, ServeStorage, ServingMode, StartupDecision, StartupReport};
    use crate::cache::Family;
    use crate::config::{Config, parse_config_document};
    use std::fmt::Write as _;
    use std::io::{self, ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    const NOW0: u64 = 1000;

    fn config_with(names: &str, allowance: u8, listen_port: u16) -> Config {
        let mut doc = format!(
            "listen = \"127.0.0.1:{listen_port}\"\nstartup_unresolved_allowance = {allowance}\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n"
        );
        for name in names.split(", ") {
            let name = name.trim_matches('"');
            let _ = write!(
                doc,
                "[allowed_fqdn.\"{name}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
            );
        }
        parse_config_document(&doc).expect("valid test config")
    }

    fn ephemeral_port() -> u16 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        port
    }

    fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
        let mut lenb = [0u8; 2];
        if sock.read_exact(&mut lenb).is_err() {
            return None;
        }
        let qlen = usize::from(u16::from_be_bytes(lenb));
        if qlen == 0 || qlen > 2048 {
            return None;
        }
        let mut q = vec![0u8; qlen];
        if sock.read_exact(&mut q).is_err() {
            return None;
        }
        Some(q)
    }

    fn write_message(sock: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
        let mut out = Vec::with_capacity(msg.len() + 2);
        out.extend_from_slice(
            &u16::try_from(msg.len())
                .expect("dns message fits u16 length prefix")
                .to_be_bytes(),
        );
        out.extend_from_slice(msg);
        sock.write_all(&out)?;
        sock.flush()
    }

    struct DnsResponder {
        addr: SocketAddr,
    }

    impl DnsResponder {
        fn spawn<F>(mut on_query: F) -> DnsResponder
        where
            F: FnMut(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
            let addr = listener.local_addr().expect("responder address");
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut sock) = stream else {
                        break;
                    };
                    while let Some(query) = read_query(&mut sock) {
                        let Some(reply) = on_query(query) else {
                            break;
                        };
                        if write_message(&mut sock, &reply).is_err() {
                            break;
                        }
                    }
                }
            });
            DnsResponder { addr }
        }
    }

    fn build_positive(query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 16 {
            return None;
        }
        let tid = u16::from_be_bytes([query[0], query[1]]);
        let qname = &query[12..query.len() - 4];
        let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
        let rdata: &[u8] = match qtype {
            1 => &[1, 1, 1, 1],
            28 => &[
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
            _ => return None,
        };
        let mut msg = Vec::with_capacity(query.len() + 22);
        msg.extend_from_slice(&tid.to_be_bytes());
        msg.extend_from_slice(&0x8000u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&query[12..]);
        msg.extend_from_slice(qname);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("rdata fits u16 wire length")
                .to_be_bytes(),
        );
        msg.extend_from_slice(rdata);
        Some(msg)
    }

    fn qname_contains(query: &[u8], label: &[u8]) -> bool {
        query.windows(label.len()).any(|w| w == label)
    }

    #[test]
    fn full_serve_opens_listener_early_before_the_window_elapses() {
        let window = Duration::from_secs(2);
        let port = ephemeral_port();
        let config = config_with(
            "\"alpha.example.org:443\", \"beta.example.org:443\"",
            0,
            port,
        );
        let responder = DnsResponder::spawn(|q| build_positive(&q));
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(outcome.decision, StartupDecision::Serve(ServingMode::Full));
        assert_eq!(outcome.report.resolved_names, 2);
        let listener = outcome.listener.expect("listener bound for full serve");
        assert_eq!(
            listener.local_addr().expect("listener address").port(),
            port
        );
        assert!(
            elapsed < window,
            "all-usable startup must return early, not wait the window"
        );
        let conn = TcpStream::connect(("127.0.0.1", port));
        assert!(conn.is_ok(), "bound listener must accept connections");
    }

    #[test]
    fn exit75_is_decided_only_at_the_actual_window_deadline() {
        let window = Duration::from_millis(300);
        let port = ephemeral_port();
        let config = config_with(
            "\"alpha.example.org:443\", \"beta.example.org:443\"",
            0,
            port,
        );
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(outcome.decision, StartupDecision::Exit75 { unresolved: 1 });
        assert!(
            outcome.listener.is_none(),
            "exit 75 must not bind a listener"
        );
        assert!(
            elapsed >= window,
            "unresolved startup must not be decided before the deadline (early snapshot)"
        );
        let conn = TcpStream::connect(("127.0.0.1", port));
        assert!(
            matches!(conn, Err(ref err) if err.kind() == ErrorKind::ConnectionRefused),
            "exit 75 must leave the listen port unreachable"
        );
    }

    #[test]
    fn degraded_is_decided_only_at_the_actual_window_deadline() {
        let window = Duration::from_millis(300);
        let port = ephemeral_port();
        let config = config_with(
            "\"alpha.example.org:443\", \"beta.example.org:443\"",
            1,
            port,
        );
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(
            outcome.decision,
            StartupDecision::Serve(ServingMode::Degraded)
        );
        assert!(
            outcome.listener.is_some(),
            "degraded serve must bind a listener"
        );
        assert!(
            elapsed >= window,
            "degraded startup must not be decided before the deadline (early snapshot)"
        );
    }

    #[test]
    fn failed_lookup_retries_within_the_window_and_recovers_to_full() {
        let window = Duration::from_secs(2);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org:443\"", 0, port);
        let mut queries = 0u32;
        let responder = DnsResponder::spawn(move |query| {
            queries += 1;
            if queries <= 2 {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(
            outcome.decision,
            StartupDecision::Serve(ServingMode::Full),
            "the windowed retry must recover the failed lookup"
        );
        assert_eq!(outcome.report.resolved_names, 1);
        assert_eq!(outcome.report.failed, 2);
        assert!(outcome.listener.is_some());
        assert!(
            elapsed < window,
            "recovered startup must return early, not wait for the deadline"
        );
    }

    #[test]
    fn retried_failures_and_never_attempted_sibling_report_truthful_not_attempted() {
        let window = Duration::from_millis(1600);
        let port = ephemeral_port();
        let config = config_with(
            "\"alpha.example.org:443\", \"beta.example.org:443\"",
            1,
            port,
        );
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
        assert!(
            outcome.report.failed >= 4,
            "beta retried at least once after its first failed exchange: {}",
            outcome.report.failed
        );
        assert_eq!(
            outcome.report.not_attempted, 1,
            "only alpha's sibling family went un-attempted; retried failures must \
             not erase the never-attempted slots (exchanges {}, failed {}, resolved {}):",
            outcome.report.exchanges, outcome.report.failed, outcome.report.resolved_names,
        );
    }

    #[test]
    fn resolved_names_family_schedule_survives_for_serving_refresh() {
        let window = Duration::from_millis(1600);
        let port = ephemeral_port();
        let config = config_with(
            "\"alpha.example.org:443\", \"beta.example.org:443\"",
            1,
            port,
        );
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
        assert_eq!(
            storage.schedules().due_time(0, Family::Aaaa).unwrap(),
            Some(NOW0),
            "a resolved name's sibling family must keep its seeded due for the \
             serving refresh, never be re-clobbered to a later now"
        );
    }

    #[test]
    fn resolved_name_sibling_stays_selectable_after_startup_for_serving() {
        let window = Duration::from_millis(1600);
        let port = ephemeral_port();
        let config = config_with(
            "\"alpha.example.org:443\", \"beta.example.org:443\"",
            1,
            port,
        );
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
        assert_eq!(
            storage.schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(NOW0),
            "sibling due must be preserved for the serving refresh"
        );
        let selected = storage
            .schedules
            .select_due(NOW0 + 2)
            .expect("a future serving refresh must be selectable")
            .expect("alpha AAAA must not be stuck in-flight after the window");
        assert_eq!(selected.name(), 0);
        assert_eq!(selected.family(), Family::Aaaa);
    }

    /// The widest legal allowlist: `ALLOWLIST_MAX` keyed FQDNs, each exactly
    /// `FQDN_MAX_LEN` bytes (four labels, the longest three at the 63-byte
    /// bound), distinct per name, in one document under
    /// [`crate::config::CONFIG_DOC_LIMIT`]. Every name stays unresolved in the
    /// tests below, so the startup emission is the 32 + 1 record worst case.
    fn widest_allowlist_config() -> Config {
        use crate::config::{ALLOWLIST_MAX, CONFIG_DOC_LIMIT, FQDN_MAX_LEN};
        let mut doc = String::from(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
        );
        for ordinal in 0..ALLOWLIST_MAX {
            let mut first = format!("n{ordinal}");
            while first.len() < 63 {
                first.push('a');
            }
            let name = format!(
                "{first}.{}.{}.{}",
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(FQDN_MAX_LEN - 3 * 63 - 3)
            );
            assert_eq!(name.len(), FQDN_MAX_LEN, "the widest legal FQDN");
            let _ = write!(
                doc,
                "[allowed_fqdn.\"{name}:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
            );
        }
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "the widest legal document ({} B) fits the {CONFIG_DOC_LIMIT} B bound",
            doc.len()
        );
        let config = crate::config::parse_config_document(&doc).expect("widest legal config");
        assert_eq!(config.allowlist().len(), ALLOWLIST_MAX);
        assert!(
            config
                .allowlist()
                .iter()
                .all(|name| name.as_str().len() == FQDN_MAX_LEN),
            "every allowlist entry sits at the 253-byte bound"
        );
        config
    }

    /// Every allowlisted name unresolved, with a full failed-exchange report.
    fn all_unresolved_report() -> StartupReport {
        use crate::config::ALLOWLIST_MAX;
        use crate::startup_dns::NameOutcome;
        StartupReport {
            exchanges: 64,
            failed: 64,
            cancelled: 0,
            not_attempted: 0,
            resolved_names: 0,
            outcomes: [NameOutcome::Negative; ALLOWLIST_MAX],
            first_failure: None,
        }
    }

    /// A real file sink the store writes through its own unbuffered syscall
    /// path, so the drain is observed as bytes on a descriptor rather than
    /// through the test-only `flush_all` loop.
    fn temp_sink_file() -> std::fs::File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "alumina-serve-log-{}-{}.log",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .expect("temp sink file")
    }

    /// A socketpair whose writer is already full, so every write is a real
    /// `WouldBlock` on a live nonblocking descriptor.
    fn stalled_sink() -> (
        LogStore,
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (reader, mut writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let filler = [b'#'; 8 * 1024];
        let mut accepted = 0usize;
        while accepted < (1 << 20) {
            match writer.write(&filler) {
                Ok(0) => break,
                Ok(n) => accepted += n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("filling the stalled sink: {err}"),
            }
        }
        assert!(accepted > 0, "the socket buffer accepted the filler");
        let store = LogStore::with_fd(&writer).expect("stalled sink store");
        (store, reader, writer)
    }

    /// B-D1 regression: the readiness decision enqueues 33 records but one
    /// `drain_sink` turn carries at most 16 fragments, so the bounded turn loop
    /// must deliver every `startup_name` record and the summary to the real
    /// sink — in ascending ordinal order, summary last — before the `Exit75`
    /// decision that ends the process.
    #[test]
    fn startup_emission_over_widest_config_reaches_the_real_sink_before_exit75() {
        use crate::config::ALLOWLIST_MAX;
        use std::io::{Read, Seek};
        let config = widest_allowlist_config();
        let allowlist = config.allowlist();
        assert_eq!(allowlist.len(), ALLOWLIST_MAX);
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let mut file = temp_sink_file();
        storage.logs = LogStore::with_fd(&file).expect("file sink store");
        storage.emit_startup_records(
            9,
            &all_unresolved_report(),
            StartupDecision::Exit75 { unresolved: 32 },
        );
        assert_eq!(storage.logs.len(), 0, "the queue is empty after the drain");
        assert_eq!(
            storage.logs.dropped(),
            0,
            "all 33 records were enqueued and delivered, none dropped"
        );
        let mut out = Vec::new();
        file.rewind().expect("rewind the sink");
        file.read_to_end(&mut out).expect("read the sink");
        let text = String::from_utf8(out).expect("ascii records");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            ALLOWLIST_MAX + 1,
            "32 startup_name records plus the summary reach the sink"
        );
        for (ordinal, line) in lines[..ALLOWLIST_MAX].iter().enumerate() {
            assert_eq!(
                *line,
                format!(
                    "level=info kind=startup_name secs=9 ordinal={ordinal} name=\"{}\" outcome=negative",
                    allowlist.get(ordinal).expect("allowlist ordinal").as_str()
                ),
                "record {ordinal}: ascending ordinal order and the full, untruncated FQDN"
            );
        }
        assert_eq!(
            lines[ALLOWLIST_MAX],
            "level=info kind=startup_final secs=9 status=\"failure\" allowance=0 usable=0 unresolved=32 exchanges=64 failed=64 not_attempted=0 dropped=0 names_dropped=0",
            "the aggregate readiness record is last and reports no loss"
        );
    }

    /// The stalled-sink half of the bounded loop: a sink that answers
    /// `WouldBlock` stops the drain after the first refusing turn instead of
    /// spending the cap or spinning, records survive for a later turn on a
    /// serving decision, and a decision that exits counts each stranded record
    /// exactly once.
    #[test]
    fn startup_drain_stops_on_a_stalled_sink_and_counts_each_stranded_record_once() {
        use crate::config::ALLOWLIST_MAX;

        let config = widest_allowlist_config();
        let report = all_unresolved_report();
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let (store, _reader, _writer) = stalled_sink();
        storage.logs = store;
        storage.emit_startup_records(9, &report, StartupDecision::Serve(ServingMode::Degraded));
        assert_eq!(
            storage.logs.len(),
            ALLOWLIST_MAX + 1,
            "a stalled sink ends the drain with every record still queued"
        );
        assert_eq!(
            storage.logs.sink_ops(),
            0,
            "the stalled sink accepted no fragment"
        );
        assert!(
            !storage.logs.sink_ready(),
            "the stop reason is the stalled sink, not the iteration cap"
        );
        assert_eq!(
            storage.logs.dropped(),
            0,
            "a serving decision counts nothing: the records are still deliverable"
        );
        let (store, _reader, _writer) = stalled_sink();
        storage.logs = store;
        storage.emit_startup_records(9, &report, StartupDecision::Exit75 { unresolved: 32 });
        assert_eq!(
            storage.logs.len(),
            0,
            "the queue an exiting owner cannot deliver is cleared"
        );
        assert_eq!(
            storage.logs.dropped(),
            (ALLOWLIST_MAX + 1) as u64,
            "each undeliverable record is counted exactly once, never twice"
        );
    }
}
