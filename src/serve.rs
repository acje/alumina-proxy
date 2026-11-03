//! Boot-owned serving storage and the canonical startup-readiness rule.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use mio::net::TcpListener;

use crate::cache::{Cache, CacheError, Family, NameIndex};
#[cfg(test)]
use crate::config::FixedHostname;
use crate::config::{Config, Fqdn};
use crate::connect::ConnectRequest;
#[cfg(test)]
use crate::enforcement::action::DomainOrdinal;
use crate::enforcement::monitor::DnsAnomalyKind;
use crate::enforcement::state::Enforcement;
use crate::incident_report::{
    ClosedWindow, EligibleTransition, IncidentReport, IncidentSnapshot, SummaryCache,
};
use crate::log::{Level, LogStore, ResolverProbeSegment};
use crate::resolver::MAX_RESOLVERS;
use crate::schedule::Schedules;
use crate::startup_dns::{
    ExchangeClass, FailureReason, IncidentNote, ProbeVerdict, PublishedKind, STARTUP_WINDOW_SECS,
    StartupDns, StartupDnsError, StartupReport, TurnResult,
};
use crate::worker::{
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
                Some(crate::schedule::TypeIncident::Open { opened_at, reason }) => {
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
            if let Some(event) = self
                .incident_report
                .note_eligible_state(ordinal, has_eligible)
            {
                self.emit_eligible(ordinal, secs, event);
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
        let result = self
            .dns
            .advance_exchange(fqdn, &mut self.cache, &mut self.schedules)?;
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
            self.logs
                .startup_warning(secs, name.as_str(), family, reason);
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
        let generation = self
            .cache
            .entry(name_index, family)
            .map_err(StartupDnsError::Cache)?
            .generation();
        self.active_exchange_family = Some(family);
        self.dns
            .start_exchange(fqdn, family, ordinal, deadline, generation, class)?;
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
mod tests;

#[cfg(test)]
mod startup_integration;
