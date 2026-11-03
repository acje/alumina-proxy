//! Worker-policy core for the serving integration: current-cache CONNECT
//! authorization, canonical per-tunnel upstream address selection, the fixed
//! slot lifecycle the single worker owns, and precise typed deadlines, as a
//! pure nonalloc typed substrate.
//!
//! This is the decision substrate of the single-owner worker (oracle gap G1,
//! G6): it owns no sockets and performs no I/O, so every path is deterministic
//! and unit-testable. The mio event loop, the `ClientHello` two-barrier gate,
//! and the byte-conserving relay are later increments and make no serving
//! claim here; the boot-owned traffic buffers this core will hand out live in
//! [`crate::inventory::TrafficStorage`].
//!
//! Setup (10 s) and per-attempt connect (2 s) deadlines are anchored on the
//! precise monotonic clock ([`Deadline`]) so a fractional-second initiation is
//! never truncated toward an earlier whole second (docs/alumina-proxy.md:169,189;
//! 1cws M2r). The DNS cache clock is whole seconds, derived from the same
//! anchor only through the explicit [`WorkerClock::cache_secs`] conversion.
//!
//! The config/cache pair reachable by a decision is constructed only by the
//! storage that owns both ([`crate::runtime::storage::ServeStorage::work_view`]; 1cws
//! M4r), and the fixed slot table is owned by [`Worker`] as a typed enum
//! lifecycle — the table, not a detached permit or a Copy accounting object,
//! owns the counts, so one owner can never release capacity on behalf of
//! another (9pac H1; 1cws H1r).
//!
//! Family alternation (docs/alumina-proxy.md:82) is driven by the *Connecting lifecycle*
//! previous-family transition input, never by a family bit stored in
//! [`AttemptCounts`]: the tunnel still stores exactly its two per-family
//! attempt counters (oracle alumina-ufrw; docs D5a). Each per-attempt connect
//! deadline is freshly clipped to the absolute setup deadline at the attempt
//! it initiates (docs/alumina-proxy.md:189).

use std::time::{Duration, Instant};

use crate::config::Config;
use crate::dns::cache::{Cache, CacheError, Entry, EntryState, Family, NameIndex};
use crate::eligibility::NumericAddr;
use crate::inspection::connect::{CONNECT_LIMIT, ConnectRequest};
use crate::inventory::{BUFFER_BYTES, TUNNEL_SLOTS};

/// Maximum concurrent tunnels, including pending setups (docs/alumina-proxy.md:160).
pub const MAX_TUNNELS: usize = TUNNEL_SLOTS;

/// Maximum concurrent pending (in-setup) tunnels; never 640 (docs/alumina-proxy.md:160).
pub const MAX_PENDING_SETUPS: usize = 128;

/// Sequential upstream connection attempts per tunnel (docs/alumina-proxy.md:82).
pub const MAX_UPSTREAM_ATTEMPTS: usize = 4;

/// Absolute setup deadline after accept, never reset (docs/alumina-proxy.md:169,189).
pub const SETUP_DEADLINE_SECS: u64 = 10;

/// Per-attempt upstream connect deadline, clipped to the setup deadline
/// (docs/alumina-proxy.md:169,82).
pub const CONNECT_DEADLINE_SECS: u64 = 2;

/// CONNECT request-head bound reused from the parser (docs/alumina-proxy.md:163).
pub const CONNECT_HEAD_LIMIT: usize = CONNECT_LIMIT;

/// One directional traffic buffer handed to a tunnel from boot storage
/// (docs/alumina-proxy.md:183). Sized here so the worker owns the storage contract;
/// instances live in the boot pool, never on this core's stack.
pub type TrafficBuffer = [u8; BUFFER_BYTES];

/// The service's single clock authority: a precise monotonic boot anchor for
/// setup/connect deadlines plus the DNS whole-second epoch (`dns0`) whose
/// scale the cache is written on. Cache seconds are mounted on `dns0`, so a
/// serving evaluation is comparable against the startup receipts' own scale
/// (`startup_dns.rs` `now0 + elapsed`) instead of a fresh zero anchor that keeps
/// every entry permanently fresh (1cws M2r; w6xo). Constructed only by the
/// storage that owns the cache and worker (crate-internal), so no caller can
/// pair a free clock with a decision.
#[derive(Clone, Copy, Debug)]
pub struct WorkerClock {
    epoch: Instant,
    dns0: u64,
}

impl WorkerClock {
    /// One authority over both clocks: `epoch` is the precise monotonic boot
    /// anchor, `dns0` the DNS whole-second epoch the startup window wrote
    /// receipts on. The storage that owns the cache, schedules, and the single
    /// worker constructs this pairing exactly once.
    pub(crate) const fn new(epoch: Instant, dns0: u64) -> WorkerClock {
        WorkerClock { epoch, dns0 }
    }

    /// The precise monotonic boot anchor, shared by all precise deadlines.
    #[expect(
        dead_code,
        reason = "designed WorkerClock boot-anchor accessor; no consumer yet"
    )]
    pub(crate) const fn epoch(self) -> Instant {
        self.epoch
    }

    /// The whole-second DNS/cache value for `now`, mounted on `dns0`: `dns0`
    /// plus whole seconds since the boot anchor. This is the only conversion
    /// from wall time to the cache clock, and it must agree with startup's
    /// `now0 + elapsed` scale.
    #[must_use]
    pub fn cache_secs(&self, now: Instant) -> u64 {
        self.dns0
            .saturating_add(now.saturating_duration_since(self.epoch).as_secs())
    }
}

/// Per-family upstream connection attempt counts for one tunnel (docs/alumina-proxy.md:82).
///
/// The tunnel stores only these two counts, never addresses or cache
/// references, so a cache replacement between attempts takes effect at the
/// next attempt. No family bit is stored here: the family of the just-failed
/// Connecting attempt arrives as the previous-family transition input on each
/// retry (oracle alumina-ufrw), keeping these exactly two counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptCounts {
    a: u8,
    aaaa: u8,
}

impl AttemptCounts {
    #[must_use]
    pub const fn new() -> AttemptCounts {
        AttemptCounts { a: 0, aaaa: 0 }
    }

    #[must_use]
    pub const fn a(self) -> u8 {
        self.a
    }

    #[must_use]
    pub const fn aaaa(self) -> u8 {
        self.aaaa
    }

    /// Total attempts across both families.
    #[must_use]
    pub const fn total(self) -> u8 {
        self.a.saturating_add(self.aaaa)
    }

    /// Returns the counts advanced by one attempt in `family`.
    #[must_use]
    pub const fn record(self, family: Family) -> AttemptCounts {
        match family {
            Family::A => AttemptCounts {
                a: self.a.saturating_add(1),
                ..self
            },
            Family::Aaaa => AttemptCounts {
                aaaa: self.aaaa.saturating_add(1),
                ..self
            },
        }
    }
}

/// The attempt-budget state a connecting tunnel carries in its own slot: the
/// two per-family counters plus the family of the last recorded attempt (the
/// `previous` transitioning input for family alternation on the next retry).
/// It lives in the slot rather than arriving as a caller argument, so the
/// attempt budget is self-enforcing once a failed attempt is recorded back
/// into the worker. No addresses or cache references cross its boundary in
/// either direction, so a cache replacement between attempts still takes
/// effect at the next attempt (docs/alumina-proxy.md:82).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptLedger {
    counts: AttemptCounts,
    previous: Option<Family>,
}

impl AttemptLedger {
    #[must_use]
    pub const fn new() -> AttemptLedger {
        AttemptLedger {
            counts: AttemptCounts::new(),
            previous: None,
        }
    }

    /// The per-family counters of the ledger.
    #[must_use]
    pub const fn counts(self) -> AttemptCounts {
        self.counts
    }

    /// The family the last recorded attempt used, when any.
    #[must_use]
    pub const fn previous(self) -> Option<Family> {
        self.previous
    }

    /// The ledger advanced by one failed attempt in `family`.
    #[must_use]
    pub const fn record(self, family: Family) -> AttemptLedger {
        AttemptLedger {
            counts: self.counts.record(family),
            previous: Some(family),
        }
    }
}

/// A fixed, saturating deadline on the precise monotonic clock. Computed once
/// from its `Instant` anchor; expiry is evaluated against `now` exactly, so
/// delayed timer processing can never extend an authorization window
/// (docs/alumina-proxy.md:82,189) and a connect deadline initiated mid-second expires a
/// full 2.0 s later, never after 1.x s of whole-second truncation (1cws M2r).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    limit: Instant,
}

impl Deadline {
    /// The absolute setup deadline: 10 s after successful accept, never reset
    /// (docs/alumina-proxy.md:169,189). Saturates to the accept instant on clock
    /// overflow, leaving an unrepresentable deadline already expired.
    #[must_use]
    pub fn setup(accepted: Instant) -> Deadline {
        accepted
            .checked_add(Duration::from_secs(SETUP_DEADLINE_SECS))
            .map_or(Deadline { limit: accepted }, |limit| Deadline { limit })
    }

    /// A fresh per-attempt upstream connect deadline: 2 s from `now`, clipped
    /// to the setup deadline (docs/alumina-proxy.md:169,189). Created at the initiation of
    /// the attempt it bounds, so an earlier attempt's expired deadline is never
    /// carried into this one and cannot be mistaken for the setup deadline
    /// (9pac M1).
    #[must_use]
    pub fn connect_attempt(now: Instant, setup: Deadline) -> Deadline {
        let fresh = now
            .checked_add(Duration::from_secs(CONNECT_DEADLINE_SECS))
            .unwrap_or(now);
        Deadline {
            limit: if fresh < setup.limit {
                fresh
            } else {
                setup.limit
            },
        }
    }

    #[must_use]
    pub const fn limit(self) -> Instant {
        self.limit
    }

    #[must_use]
    pub fn is_expired(self, now: Instant) -> bool {
        now >= self.limit
    }
}

/// Destination-selection outcome for one connection attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerDecision {
    /// Attempt a TCP connection to this eligible destination for `family`.
    Peer { addr: NumericAddr, family: Family },
    /// No family remains with an unused, non-retired, eligible binding.
    NoFamily,
}

/// The terminal CONNECT-phase decision for one tunnel, computed from the
/// current cache only. Everything that can refuse before an upstream socket
/// is opened is decided here, so a refusal outcome guarantees no upstream peer
/// is ever attempted (effect non-reachability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectPhase {
    /// The CONNECT hostname is not allowlisted (HTTP 403).
    Forbidden,
    /// Allowlisted but the name currently has no eligible non-retired binding
    /// at any outstanding per-family cursor: never resolved, or all remaining
    /// addresses are retired (HTTP 502, "no resolved addresses"; docs/alumina-proxy.md:83).
    NoBinding,
    /// The absolute setup deadline has passed before the forwarding gate
    /// opened (HTTP 504; docs/alumina-proxy.md:83).
    DeadlineExhausted,
    /// All allowed upstream attempts were consumed (HTTP 502, "upstream
    /// connection failed"; docs/alumina-proxy.md:83). Distinct from [`ConnectPhase::NoBinding`]
    /// so the two 502 reasons and bodies are never conflated (9pac M5).
    CandidatesExhausted,
    /// Proceed: dial this eligible destination for this family within the
    /// fresh clipped per-attempt `connect_deadline`. The peer stays fixed once
    /// committed; retries only ever follow failed establishment.
    Peer {
        addr: NumericAddr,
        family: Family,
        connect_deadline: Deadline,
    },
}

impl ConnectPhase {
    /// The canonical fixed status for this phase (docs/alumina-proxy.md:83;
    /// canonical refusal matrix at src/serving/policy.rs:8-24): 403
    /// not-allowlisted, 502 for both no-binding and candidates-exhausted, 504
    /// setup deadline, 200 for an authorized `Peer`. HTTP 503 is
    /// capacity-only and lives in [`AdmissionError`]; HTTP 400 malformed is
    /// parser-owned and never reaches the worker. Pinned by
    /// `refusal_statuses_follow_the_canonical_fixed_matrix`.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            ConnectPhase::Forbidden => 403,
            ConnectPhase::NoBinding | ConnectPhase::CandidatesExhausted => 502,
            ConnectPhase::DeadlineExhausted => 504,
            ConnectPhase::Peer { .. } => 200,
        }
    }
}

/// A setup-phase slot identifier granted by [`Worker::admit`]. It is moved
/// (never copied) between the worker's lifecycle transitions and consumed by
/// [`Worker::release`], so a stale handle can never free a slot that a later
/// admit reused for another owner (9pac H1; 1cws H1r). The table, not a permit
/// object, owns the accounting.
#[derive(Debug, PartialEq, Eq)]
pub struct SlotIndex(u16);

impl SlotIndex {
    pub(crate) const fn index(&self) -> usize {
        self.0 as usize
    }
}

/// The established-phase handle produced by graduating a setup with
/// [`Worker::finish_setup`]: the same physical slot, now in a distinct type so
/// a setup handle can never graduate or release an established tunnel and an
/// established handle can never corrupt pending accounting (9mq9 H1r, typed
/// transition).
#[derive(Debug, PartialEq, Eq)]
pub struct TunnelIndex(u16);

impl TunnelIndex {
    pub(crate) const fn index(&self) -> usize {
        self.0 as usize
    }
}

/// The lifecycle of one fixed tunnel slot: exactly one of free, in setup, or
/// established. Encoding the lifecycle as an enum makes a slot's state
/// unambiguous and makes every transition mutate exactly that slot, so
/// graduating or releasing a tunnel can never decrement another tunnel's
/// pending count (9pac H1; 1cws H1r).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Free,
    InSetup {
        setup_deadline: Deadline,
        attempts: AttemptLedger,
    },
    Established {
        setup_deadline: Deadline,
    },
}

/// Reasons the single worker can refuse a new setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    SlotCapacity,
    PendingCapacity,
}

/// The single-owner slot table for the fixed tunnel budget: at most
/// [`MAX_TUNNELS`] occupied slots including at most [`MAX_PENDING_SETUPS`]
/// pending setups; established work is never evicted (docs/alumina-proxy.md:160,193).
/// The worker owns the table (not a detachable counter object) and the single
/// clock authority; busy/pending are derived from the slot states, so the
/// accounting can never be copied out or underflow. It owns no sockets and no
/// I/O; the actual accept/connect/close event processing holds its granted
/// handles and drives the transitions.
pub struct Worker {
    slots: [SlotState; MAX_TUNNELS],
    clock: WorkerClock,
    occupied_count: usize,
    pending_count: usize,
    free_heap: [u16; MAX_TUNNELS],
    free_count: usize,
}

impl Worker {
    /// Constructs the empty slot table with the owning storage's clock
    /// authority. All state is preallocated (fixed arrays and counters); the
    /// free-index min-heap is initialised with every slot index exactly once,
    /// so admit never needs a slot scan. An ascending array is a valid binary
    /// min-heap, so no heapify pass is required. Crate-internal: the single
    /// constructor site is the storage that owns cache, schedules, and this
    /// worker.
    pub(crate) const fn boot(clock: WorkerClock) -> Worker {
        let mut free_heap = [0; MAX_TUNNELS];
        let mut index = 0;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the fixed 512-slot budget fits a u16 slot index, so the cast never truncates"
        )]
        while index < MAX_TUNNELS {
            free_heap[index] = index as u16;
            index += 1;
        }
        Worker {
            slots: [SlotState::Free; MAX_TUNNELS],
            clock,
            occupied_count: 0,
            pending_count: 0,
            free_heap,
            free_count: MAX_TUNNELS,
        }
    }

    /// Re-anchors this worker's clock to the one authority after the startup
    /// DNS window mounts `now0` and its exact elapsed origin. Crate-internal:
    /// called once by the owning storage after `resolve_window`.
    pub(crate) const fn set_clock(&mut self, clock: WorkerClock) {
        self.clock = clock;
    }

    /// The single clock authority for this worker's decisions.
    pub(crate) const fn clock(&self) -> WorkerClock {
        self.clock
    }

    /// The number of slots currently in setup (pending), read O(1) from the
    /// cached counter kept in lockstep with every slot transition.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.pending_count
    }

    /// The number of occupied slots (in setup or established), read O(1) from
    /// the cached counter kept in lockstep with every slot transition.
    #[must_use]
    pub const fn occupied(&self) -> usize {
        self.occupied_count
    }

    /// Admits a new setup into a free slot, capturing the absolute setup
    /// deadline at the accept instant, and returns the granted in-setup
    /// handle [`SlotIndex`]. The handle is moved through the lifecycle and
    /// consumed by [`Worker::release`] or [`Worker::finish_setup`], so a stale
    /// handle can never free a slot reused for another owner (9mq9 H1r).
    ///
    /// # Errors
    ///
    /// Returns `SlotCapacity` at [`MAX_TUNNELS`] occupied slots and
    /// `PendingCapacity` at [`MAX_PENDING_SETUPS`] pending setups; both are
    /// HTTP 503 + close (docs/alumina-proxy.md:193).
    pub(crate) fn admit(&mut self, now: Instant) -> Result<SlotIndex, AdmissionError> {
        if self.occupied_count >= MAX_TUNNELS {
            return Err(AdmissionError::SlotCapacity);
        }
        if self.pending_count >= MAX_PENDING_SETUPS {
            return Err(AdmissionError::PendingCapacity);
        }
        let index = self.take_min_free();
        self.slots[index as usize] = SlotState::InSetup {
            setup_deadline: Deadline::setup(now),
            attempts: AttemptLedger::new(),
        };
        self.occupied_count += 1;
        self.pending_count += 1;
        #[cfg(debug_assertions)]
        self.check_counter_lockstep();
        Ok(SlotIndex(index))
    }

    fn take_min_free(&mut self) -> u16 {
        let min = self.free_heap[0];
        self.free_count -= 1;
        self.free_heap[0] = self.free_heap[self.free_count];
        self.sift_down(0);
        min
    }

    #[expect(
        clippy::missing_const_for_fn,
        reason = "retained mutable free-slot min-heap; constness is not load-bearing on the runtime serving path"
    )]
    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = position * 2 + 1;
            if left >= self.free_count {
                break;
            }
            let right = left + 1;
            let mut smallest = left;
            if right < self.free_count && self.free_heap[right] < self.free_heap[left] {
                smallest = right;
            }
            if self.free_heap[smallest] >= self.free_heap[position] {
                break;
            }
            self.free_heap.swap(position, smallest);
            position = smallest;
        }
    }

    /// The one owned decision for an in-setup tunnel: authorization and peer
    /// selection against the current cache, with the setup deadline and the
    /// attempt budget both read from the granted slot (never supplied by a
    /// caller) and cache seconds from this worker's clock authority (never a
    /// free clock) (9mq9 M2r/M3). Consumes the caller-minted `resolved` context
    /// so authorization never re-resolves identity.
    ///
    /// # Errors
    ///
    /// Returns `NotInSetup` when the handle no longer names a live setup (a
    /// caller-level misuse the handle discipline prevents) and propagates the
    /// underlying current-cache lookup error.
    pub(crate) fn decide(
        &self,
        slot: &SlotIndex,
        resolved: &ResolvedRequest<'_>,
        now: Instant,
    ) -> Result<ConnectPhase, DecideError> {
        let setup = self.setup_deadline(slot).ok_or(DecideError::NotInSetup)?;
        let attempts = self.attempt_ledger(slot).ok_or(DecideError::NotInSetup)?;
        next_phase(resolved, now, attempts.counts(), attempts.previous(), setup)
            .map_err(DecideError::Cache)
    }

    /// Records one failed attempt in `family` on the granted in-setup slot,
    /// advancing its ledger toward the fixed attempt budget. The budget is
    /// self-enforcing: once [`MAX_UPSTREAM_ATTEMPTS`] attempts are recorded,
    /// any later [`Worker::decide`] for the slot resolves
    /// [`ConnectPhase::CandidatesExhausted`].
    ///
    /// # Errors
    ///
    /// Returns `NotInSetup` when the handle no longer names a live setup, so
    /// an established or released tunnel can never grow its counters.
    pub(crate) const fn record_attempt(
        &mut self,
        slot: &SlotIndex,
        family: Family,
    ) -> Result<AttemptLedger, DecideError> {
        match &mut self.slots[slot.index()] {
            SlotState::InSetup { attempts, .. } => {
                *attempts = attempts.record(family);
                Ok(*attempts)
            }
            _ => Err(DecideError::NotInSetup),
        }
    }

    /// The attempt ledger of the granted in-setup slot, or `None` when the
    /// slot is not in setup.
    pub(crate) const fn attempt_ledger(&self, slot: &SlotIndex) -> Option<AttemptLedger> {
        match self.slots[slot.index()] {
            SlotState::InSetup { attempts, .. } => Some(attempts),
            _ => None,
        }
    }

    /// Graduates the setup named by `slot` to established work, returning the
    /// established-phase handle: it stays occupied but no longer counts
    /// pending, and the setup handle is consumed so it cannot later free or
    /// re-graduate this tunnel. A no-op when the slot is not in setup (the
    /// grant flow guarantees that), so a misplaced call can never corrupt a
    /// different slot.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by value encodes the consume-once linear-handle discipline (the setup handle is consumed, converting it into exactly one established handle)"
    )]
    pub(crate) fn finish_setup(&mut self, slot: SlotIndex) -> TunnelIndex {
        if let SlotState::InSetup { setup_deadline, .. } = self.slots[slot.index()] {
            self.slots[slot.index()] = SlotState::Established { setup_deadline };
            self.pending_count -= 1;
            #[cfg(debug_assertions)]
            self.check_counter_lockstep();
        }
        TunnelIndex(slot.0)
    }
    /// Frees the granted in-setup slot for reuse, consuming the handle.
    /// Operates on the granted slot only, so closing a setup can never release
    /// another tunnel's pending or established seat (9mq9 H1r).
    /// Consumes the setup handle so the established tunnel's handle cannot be
    /// reused to double-free the slot. Callers re-establish via a fresh handle.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by value encodes the consume-once linear-handle discipline (preventing double release)"
    )]
    pub(crate) fn release(&mut self, slot: SlotIndex) {
        debug_assert!(
            matches!(self.slots[slot.index()], SlotState::InSetup { .. }),
            "release requires an in-setup slot"
        );
        self.slots[slot.index()] = SlotState::Free;
        self.push_free(slot.0);
        self.pending_count -= 1;
        self.occupied_count -= 1;
        #[cfg(debug_assertions)]
        self.check_counter_lockstep();
    }

    /// Frees an established tunnel for reuse, consuming the established handle.
    /// Consumes the established handle, which must not be re-graduated or
    /// double-released after a tunnel reset. Callers reap via a fresh handle.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by value encodes the consume-once linear-handle discipline (preventing reuse after reset)"
    )]
    pub(crate) fn release_tunnel(&mut self, tunnel: TunnelIndex) {
        self.slots[tunnel.index()] = SlotState::Free;
        self.push_free(tunnel.0);
        self.occupied_count -= 1;
        #[cfg(debug_assertions)]
        self.check_counter_lockstep();
    }

    #[expect(
        clippy::missing_const_for_fn,
        reason = "retained mutable free-slot min-heap; constness is not load-bearing on the runtime serving path"
    )]
    fn push_free(&mut self, index: u16) {
        let mut position = self.free_count;
        self.free_heap[position] = index;
        self.free_count += 1;
        while position > 0 {
            let parent = (position - 1) / 2;
            if self.free_heap[parent] <= self.free_heap[position] {
                break;
            }
            self.free_heap.swap(parent, position);
            position = parent;
        }
    }

    #[cfg(debug_assertions)]
    fn check_counter_lockstep(&self) {
        let occupied = self
            .slots
            .iter()
            .filter(|s| !matches!(s, SlotState::Free))
            .count();
        let pending = self
            .slots
            .iter()
            .filter(|s| matches!(s, SlotState::InSetup { .. }))
            .count();
        debug_assert_eq!(
            self.occupied_count, occupied,
            "occupied counter drifted from the slot table"
        );
        debug_assert_eq!(
            self.pending_count, pending,
            "pending counter drifted from the slot table"
        );
        debug_assert_eq!(
            self.free_count,
            MAX_TUNNELS - occupied,
            "free count drifted from the occupied seats in the slot table"
        );
        self.check_free_heap_valid();
    }

    #[cfg(debug_assertions)]
    fn check_free_heap_valid(&self) {
        let mut seen = [false; MAX_TUNNELS];
        for &entry in &self.free_heap[..self.free_count] {
            debug_assert!(
                matches!(self.slots[entry as usize], SlotState::Free),
                "free heap names a non-free slot {entry}"
            );
            debug_assert!(
                !seen[entry as usize],
                "free heap lists slot {entry} more than once"
            );
            seen[entry as usize] = true;
        }
        let mut position = 0;
        while position * 2 + 1 < self.free_count {
            let left = position * 2 + 1;
            debug_assert!(
                self.free_heap[position] <= self.free_heap[left],
                "min-heap disorder at parent {position} vs left {left}"
            );
            let right = left + 1;
            if right < self.free_count {
                debug_assert!(
                    self.free_heap[position] <= self.free_heap[right],
                    "min-heap disorder at parent {position} vs right {right}"
                );
            }
            position += 1;
        }
    }

    /// The absolute setup deadline of the granted in-setup slot, or `None`
    /// when the slot is free.
    pub(crate) const fn setup_deadline(&self, slot: &SlotIndex) -> Option<Deadline> {
        match self.slots[slot.index()] {
            SlotState::InSetup { setup_deadline, .. }
            | SlotState::Established { setup_deadline } => Some(setup_deadline),
            SlotState::Free => None,
        }
    }

    /// The absolute setup deadline of an established tunnel's slot, or `None`
    /// when the slot is free.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "designed established-tunnel deadline accessor; exercised in worker tests (worker.rs:1206), no production consumer yet"
        )
    )]
    pub(crate) const fn tunnel_setup_deadline(&self, tunnel: &TunnelIndex) -> Option<Deadline> {
        match self.slots[tunnel.index()] {
            SlotState::InSetup { setup_deadline, .. }
            | SlotState::Established { setup_deadline } => Some(setup_deadline),
            SlotState::Free => None,
        }
    }

    /// The occupied slot index for the granted in-setup handle, for the actual
    /// event processor to key its per-slot socket/parser/buffer state.
    pub(crate) const fn slot_index(slot: &SlotIndex) -> usize {
        slot.index()
    }
}

/// A setup-phase decision failure: either the granted handle no longer names a
/// live setup (a caller misuse the handle discipline prevents) or an
/// underlying current-cache lookup error.
#[derive(Debug, PartialEq, Eq)]
pub enum DecideError {
    /// The granted slot handle does not currently name an in-setup slot; the
    /// handle was released or already graduated. Unreachable in the serving
    /// path by construction (handles are consumed by the transitions).
    NotInSetup,
    /// The current-cache lookup failed for an allowlisted ordinal.
    Cache(CacheError),
}

/// The single-owner worker's boot-paired inputs to one CONNECT decision: the
/// validated allowlist config, the current cache derived from that same
/// allowlist, and the single clock authority that owns both the precise
/// deadlines and the DNS-scale cache seconds. The decision core accepts this
/// view, never a free (config, cache, clock) triple, so an allowlist ordinal
/// can never index a different name in a mismatched cache and a decision can
/// never evaluate the cache on a foreign clock (1cws M4r + M2r;
/// destination-binding, docs/alumina-proxy.md:145). The only construction seam is
/// crate-internal, so no public route can pair unrelated fields.
#[derive(Clone, Copy)]
pub struct WorkerView<'a> {
    config: &'a Config,
    cache: &'a Cache,
    clock: WorkerClock,
}

impl<'a> WorkerView<'a> {
    /// Binds a config, the cache derived from that same config, and the clock
    /// authority owned by the storage that built both. Crate-internal: the
    /// production caller is the owning storage, which passes its own aligned
    /// fields ([`crate::runtime::storage::ServeStorage::work_view`]); the worker's unit
    /// tests use it to pin decision behaviour over known in-cache state.
    pub(crate) const fn new(
        config: &'a Config,
        cache: &'a Cache,
        clock: WorkerClock,
    ) -> WorkerView<'a> {
        WorkerView {
            config,
            cache,
            clock,
        }
    }

    /// The single exact-pair resolution of an already-validated CONNECT bound
    /// to this view: resolves `request` against this view's config and carries
    /// the view itself, so the returned context can only ever be decided
    /// against the config/cache/clock it was resolved against
    /// (destination-binding, docs/alumina-proxy.md:145).
    pub(crate) fn resolve(self, request: &'a ConnectRequest) -> ResolvedRequest<'a> {
        let ordinal = self
            .config
            .allowlist_position(request.hostname(), request.port());
        ResolvedRequest {
            request,
            view: self,
            ordinal,
        }
    }

    /// The single clock authority bound to this config/cache pair.
    #[expect(
        dead_code,
        reason = "designed WorkerView clock accessor; referenced by rustdoc worker.rs:666, no consumer yet"
    )]
    pub(crate) const fn clock(&self) -> WorkerClock {
        self.clock
    }
}

/// The single exact-pair resolution of an already-validated CONNECT carried
/// through one decision: the original request bound to its raw allowlist
/// position and the [`WorkerView`] it was resolved against, minted only by
/// [`WorkerView::resolve`]. The serving block precheck, the current-cache
/// decision, peer freshness and report attribution all share this one
/// resolution; none re-resolves identity (alumina-sechd L14).
///
/// The mint binds the request to the view's config, so no caller can pair the
/// ordinal with a foreign cache or clock: `ordinal()` is always the allowlist
/// position of `request()` in the carried view's config, and every consumer
/// decides against that carried view. The raw index is distinct from the
/// enforcement `DomainOrdinal` and the cache `NameIndex` and is not
/// interchangeable with either; sites that need one convert from this value
/// themselves. All fields are private; the only read surface is the getters.
pub(crate) struct ResolvedRequest<'a> {
    request: &'a ConnectRequest,
    view: WorkerView<'a>,
    ordinal: Option<usize>,
}

impl<'a> ResolvedRequest<'a> {
    /// The bound original request with unchanged bytes.
    pub(crate) const fn request(&self) -> &'a ConnectRequest {
        self.request
    }

    /// The raw allowlist position of the bound request, or `None` when its
    /// exact `<fqdn>:<port>` pair is not allowlisted.
    pub(crate) const fn ordinal(&self) -> Option<usize> {
        self.ordinal
    }

    /// The bound request's selected-family entry state at `now` on this view's
    /// clock authority: `None` when the request is not allowlisted or its
    /// current-cache entry cannot be read, which callers treat as an
    /// observation with no effect, matching the serving freshness fold's
    /// pre-existing fallibility. The family is the just-selected peer's
    /// family, so the observation is bound to this resolution and never takes
    /// a caller-supplied view, raw index, or clock.
    pub(crate) fn peer_state(&self, family: Family, now: Instant) -> Option<EntryState> {
        let view = &self.view;
        let ordinal = self.ordinal()?;
        let name = view.cache.name_index(ordinal)?;
        let entry = view.cache.entry(name, family).ok()?;
        Some(entry.state(view.clock.cache_secs(now)))
    }
}

/// Decides the next CONNECT-phase action for a tunnel from the current cache.
///
/// Authorization is allowlist membership of the already-validated CONNECT
/// (hostname, port) pair, requiring the exact configured `<fqdn>:<port>`; the
/// 1..=65535 port range and non-literal hostname forms are enforced upstream
/// in the parser. The caller mints the single exact-pair resolution once
/// ([`ResolvedRequest`]); this core consumes that context and never re-resolves
/// identity. After authorization, the fixed setup deadline and the attempt
/// budget are checked before any address is selected, so a refusal never
/// reaches the peer-selection step and no upstream socket is opened. The
/// per-attempt connect deadline is freshly clipped inside the returned
/// `Peer`, never passed in (9pac M1); deadlines use the precise `now` instant
/// while cache freshness uses the view's own clock authority
/// ([`WorkerView::clock`] → [`WorkerClock::cache_secs`], 1cws M2r).
///
/// Crate-internal: the owning storage supplies `setup_deadline` from the
/// granted slot via [`Worker::decide`], never from a caller (9mq9 M3).
///
/// # Errors
///
/// Propagates `NameOutOfRange` from the current-cache lookup; because the
/// cache is owned and sized by the same validated allowlist, an allowlisted
/// ordinal is always admitted.
pub(crate) fn next_phase(
    resolved: &ResolvedRequest<'_>,
    now: Instant,
    counts: AttemptCounts,
    previous: Option<Family>,
    setup_deadline: Deadline,
) -> Result<ConnectPhase, CacheError> {
    let view = &resolved.view;
    let Some(ordinal) = resolved.ordinal() else {
        return Ok(ConnectPhase::Forbidden);
    };
    let name = view
        .cache
        .name_index(ordinal)
        .ok_or(CacheError::NameOutOfRange)?;
    if setup_deadline.is_expired(now) {
        return Ok(ConnectPhase::DeadlineExhausted);
    }
    if usize::from(counts.total()) >= MAX_UPSTREAM_ATTEMPTS {
        return Ok(ConnectPhase::CandidatesExhausted);
    }
    let cache_now = view.clock.cache_secs(now);
    match select_peer(view.cache, name, cache_now, counts, previous)? {
        PeerDecision::Peer { addr, family } => Ok(ConnectPhase::Peer {
            addr,
            family,
            connect_deadline: Deadline::connect_attempt(now, setup_deadline),
        }),
        PeerDecision::NoFamily => Ok(ConnectPhase::NoBinding),
    }
}

/// Selects the next upstream peer from the current cache (docs/alumina-proxy.md:82).
///
/// Reads the current A and AAAA entries afresh and ignores any that are empty,
/// retired, exhausted at their current per-family attempt count, or whose
/// candidate at the attempt cursor is ineligible. When only one family
/// remains it is used; when both remain, the first attempt uses IPv4 and each
/// later attempt uses the family NOT used by the previous attempt (the
/// `previous` Connecting-lifecycle transition input, oracle alumina-ufrw).
/// Within a family the address at index `n` is used, where `n` is the number
/// of earlier attempts in that family; the family is exhausted when `n`
/// reaches the entry's current address count. `now` is the whole-second
/// DNS/cache clock ([`WorkerClock::cache_secs`]), never a precise deadline.
///
/// # Errors
///
/// Propagates `NameOutOfRange` from the current-cache lookup.
pub(crate) fn select_peer(
    cache: &Cache,
    name: NameIndex,
    now: u64,
    counts: AttemptCounts,
    previous: Option<Family>,
) -> Result<PeerDecision, CacheError> {
    let a = cache.entry(name, Family::A)?;
    let aaaa = cache.entry(name, Family::Aaaa)?;
    match (
        usable_peer(&a, Family::A, counts.a(), now),
        usable_peer(&aaaa, Family::Aaaa, counts.aaaa(), now),
    ) {
        (None, None) => Ok(PeerDecision::NoFamily),
        (Some((addr, family)), None) | (None, Some((addr, family))) => {
            Ok(PeerDecision::Peer { addr, family })
        }
        (Some(a_peer), Some(aaaa_peer)) => {
            let (addr, family) = match previous {
                None | Some(Family::Aaaa) => a_peer,
                Some(Family::A) => aaaa_peer,
            };
            Ok(PeerDecision::Peer { addr, family })
        }
    }
}

/// The usable candidate for `family` at its current attempt cursor: `Some`
/// only when the family still holds a binding at index `attempted`, that entry
/// is not empty or retired, and the specific candidate passes destination
/// eligibility. An ineligible candidate makes THIS family unavailable at the
/// cursor — it never erases a usable other family (9pac M3). In the running
/// path bindings are already eligible because publishing filters them
/// (cache.rs `publish_positive`), so this eligibility check is defense.
fn usable_peer(
    entry: &Entry,
    family: Family,
    attempted: u8,
    now: u64,
) -> Option<(NumericAddr, Family)> {
    if usize::from(attempted) >= entry.bindings().len() {
        return None;
    }
    if !entry.servable(now) {
        return None;
    }
    let addr = entry.bindings()[usize::from(attempted)];
    if !addr.is_eligible() {
        return None;
    }
    Some((addr, family))
}

#[cfg(test)]
mod tests;
