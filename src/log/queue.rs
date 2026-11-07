use super::encoding::{AssurancePhase, encode_dns_assurance};
use super::{
    Dimension, Edge, Field, HIGH_PCT_NUMBER, Kind, LOW_PCT_NUMBER, Level, LogStore, QUEUE_MASK,
    QUEUE_SLOTS, SLOT_BYTES, Val, Watermark, encode_record,
};
use crate::runtime::storage::AssuranceSnapshot;

impl LogStore {
    /// Whole-record drops so far; saturates at `u64::MAX`.
    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }
    /// Whether the drop counter has been saturated (the overflow state).
    #[cfg(test)]
    pub(crate) const fn dropped_overflow(&self) -> bool {
        self.dropped_overflow
    }
    /// Queued (not yet flushed) record count.
    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.count
    }
    /// Whether the queue holds `QUEUE_SLOTS` records.
    #[cfg(test)]
    pub(crate) const fn is_full(&self) -> bool {
        self.count >= QUEUE_SLOTS
    }
    /// The bytes of the most recently committed queued record: test
    /// observation of the exact emitted record text without draining to a
    /// sink, so an integration test can assert the folded monitor fields.
    #[cfg(test)]
    pub(crate) fn last_record_bytes(&self) -> Option<&[u8]> {
        if self.count == 0 {
            return None;
        }
        let index = (self.write_index() + QUEUE_MASK) & QUEUE_MASK;
        Some(&self.slots[index].buf[..self.slots[index].bytes])
    }
    /// Marks the drop counter saturated as a test hook for the overflow flag.
    #[cfg(test)]
    pub(crate) const fn saturate_dropped_for_test(&mut self) {
        self.dropped = u64::MAX;
        self.dropped_overflow = true;
    }
    pub(super) fn capacity_edge(&mut self, dimension: Dimension, edge: Edge) {
        let (kind, level, used, cap) = match (dimension, edge) {
            (Dimension::Queue, Edge::High { used, cap }) => {
                (Kind::QueueHigh, Level::Error, used, cap)
            }
            (Dimension::Queue, Edge::Low { used, cap }) => (Kind::QueueLow, Level::Info, used, cap),
            (Dimension::Slots | Dimension::Setups, Edge::High { used, cap }) => {
                (Kind::CapacityHigh, Level::Error, used, cap)
            }
            (Dimension::Slots | Dimension::Setups, Edge::Low { used, cap }) => {
                (Kind::CapacityLow, Level::Info, used, cap)
            }
        };
        let secs = self.secs;
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("dimension", Val::Str(dimension.as_str())),
            Field::new("used", Val::U64(used)),
            Field::new("cap", Val::U64(cap)),
        ];
        self.enqueue(level, kind, &fields);
    }
    /// Evaluates the queue watermark on enqueue and again on each drain step
    /// (real-time threshold transitions per review M3).
    pub(super) fn note_queue_usage(&mut self) {
        if let Some(edge) = note_usage(&mut self.queue_wm, self.count, QUEUE_SLOTS) {
            self.capacity_edge(Dimension::Queue, edge);
        }
    }
    pub(super) const fn write_index(&self) -> usize {
        (self.front + self.count) & QUEUE_MASK
    }
    pub(super) fn enqueue(&mut self, level: Level, kind: Kind, fields: &[Field<'_>]) {
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
        } else {
            let index = self.write_index();
            match encode_record(&mut self.slots[index].buf, level, kind, fields) {
                Some(len) => self.commit_record(index, len),
                None => self.drop_one(),
            }
        }
        self.note_queue_usage();
    }
    pub(super) fn commit_record(&mut self, index: usize, len: usize) {
        self.slots[index].bytes = len;
        self.slots[index].reserved = false;
        self.count += 1;
    }
    /// Best-effort enqueue for a non-reserved record built by `encode` (the
    /// `monitor_domain` / `monitor_capture` detail batches). On a full ring the
    /// record is dropped whole without running `encode`; on encode failure it
    /// is dropped too. Returns whether the record was committed. Never calls
    /// `note_queue_usage` (the caller accounts queue pressure once per turn).
    pub(super) fn enqueue_normal(
        &mut self,
        encode: impl FnOnce(&mut [u8; SLOT_BYTES]) -> Option<usize>,
    ) -> bool {
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
            return false;
        }
        let index = self.write_index();
        if let Some(len) = encode(&mut self.slots[index].buf) {
            self.commit_record(index, len);
            true
        } else {
            self.drop_one();
            false
        }
    }
    /// Typed-enqueue sibling of `enqueue_normal` for owner telemetry: the
    /// caller's encoder surfaces a `CacheError` as `Err`, preserved distinctly
    /// rather than folded into a counted drop. On `Err` the slot is left
    /// uncommitted (its partial bytes remain garbage-on-failure) and neither
    /// the drop counter nor any queue-usage state moves; the caller accounts
    /// queue pressure once per turn. `Ok` values keep `enqueue_normal`'s
    /// semantics: `Some(len)` commits the record; `None` or a full ring drops
    /// a whole record and counts it.
    pub(super) fn enqueue_fallible<E>(
        &mut self,
        encode: impl FnOnce(&mut [u8; SLOT_BYTES]) -> Result<Option<usize>, E>,
    ) -> Result<bool, E> {
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
            return Ok(false);
        }
        let index = self.write_index();
        match encode(&mut self.slots[index].buf) {
            Ok(Some(len)) => {
                self.commit_record(index, len);
                Ok(true)
            }
            Ok(None) => {
                self.drop_one();
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    /// Enqueues one owner-captured snapshot; overflow counts one whole drop.
    pub(crate) fn enqueue_assurance(
        &mut self,
        snapshot: &AssuranceSnapshot,
        seq: u64,
        phase: AssurancePhase,
    ) -> bool {
        self.set_now(self.secs.max(snapshot.secs()));
        self.enqueue_normal(|slot| encode_dns_assurance(slot, snapshot, seq, phase))
    }
    /// Enqueues a reserved priority-class record (docs/alumina-proxy.md:1299-1301).
    /// On a full ring the record is encoded into a stack scratch slot first and
    /// only on encode success displaces the newest normal record, so a failed
    /// encode never evicts a held record. Returns whether the record was
    /// committed (admitted or displacing).
    pub(super) fn enqueue_reserved(
        &mut self,
        kind: Kind,
        encode: impl FnOnce(&mut [u8; SLOT_BYTES]) -> Option<usize>,
    ) -> bool {
        debug_assert!(
            kind.is_reserved(),
            "only reserved priority-class kinds reach enqueue_reserved"
        );
        if self.count >= QUEUE_SLOTS {
            let mut scratch = [0u8; SLOT_BYTES];
            if let Some(len) = encode(&mut scratch) {
                self.displace_reserved(&scratch[..len]);
                true
            } else {
                self.drop_one();
                false
            }
        } else {
            let index = self.write_index();
            if let Some(len) = encode(&mut self.slots[index].buf) {
                self.commit_reserved(index, len);
                true
            } else {
                self.drop_one();
                false
            }
        }
    }
    fn commit_reserved(&mut self, index: usize, len: usize) {
        self.slots[index].bytes = len;
        self.slots[index].reserved = true;
        self.count += 1;
    }
    /// Displaces the newest normal record to admit a reserved one on a full
    /// ring: the reserved block newer than the victim shifts one slot toward
    /// the front and the encoded record takes the newest slot, so only the
    /// newest-lowest-priority record is lost. When every held record is
    /// reserved the newest reserved record is the bounded-not-lossless victim
    /// (docs/alumina-proxy.md:290, :1303).
    fn displace_reserved(&mut self, scratch: &[u8]) {
        let front_started = self.cursor.is_some_and(|cursor| cursor.off > 0);
        let victim = (0..QUEUE_SLOTS)
            .rev()
            .filter(|&j| j != 0 || !front_started)
            .find(|&j| !self.slots[(self.front + j) & QUEUE_MASK].reserved)
            .unwrap_or(QUEUE_SLOTS - 1);
        for j in (victim + 1)..QUEUE_SLOTS {
            self.slots[(self.front + j - 1) & QUEUE_MASK] =
                self.slots[(self.front + j) & QUEUE_MASK];
        }
        self.drop_one();
        let index = (self.front + QUEUE_SLOTS - 1) & QUEUE_MASK;
        self.slots[index].buf[..scratch.len()].copy_from_slice(scratch);
        self.slots[index].bytes = scratch.len();
        self.slots[index].reserved = true;
    }
    pub(super) const fn drop_one(&mut self) {
        self.dropped = self.dropped.saturating_add(1);
        if self.dropped == u64::MAX {
            self.dropped_overflow = true;
        }
    }
}

/// Evaluates the 80%/70% threshold on a single watermark and latches the
/// transition. Returns the edge to emit, or `None` when no transition occurred.
pub(super) const fn note_usage(wm: &mut Watermark, used: usize, cap: usize) -> Option<Edge> {
    let used = used as u64;
    let cap = cap as u64;
    let exceeds_high = used.saturating_mul(100) > HIGH_PCT_NUMBER.saturating_mul(cap);
    let below_low = used.saturating_mul(100) < LOW_PCT_NUMBER.saturating_mul(cap);
    if exceeds_high && !wm.crossed_high {
        wm.crossed_high = true;
        Some(Edge::High { used, cap })
    } else if below_low && wm.crossed_high {
        wm.crossed_high = false;
        Some(Edge::Low { used, cap })
    } else {
        None
    }
}
