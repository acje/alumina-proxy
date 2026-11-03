use std::io;
use std::io::IoSlice;
use std::time::Instant;

use super::{
    Cursor, LOG_RETRY, LogStore, LogStoreError, QUEUE_MASK, SINK_MAX_BYTES, SINK_MAX_OPS, SinkIo,
};

impl LogStore {
    /// Arms the production stdout sink: makes the owned stdout clone
    /// nonblocking so a full or absent stdout pipe can never stall serving.
    /// Because the clone shares the file description with fd 1, this also
    /// flips the process's real stdout. Only the process that owns stdout (the
    /// binary) calls this once after boot, so tests and the library never flip
    /// the descriptor.
    pub(crate) fn prepare_stdout(&mut self) -> Result<(), LogStoreError> {
        match &self.sink.io {
            SinkIo::Stdout(stream) => stream
                .set_nonblocking(true)
                .map_err(|_| LogStoreError::StdoutNonblocking)?,
            #[cfg(test)]
            SinkIo::Fd(_) => {}
            #[cfg(test)]
            SinkIo::Scripted(_) => {}
        }
        Ok(())
    }
    /// The next Instant at which draining the queued logs is useful (N4/T3):
    /// queued non-WouldBlock logs are immediately runnable, WouldBlock-blocked
    /// logs retry on the bounded [`LOG_RETRY`] cadence, and an empty or failed
    /// sink is quiescent (it never wakes a poll).
    pub(crate) fn next_drain(&self, now: Instant) -> Option<Instant> {
        if self.count == 0 || self.sink.failed {
            return None;
        }
        if self.sink.blocked {
            Some(now + LOG_RETRY)
        } else {
            Some(now)
        }
    }
    /// Whether a further drain turn can still deliver queued records: records
    /// remain and the sink is neither stalled mid-write (a retained cursor
    /// awaiting the bounded [`LOG_RETRY`] cadence) nor latched failed. A boot
    /// seam that must deliver more than one [`SINK_MAX_OPS`] budget repeats
    /// [`Self::drain_sink`] only while this holds, so a stalled sink costs one
    /// turn instead of spinning.
    pub(crate) const fn sink_ready(&self) -> bool {
        self.count > 0 && !self.sink.blocked && !self.sink.failed
    }
    /// Accounts for every queued record that no later drain turn can deliver
    /// because the owner is about to exit: each is dropped whole and counted
    /// exactly once in the shared drop tally, and any retained partial cursor
    /// is cleared. Returns how many records were stranded. Used only on the
    /// exit paths, where the queue would otherwise be destroyed uncounted:
    /// queue-accepted records that cannot be drained before the process ends
    /// are counted under the existing whole-record drop accounting, never
    /// silently lost (docs/alumina-proxy.md:197, L18). A path that keeps
    /// running never calls this — it leaves the records queued and retries on
    /// the bounded [`LOG_RETRY`] cadence (`next_drain`).
    pub(crate) const fn strand_queued(&mut self) -> u64 {
        let mut stranded = 0u64;
        while self.count > 0 {
            self.drop_one();
            self.count -= 1;
            stranded += 1;
        }
        self.cursor = None;
        stranded
    }
    /// Total write calls made by the sink (test observation of the per-turn
    /// op budget).
    #[cfg(test)]
    pub(crate) const fn sink_ops(&self) -> usize {
        self.sink.ops
    }
    /// Total write-vector syscalls issued by the sink (test observation of
    /// the gather: fewer syscalls than fragments when fragments coalesce).
    #[cfg(test)]
    pub(crate) const fn sink_syscalls(&self) -> usize {
        self.sink.syscalls
    }
    /// Whether the sink latched failed after a non-WouldBlock write error
    /// (e.g. the stdout pipe closed). The latch is persistent state: no later
    /// drain consumes or clears it, so the serving owner reads it after each
    /// per-turn drain and exits `EX_IOERR` when it is set (F-09).
    pub(crate) const fn sink_has_failed(&self) -> bool {
        self.sink.failed
    }
    /// Drains the queue through the nonblocking stdout sink under the
    /// per-turn work budget: at most [`SINK_MAX_OPS`] gathered fragments or
    /// [`SINK_MAX_BYTES`] bytes, emitted in a single `write_vectored` call per
    /// turn. A `WouldBlock` retains the partial cursor and yields
    /// immediately; a write/close failure latches the sink failed so no later
    /// drain spins or blocks. The latch is the owner's signal: the serving
    /// owner observes it through [`Self::sink_has_failed`] after each drain
    /// (F-09), and it is persistent state — never consumed or cleared by a
    /// later drain — so a startup-window or probe drain that latches it is
    /// still seen by the first serving owner turn.
    pub(crate) fn drain_sink(&mut self) {
        if self.sink.failed {
            return;
        }
        let mut ops = 0usize;
        let mut bytes_out = 0usize;
        loop {
            if ops >= SINK_MAX_OPS || bytes_out >= SINK_MAX_BYTES {
                return;
            }
            let (index, off) = if let Some(cursor) = self.cursor {
                (self.front, cursor.off)
            } else {
                if self.count == 0 {
                    return;
                }
                (self.front, 0)
            };
            let rec_len = self.slots[index].bytes;
            if off >= rec_len {
                self.advance_front();
                continue;
            }
            let mut iovs: [IoSlice<'_>; SINK_MAX_OPS] = [IoSlice::new(&[]); SINK_MAX_OPS];
            let mut remain = SINK_MAX_BYTES - bytes_out;
            let mut gathered = 0usize;
            while gathered < self.count && gathered < SINK_MAX_OPS && remain > 0 {
                let fi = (index + gathered) & QUEUE_MASK;
                let start = if gathered == 0 { off } else { 0 };
                let end = self.slots[fi].bytes;
                let part = (end - start).min(remain);
                iovs[gathered] = IoSlice::new(&self.slots[fi].buf[start..start + part]);
                gathered += 1;
                remain -= part;
            }
            let written = self.sink.io.write_vectored(&iovs[..gathered]);
            match written {
                Err(ref err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::Interrupted =>
                {
                    self.sink.blocked = true;
                    self.cursor = Some(Cursor { off });
                    return;
                }
                Err(_) => {
                    self.sink.failed = true;
                    while self.count > 0 {
                        self.drop_one();
                        self.count -= 1;
                    }
                    self.cursor = None;
                    return;
                }
                Ok(0) => {
                    self.sink.blocked = true;
                    self.cursor = Some(Cursor { off });
                    return;
                }
                Ok(n) => {
                    ops += gathered;
                    #[cfg(test)]
                    {
                        self.sink.ops += gathered;
                        self.sink.syscalls += 1;
                    }
                    bytes_out += n;
                    self.sink.blocked = false;
                    if self.consume_gathered(gathered, n) {
                        return;
                    }
                }
            }
        }
    }
    /// Accounts `n` written bytes over the `gathered` fragments of a single
    /// `writev`, advancing the queue front once per fully-emitted record so
    /// watermark edges observe true per-record occupancy. Returns `true` when
    /// the write stopped mid-record (a partial write): the turn must end with
    /// the cursor retained for the drain to resume at the exact residue.
    fn consume_gathered(&mut self, gathered: usize, mut n: usize) -> bool {
        let index = self.front;
        let off = self.cursor.map_or(0, |c| c.off);
        for k in 0..gathered {
            let start = if k == 0 { off } else { 0 };
            let remain = self.slots[(index + k) & QUEUE_MASK].bytes - start;
            if n < remain {
                self.cursor = Some(Cursor { off: start + n });
                return true;
            }
            n -= remain;
            self.advance_front();
        }
        false
    }
    fn advance_front(&mut self) {
        self.cursor = None;
        if self.count > 0 {
            self.count -= 1;
            self.front = (self.front + 1) & QUEUE_MASK;
            self.note_queue_usage();
        }
    }
}
