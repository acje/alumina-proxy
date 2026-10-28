use std::fmt;
use std::mem::size_of;

use crate::client_hello::ChInspector;
use crate::config::CONFIG_DOC_LIMIT;
use crate::connect::ConnectParser;
use crate::dns::ResponseWorkspace;
use crate::startup_dns::{QUERY_BUF_LEN, RECV_BUF_LEN};

pub const TUNNEL_SLOTS: usize = 512;
pub const BUFFERS_PER_SLOT: usize = 2;
pub const BUFFER_BYTES: usize = 128 * 1024;
pub const TRAFFIC_STORAGE_BYTES: usize = TUNNEL_SLOTS * BUFFERS_PER_SLOT * BUFFER_BYTES;
/// The transient configuration-document read buffer: one byte past the
/// `CONFIG_DOC_LIMIT` bound so the oversize probe can observe an over-limit
/// document (`config::load_config_document`'s `take` limit).
pub const CONFIG_DOC_BUFFER_BYTES: usize = CONFIG_DOC_LIMIT + 1;

/// The retained per-slot serving workspace: the fixed [`ConnectParser`] head
/// and the [`ChInspector`] retained once per tunnel slot for the process
/// lifetime and reused across connections. The inspector stores its parsed
/// [`crate::client_hello::ClientHello`] by value — including the fixed
/// cipher-suite, extension, ALPN, and signature-algorithm arrays that back the
/// JA4 fingerprint — so `size_of` over the two retained types accounts for
/// every retained parsing/inspection byte with no second hand-maintained
/// factor. This is a lower
/// bound on the slot's retained bytes: the per-slot serving workspace also
/// carries gate, capture, cursors, and the approved hostname, which are
/// deliberately not folded in here.
pub const SLOT_WORKSPACE_BYTES: usize = size_of::<ConnectParser>() + size_of::<ChInspector>();

/// The total retained serving-workspace bytes across all 512 tunnel slots:
/// every slot carries its own parser + inspector (incl. the retained JA4
/// arrays), so the total is the per-slot type-derived figure times the fixed
/// slot count.
pub const SERVING_WORKSPACE_BYTES: usize = TUNNEL_SLOTS * SLOT_WORKSPACE_BYTES;

/// The retained DNS transport named buffers (lower bound): the fixed 512-byte
/// query buffer plus the fixed `DNS_MSG_LIMIT + 2` response buffer that the
/// startup DNS transport pre-allocates, and the reusable response parse
/// workspace (fixed owners table). These are the named buffers retained for
/// the process lifetime; the DNS response message bound is their constituent.
pub const DNS_NAMED_BUFFER_BYTES: usize =
    QUERY_BUF_LEN + RECV_BUF_LEN + size_of::<ResponseWorkspace>();

/// The boot-owned best-effort log queue (256 records x 2 KiB), reserved and
/// initialized once by the log store at boot and retained for the process
/// lifetime.
pub const LOG_QUEUE_BYTES: usize = 256 * (2 * 1024);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageUnavailable;

impl fmt::Display for StorageUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boot traffic storage unavailable: failed to allocate {TRAFFIC_STORAGE_BYTES} bytes"
        )
    }
}

/// The two retained directional buffers for one tunnel slot, allocated once at
/// boot and transferred by value into the serving slot they back.
#[derive(Debug)]
pub struct SlotTraffic {
    pub up: Box<[u8]>,
    pub down: Box<[u8]>,
}

impl SlotTraffic {
    /// Splits the retained pair into its two buffer halves for transfer.
    #[must_use]
    pub fn into_parts(self) -> (Box<[u8]>, Box<[u8]>) {
        (self.up, self.down)
    }
}

/// The boot-owned traffic store: one retained directional-buffer pair per
/// tunnel slot, fully initialized before the first DNS exchange. Allocation is
/// fallible and any failure surfaces as the typed OOM [`StorageUnavailable`];
/// the store is transferred in whole to the serving owner, so no duplicate
/// traffic blob exists and serving performs no buffer allocation.
#[derive(Debug)]
pub struct TrafficStorage {
    slots: Box<[SlotTraffic]>,
}

impl TrafficStorage {
    /// Allocates and zero-initializes the full 128 MiB traffic store.
    ///
    /// # Errors
    ///
    /// Returns [`StorageUnavailable`] when any retained buffer cannot be
    /// reserved; the partial store is dropped and boot fails with the typed
    /// OOM variant.
    pub fn allocate() -> Result<TrafficStorage, StorageUnavailable> {
        #[cfg(test)]
        if alloc_fault::armed() {
            return Err(StorageUnavailable);
        }
        let mut slots: Vec<SlotTraffic> = Vec::new();
        slots
            .try_reserve_exact(TUNNEL_SLOTS)
            .map_err(|_| StorageUnavailable)?;
        for _ in 0..TUNNEL_SLOTS {
            slots.push(SlotTraffic {
                up: buffer_bytes()?,
                down: buffer_bytes()?,
            });
        }
        Ok(TrafficStorage {
            slots: slots.into_boxed_slice(),
        })
    }

    /// The exact initialized traffic bytes: 512 slots x 2 directions x 128 KiB.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len() * BUFFERS_PER_SLOT * BUFFER_BYTES
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Read view of the retained per-slot pairs, for accounting and tests.
    #[must_use]
    pub fn slots(&self) -> &[SlotTraffic] {
        &self.slots
    }

    /// Consumes the store, yielding the per-slot pairs for transfer into the
    /// serving owner without a second allocation.
    #[must_use]
    pub fn into_slots(self) -> Box<[SlotTraffic]> {
        self.slots
    }
}

fn buffer_bytes() -> Result<Box<[u8]>, StorageUnavailable> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes
        .try_reserve_exact(BUFFER_BYTES)
        .map_err(|_| StorageUnavailable)?;
    bytes.resize(BUFFER_BYTES, 0);
    Ok(bytes.into_boxed_slice())
}

#[expect(
    clippy::struct_field_names,
    reason = "the shared `_bytes` postfix documents that every field is a byte-quantity and backs the public `*_bytes()` accessors used in the boot inventory report (tests/boot.rs, main.rs); dropping it would diverge field/accessor naming and the byte-unit signal in the fixed-profile sizing identifiers"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInventory {
    traffic_storage_bytes: usize,
    serving_workspace_bytes: usize,
    dns_named_buffer_bytes: usize,
    transient_config_buffer_bytes: usize,
    reserved_log_queue_bytes: usize,
}

impl BootInventory {
    #[must_use]
    pub const fn phase1() -> BootInventory {
        BootInventory {
            traffic_storage_bytes: TRAFFIC_STORAGE_BYTES,
            serving_workspace_bytes: SERVING_WORKSPACE_BYTES,
            dns_named_buffer_bytes: DNS_NAMED_BUFFER_BYTES,
            transient_config_buffer_bytes: CONFIG_DOC_BUFFER_BYTES,
            reserved_log_queue_bytes: LOG_QUEUE_BYTES,
        }
    }

    /// The fixed named buffers the process is planned to retain for its
    /// lifetime (lower bound over named constants and `size_of` of the
    /// retained types). Constant-derived plan, not an observation and never a
    /// measured RSS / process or kernel memory figure: the traffic store
    /// initializes at boot, the serving workspaces at
    /// [`Preallocated::preallocate`](crate::runtime::Preallocated::preallocate),
    /// and the DNS buffers at the DNS transport's own construction.
    ///
    /// The bound sums three distinct categories — traffic storage, the
    /// retained serving workspaces (per-slot parser + inspector, including the
    /// retained JA4 arrays), and the DNS named buffers — and deliberately
    /// excludes the remaining per-slot serving metadata (gate, capture,
    /// cursors, approved hostname), transient scratch, the reserved log queue,
    /// and any measured process/kernel memory, so it is a lower bound over
    /// retained named buffers, never an RSS estimate.
    #[must_use]
    pub const fn named_fixed_buffer_bytes(&self) -> usize {
        self.traffic_storage_bytes
            .saturating_add(self.serving_workspace_bytes)
            .saturating_add(self.dns_named_buffer_bytes)
    }

    #[must_use]
    pub const fn traffic_storage_bytes(&self) -> usize {
        self.traffic_storage_bytes
    }

    #[must_use]
    pub const fn serving_workspace_bytes(&self) -> usize {
        self.serving_workspace_bytes
    }

    #[must_use]
    pub const fn dns_named_buffer_bytes(&self) -> usize {
        self.dns_named_buffer_bytes
    }

    #[must_use]
    pub const fn transient_scratch_bytes(&self) -> usize {
        self.transient_config_buffer_bytes
    }

    #[must_use]
    pub const fn reserved_future_bytes(&self) -> usize {
        self.reserved_log_queue_bytes
    }
}

#[cfg(test)]
pub(crate) fn arm_alloc_failure() {
    alloc_fault::set(true);
}

#[cfg(test)]
pub(crate) fn clear_alloc_failure() {
    alloc_fault::set(false);
}

#[cfg(test)]
mod alloc_fault {
    use std::cell::Cell;

    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn set(value: bool) {
        FAIL.with(|cell| cell.set(value));
    }

    pub(super) fn armed() -> bool {
        FAIL.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
mod workspace_byte_constants {
    use super::*;
    use crate::client_hello::{ChInspector, ClientHello};
    use crate::connect::ConnectParser;

    #[test]
    fn slot_workspace_derives_from_retained_parser_and_inspector() {
        let parser = size_of::<ConnectParser>();
        let inspector = size_of::<ChInspector>();
        let hello = size_of::<ClientHello>();
        assert_eq!(
            SLOT_WORKSPACE_BYTES,
            parser + inspector,
            "SLOT_WORKSPACE_BYTES must be the retained per-slot serving types verbatim: \
             size_of::<ConnectParser>()={parser}, size_of::<ChInspector>()={inspector} \
             (incl. size_of::<ClientHello>()={hello} retained inline); a change to the \
             retained ClientHello/JA4 arrays must change this derived sum"
        );
    }

    #[test]
    fn slot_workspace_pinned_as_documented_tripwire() {
        // [Tripwire] The derived per-slot serving workspace is pinned to the
        // measured type-derived figure. If a retained ClientHello array (JA4
        // ciphers/extensions/ALPN/sigalgs) or the parser/inspector layout ever
        // changes, this pin FAILS and the documented figure (the architecture
        // retained-storage table) must be reconciled and the pin rebased IN
        // THE SAME CHANGE — never by bumping this number alone.
        let per_slot = size_of::<ConnectParser>() + size_of::<ChInspector>();
        assert_eq!(
            SLOT_WORKSPACE_BYTES, 156_856,
            "measured type-derived figure is {per_slot} bytes; reconcile the documented figure in the same change as any retained-array/layout edit"
        );
    }

    #[test]
    fn serving_workspace_derives_from_slot_count() {
        assert_eq!(
            SERVING_WORKSPACE_BYTES,
            TUNNEL_SLOTS * SLOT_WORKSPACE_BYTES,
            "definition must stay in sync with slot count"
        );
    }
}
