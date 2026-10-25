use std::fmt;
use std::mem::size_of;

use crate::client_hello::MAX_CLIENT_HELLO;
use crate::config::CONFIG_DOC_LIMIT;
use crate::connect::CONNECT_LIMIT;
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

/// The retained per-slot serving metadata: the fixed CONNECT parser head and
/// the two 64 KiB `ClientHello` inspector buffers, allocated once per tunnel
/// slot for the process lifetime and reused across connections.
pub const SLOT_WORKSPACE_BYTES: usize = CONNECT_LIMIT + (MAX_CLIENT_HELLO * 2);

/// The total retained serving-workspace bytes across all 512 slots.
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
    /// retained DNS workspace). Constant-derived plan, not an observation:
    /// the traffic store initializes at boot, the serving workspaces at
    /// [`Preallocated::preallocate`](crate::runtime::Preallocated::preallocate),
    /// and the DNS buffers at the DNS transport's own construction.
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

    #[test]
    fn slot_workspace_matches_documented_136_kib() {
        // G5-C06: pin the exact documented per-slot retained workspace figure
        // (CONNECT parser head + two 64 KiB ClientHello buffers) so the
        // arithmetic cannot drift from the design estimate.
        assert_eq!(SLOT_WORKSPACE_BYTES, 136 * 1024);
        assert_eq!(
            SLOT_WORKSPACE_BYTES,
            CONNECT_LIMIT + (MAX_CLIENT_HELLO * 2),
            "definition must stay in sync with its constituents"
        );
    }

    #[test]
    fn serving_workspace_matches_documented_68_mib() {
        assert_eq!(SERVING_WORKSPACE_BYTES, 68 * 1024 * 1024);
        assert_eq!(
            SERVING_WORKSPACE_BYTES,
            TUNNEL_SLOTS * SLOT_WORKSPACE_BYTES,
            "definition must stay in sync with slot count"
        );
    }
}
