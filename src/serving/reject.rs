use std::time::Instant;

use crate::client_hello::HelloRejectReason;
use crate::config::FixedHostname;
use crate::enforcement::policy::AnyIllegalCause;
use crate::log::RejectReason;

use super::Refusal;
use super::{Serving, Stage};

impl Serving {
    pub(super) fn refuse(&mut self, index: usize, refusal: Refusal) {
        let hostname = self.slots[index].approved;
        self.refuse_impl(index, refusal, hostname);
    }

    /// Refuses a connection whose requested hostname is known but whose slot
    /// has not yet been approved (the pre-Peer refusal sites, G11-C01): the
    /// hostname is carried into the reject telemetry without setting
    /// `slot.approved`.
    pub(super) fn refuse_with_hostname(
        &mut self,
        index: usize,
        refusal: Refusal,
        hostname: FixedHostname,
    ) {
        self.refuse_impl(index, refusal, Some(hostname));
    }

    fn refuse_impl(&mut self, index: usize, refusal: Refusal, hostname: Option<FixedHostname>) {
        let body = refusal.body();
        self.emit_reject(index, refusal.reason(), hostname);
        if self.block_all_latched() {
            self.close_slot(index);
            return;
        }
        let ws = &mut self.slots[index];
        ws.down_off = 0;
        ws.down[..body.len()].copy_from_slice(body);
        ws.down_len = body.len();
        ws.stage = Stage::Refusing(body);
        self.flush_down(index);
        if self.slots[index].down_len == 0 {
            self.close_slot(index);
        }
    }

    /// Emits one warn-reject record for the rejected slot: the client address
    /// when readable and the hostname when one was supplied — the approved
    /// hostname, or the requested hostname for a pre-Peer refusal.
    pub(super) fn emit_reject(
        &mut self,
        index: usize,
        reason: RejectReason,
        hostname: Option<FixedHostname>,
    ) {
        let secs = self.storage.cache_secs(Instant::now());
        let client = self.slots[index]
            .client
            .as_ref()
            .and_then(|c| c.peer_addr().ok());
        let hostname = hostname.as_ref().map(FixedHostname::as_str);
        self.storage
            .logs_mut()
            .reject(secs, reason, client, hostname);
    }

    pub(super) fn reject_hello(&mut self, index: usize, reason: HelloRejectReason) {
        self.slots[index].gate.on_hello_rejected();
        self.any_illegal(index, AnyIllegalCause::TlsProfile(reason));
        self.emit_reject(
            index,
            RejectReason::TlsValidation,
            self.slots[index].approved,
        );
        self.close_slot(index);
    }

    pub(super) fn close_slot(&mut self, index: usize) {
        let now = Instant::now();
        let ws = &mut self.slots[index];
        ws.stage = Stage::Closing;
        let slot = ws.handle.take();
        let tunnel = ws.tunnel.take();
        ws.client.take();
        ws.upstream.take();
        let capture = std::mem::take(&mut ws.capture);
        ws.reset();
        self.sync_live_deadline(index);
        self.storage
            .enforcement_mut()
            .note_consumed_capture(capture);
        if let Some(tunnel) = tunnel {
            self.storage.release_tunnel(tunnel);
        } else if let Some(slot) = slot {
            self.storage.release(slot);
        }
        self.note_occupancy(now);
    }
}
