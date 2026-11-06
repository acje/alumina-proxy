use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::dns::cache::Family;
use crate::dns::transport::{
    EXCHANGE_DEADLINE_SECS, ExchangeClass, StartupDnsError, TurnResult, WindowLedger,
};
use crate::runtime::storage::{StartupError, StartupOutcome};

use super::Serving;

impl Serving {
    /// Drives the startup DNS window cooperatively over the single serving
    /// poll. The retained DNS transport is attached to the serving poll
    /// *before* selection starts, so the boot-armed poll carries the SIGTERM
    /// self-pipe, DNS freshness, and the listener together: a first-observed
    /// SIGTERM during the window is seen within one bounded poll instead of
    /// being invisible for the window's full duration, and it settles as the
    /// typed terminated outcome that never binds a listener. Each iteration
    /// advances the in-flight cooperative exchange, selects the next due step
    /// only while idle, and folds a single bounded wait over the serving poll
    /// (signal priority is handled inside [`Self::run_once`]).
    #[expect(
        clippy::too_many_lines,
        reason = "long cooperative startup-DNS window loop folding poll/exchange/selection phases"
    )]
    pub(crate) fn run_startup_window(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<StartupOutcome, StartupError> {
        self.attach_dns_shared().map_err(|err| {
            StartupError::Dns(StartupDnsError::Transport {
                kind: err.kind,
                detail: "shared",
            })
        })?;
        let resolvers = *self.storage.config().resolver_set();
        let window_deadline = self
            .storage
            .dns_mut()
            .begin_window(nameserver, resolvers, now0, window)?;
        let names = self.storage.config().allowlist().len();
        for ordinal in 0..names {
            for family in Family::ALL {
                self.storage
                    .schedules_mut()
                    .overwrite_due_at(ordinal, family, now0)
                    .map_err(StartupDnsError::from)?;
            }
        }
        let mut ledger = WindowLedger::new(names);
        let mut terminated = false;
        loop {
            if self.is_shutdown() {
                terminated = true;
                break;
            }
            let now = self.storage.dns().now_u64();
            ledger
                .refresh_resolved(self.storage.cache(), now)
                .map_err(StartupDnsError::Cache)?;
            if ledger.all_resolved() {
                break;
            }
            if Instant::now() >= window_deadline {
                if let Some((ordinal, ex_family)) = self.storage.dns().active_identity() {
                    self.storage
                        .schedules_mut()
                        .release_selection(ordinal, ex_family)
                        .map_err(StartupDnsError::from)?;
                    self.storage.dns_mut().cancel_for_shutdown();
                }
                break;
            }
            if let Some((ordinal, ex_family)) = self.storage.dns().active_identity() {
                match self.storage.advance_dns()? {
                    None | Some(TurnResult::Pending | TurnResult::Superseded) => {}
                    Some(TurnResult::Published(kind)) => {
                        ledger.mark_published(ordinal, kind);
                    }
                    Some(TurnResult::Failed(reason)) => {
                        if ledger.mark_failed(ordinal, ex_family, reason) {
                            let now = self.storage.dns().now_u64();
                            self.storage.startup_warning_first(
                                now,
                                ordinal,
                                ex_family,
                                reason.as_str(),
                            );
                        }
                    }
                }
            }
            ledger
                .refresh_resolved(self.storage.cache(), self.storage.dns().now_u64())
                .map_err(StartupDnsError::Cache)?;
            if !self.storage.dns().has_active_exchange() {
                let secs = self.storage.dns().now_u64();
                let selected = self
                    .storage
                    .schedules_mut()
                    .select_due(secs)
                    .map_err(StartupDnsError::from)?;
                if let Some(token) = selected {
                    let ordinal = token.name();
                    let family = token.family();
                    if ledger.is_resolved(ordinal) {
                        self.storage
                            .schedules_mut()
                            .release_selection(ordinal, family)
                            .map_err(StartupDnsError::from)?;
                        continue;
                    }
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    let deadline =
                        Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
                    ledger.track_attempt(ordinal, family);
                    self.storage.start_dns_exchange(
                        ordinal,
                        family,
                        deadline,
                        ExchangeClass::Startup,
                    )?;
                    continue;
                }
            }

            self.sync_dns_shared().map_err(|err| {
                StartupError::Dns(StartupDnsError::Transport {
                    kind: err.kind,
                    detail: "shared",
                })
            })?;
            if self.is_shutdown() {
                terminated = true;
                break;
            }
            let now_i = Instant::now();
            let remaining = window_deadline.saturating_duration_since(now_i);
            let exchange_wait = self
                .storage
                .dns()
                .exchange_deadline()
                .map(|d| d.saturating_duration_since(Instant::now()));
            let dns_wait = match exchange_wait {
                Some(exchange_wait) => exchange_wait.min(remaining),
                None => self
                    .storage
                    .dns()
                    .next_due_wait(self.storage.schedules(), &ledger)?
                    .min(remaining),
            };
            let log_wait = self
                .storage
                .logs()
                .next_drain(now_i)
                .map(|retry| retry.saturating_duration_since(Instant::now()));
            let wait =
                if self.storage.dns().has_active_exchange() && !self.storage.dns().needs_wait() {
                    Duration::ZERO
                } else {
                    log_wait.map_or(dns_wait, |log_wait| dns_wait.min(log_wait))
                };
            self.storage.logs_mut().drain_sink();
            #[cfg(test)]
            if let Some(hook) = self.pre_poll.as_ref() {
                (hook.as_ref())(self);
            }
            self.run_once(Some(wait)).map_err(|err| {
                StartupError::Dns(StartupDnsError::Transport {
                    kind: err.kind,
                    detail: "startup-serve",
                })
            })?;
        }
        if !terminated {
            #[cfg(test)]
            if let Some(hook) = self.pre_settlement.take() {
                hook();
            }
            self.run_once(Some(Duration::ZERO)).map_err(|err| {
                StartupError::Dns(StartupDnsError::Transport {
                    kind: err.kind,
                    detail: "startup-settle",
                })
            })?;
            terminated = self.is_shutdown();
        }
        if terminated {
            self.storage.dns_mut().cancel_for_shutdown();
        }
        self.sync_dns_shared().map_err(|err| {
            StartupError::Dns(StartupDnsError::Transport {
                kind: err.kind,
                detail: "shared",
            })
        })?;
        let elapsed = self.storage.dns().window_start().elapsed().as_secs();
        ledger
            .refresh_resolved(self.storage.cache(), now0.saturating_add(elapsed))
            .map_err(StartupDnsError::Cache)?;
        self.storage
            .settle_startup(now0, ledger.finish(), elapsed, terminated)
    }
}
