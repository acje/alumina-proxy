use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::dns::cache::Family;
use crate::dns::transport::{
    EXCHANGE_DEADLINE_SECS, ExchangeClass, StartupDnsError, TurnResult, WindowLedger,
};
use crate::runtime::storage::{StartupError, StartupOutcome};

use super::{ServeError, Serving};

/// Why the startup window's current iteration stops: every allowlisted name is
/// already usable, the absolute window deadline expired, or shutdown was
/// observed before either.
enum WindowEnd {
    Resolved,
    Expired,
    Terminated,
}

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
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when arming, the cooperative exchange,
    /// the serving poll, or the settlement fails.
    pub(crate) fn run_startup_window(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<StartupOutcome, StartupError> {
        let (mut ledger, window_deadline) = self.arm_startup_window(nameserver, now0, window)?;
        let terminated = loop {
            if let Some(end) = self.startup_window_end(&mut ledger, window_deadline)? {
                break matches!(end, WindowEnd::Terminated);
            }
            if self.storage.dns().has_active_exchange() {
                self.advance_startup_exchange(&mut ledger)?;
            }
            self.refresh_startup_ledger(&mut ledger, self.storage.dns().now_u64())?;
            if !self.storage.dns().has_active_exchange()
                && self.select_startup_step(&mut ledger, window_deadline)?
            {
                continue;
            }
            self.sync_dns_shared().map_err(startup_shared_error)?;
            if self.is_shutdown() {
                break true;
            }
            let wait = self.startup_poll_wait(&ledger, window_deadline)?;
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
        };
        self.settle_startup_window(now0, terminated, &mut ledger)
    }

    /// Arms the startup DNS window: attaches the retained transport to the
    /// serving poll, anchors the window on the boot clock, marks every
    /// name-family due at the window origin, and returns the fresh ledger with
    /// the absolute window deadline.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the transport cannot join the
    /// poll, the window anchor overflows, or a schedule cannot be due-dated.
    fn arm_startup_window(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<(WindowLedger, Instant), StartupError> {
        self.attach_dns_shared().map_err(startup_shared_error)?;
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
        Ok((WindowLedger::new(names), window_deadline))
    }

    /// The window's stop condition for the current iteration, in signal order:
    /// shutdown observed first, then the cache refresh and full-resolution
    /// check, then the absolute deadline, which releases any active selection
    /// before canceling for shutdown. `None` keeps the window serving.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the resolver cache refresh or the
    /// deadline's selection release fails.
    fn startup_window_end(
        &mut self,
        ledger: &mut WindowLedger,
        window_deadline: Instant,
    ) -> Result<Option<WindowEnd>, StartupError> {
        if self.is_shutdown() {
            return Ok(Some(WindowEnd::Terminated));
        }
        let now = self.storage.dns().now_u64();
        self.refresh_startup_ledger(ledger, now)?;
        if ledger.all_resolved() {
            return Ok(Some(WindowEnd::Resolved));
        }
        if Instant::now() < window_deadline {
            return Ok(None);
        }
        self.expire_startup_window()?;
        Ok(Some(WindowEnd::Expired))
    }

    /// Releases the active selection at the window deadline and cancels the
    /// in-flight exchange for shutdown, so a frozen window never strands a
    /// schedule guard or a retained connection.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the selected step cannot be
    /// released.
    fn expire_startup_window(&mut self) -> Result<(), StartupError> {
        let Some((ordinal, ex_family)) = self.storage.dns().active_identity() else {
            return Ok(());
        };
        self.storage
            .schedules_mut()
            .release_selection(ordinal, ex_family)
            .map_err(StartupDnsError::from)?;
        self.storage.dns_mut().cancel_for_shutdown();
        Ok(())
    }

    /// Refreshes the ledger's resolved-name mask from the cache at `now`.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the cache cannot be read.
    fn refresh_startup_ledger(
        &self,
        ledger: &mut WindowLedger,
        now: u64,
    ) -> Result<(), StartupError> {
        ledger
            .refresh_resolved(self.storage.cache(), now)
            .map_err(StartupDnsError::Cache)?;
        Ok(())
    }

    /// Advances the single in-flight cooperative exchange against the ledger: a
    /// published turn merges into the ledger, and the first counted failure
    /// emits the single first-failure warning.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the exchange turn fails.
    fn advance_startup_exchange(&mut self, ledger: &mut WindowLedger) -> Result<(), StartupError> {
        let Some((ordinal, ex_family)) = self.storage.dns().active_identity() else {
            return Ok(());
        };
        match self.storage.advance_dns()? {
            None | Some(TurnResult::Pending | TurnResult::Superseded) => {}
            Some(TurnResult::Published(kind)) => ledger.mark_published(ordinal, ex_family, kind),
            Some(TurnResult::Failed(reason)) => {
                if ledger.mark_failed(ordinal, ex_family, reason) {
                    let now = self.storage.dns().now_u64();
                    self.storage
                        .startup_warning_first(now, ordinal, ex_family, reason.as_str());
                }
            }
        }
        Ok(())
    }

    /// Selects the next due step while the window is idle: a selection already
    /// resolved is released and the iteration restarts, otherwise the step
    /// gets the exchange deadline clipped to the window and starts as a
    /// startup exchange. Returns whether the iteration restarts before the
    /// serving poll.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when selection, release, or the exchange
    /// start fails.
    fn select_startup_step(
        &mut self,
        ledger: &mut WindowLedger,
        window_deadline: Instant,
    ) -> Result<bool, StartupError> {
        let secs = self.storage.dns().now_u64();
        let Some(token) = self
            .storage
            .schedules_mut()
            .select_due(secs)
            .map_err(StartupDnsError::from)?
        else {
            return Ok(false);
        };
        let ordinal = token.name();
        let family = token.family();
        if ledger.is_resolved(ordinal) {
            self.storage
                .schedules_mut()
                .release_selection(ordinal, family)
                .map_err(StartupDnsError::from)?;
            return Ok(true);
        }
        let remaining = window_deadline.saturating_duration_since(Instant::now());
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
        ledger.track_attempt(ordinal, family);
        self.storage
            .start_dns_exchange(ordinal, family, deadline, ExchangeClass::Startup)?;
        Ok(true)
    }

    /// The single bounded wait folded into the serving poll: the in-flight
    /// exchange deadline or the earliest due step, clipped to the window's
    /// remaining time, and further clipped by the next log drain. An active
    /// exchange that needs no readiness wait forces a zero wait for prompt
    /// handling.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the next due step cannot be
    /// computed.
    fn startup_poll_wait(
        &self,
        ledger: &WindowLedger,
        window_deadline: Instant,
    ) -> Result<Duration, StartupError> {
        let now = Instant::now();
        let remaining = window_deadline.saturating_duration_since(now);
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
                .next_due_wait(self.storage.schedules(), ledger)?
                .min(remaining),
        };
        let log_wait = self
            .storage
            .logs()
            .next_drain(now)
            .map(|retry| retry.saturating_duration_since(Instant::now()));
        Ok(
            if self.storage.dns().has_active_exchange() && !self.storage.dns().needs_wait() {
                Duration::ZERO
            } else {
                log_wait.map_or(dns_wait, |log_wait| dns_wait.min(log_wait))
            },
        )
    }

    /// Settles the frozen window: the test settlement hook, one zero-duration
    /// poll for the terminal outcome, shutdown cancellation, the shared
    /// re-sync, and the final refresh before the typed report is recorded.
    ///
    /// # Errors
    ///
    /// Returns the typed startup error when the settlement poll, the shared
    /// re-sync, the final refresh, or the storage settlement fails.
    fn settle_startup_window(
        &mut self,
        now0: u64,
        mut terminated: bool,
        ledger: &mut WindowLedger,
    ) -> Result<StartupOutcome, StartupError> {
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
        self.sync_dns_shared().map_err(startup_shared_error)?;
        let elapsed = self.storage.dns().window_start().elapsed().as_secs();
        self.refresh_startup_ledger(ledger, now0.saturating_add(elapsed))?;
        self.storage
            .settle_startup(now0, ledger.finish(), elapsed, terminated)
    }
}

/// Maps a serving-poll error at the startup boundary to the shared DNS
/// registration detail the window reports.
const fn startup_shared_error(ServeError { kind }: ServeError) -> StartupError {
    StartupError::Dns(StartupDnsError::Transport {
        kind,
        detail: "shared",
    })
}
