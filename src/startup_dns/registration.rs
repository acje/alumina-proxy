use std::io;

use mio::net::TcpStream;
use mio::{Interest, Registry, Token};

use super::StartupDnsError;

/// Whether the retained transport belongs to this transport's own private poll
/// or to the shared owner's single serving poll. A source has exactly one
/// registry (mio rejects a second); the two modes make the owners mutually
/// exclusive and only `Private` ever touches the DNS-private poll.
///
/// The registration owner performs every cache and operating-system update for
/// its mode: a caller chooses a semantic lifecycle event, never a raw
/// armed-cache write or register/re-register/deregister policy branch.
#[derive(Debug)]
#[repr(transparent)]
pub(super) struct Registration(Mode);

/// The two registration modes: the transport's own private poll, or a shared
/// owner's single poll at `token` with the currently-registered interest in
/// `armed` — `Some(interest)` while registered, `None` while the stream is
/// fresh or closed.
#[derive(Debug)]
enum Mode {
    Private,
    Shared {
        token: Token,
        armed: Option<Interest>,
    },
}

impl Registration {
    /// A private-mode registration against this transport's own DNS-private
    /// poll.
    pub(super) const fn private() -> Self {
        Registration(Mode::Private)
    }

    /// A shared-mode registration for the owner's single poll at `token`, with
    /// no interest registered yet.
    pub(super) const fn shared(token: Token) -> Self {
        Registration(Mode::Shared { token, armed: None })
    }

    /// Whether the transport is registered with the shared owner's poll: the
    /// query that decides which wait owner drives the source.
    pub(super) const fn is_shared(&self) -> bool {
        matches!(self.0, Mode::Shared { .. })
    }

    /// Registers a freshly dialed connection. The private mode performs the
    /// exact connect-time `READABLE | WRITABLE` registration against the
    /// DNS-private poll; the shared mode only invalidates the cached interest,
    /// because the owner registers the source at its next sync once it is
    /// observed.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the private registration fails.
    pub(super) fn begin_connect(
        &mut self,
        registry: &Registry,
        stream: &mut TcpStream,
        token: Token,
    ) -> Result<(), StartupDnsError> {
        match &mut self.0 {
            Mode::Private => registry
                .register(stream, token, Interest::READABLE.add(Interest::WRITABLE))
                .map_err(|e| StartupDnsError::Transport {
                    kind: e.kind(),
                    detail: "register",
                }),
            Mode::Shared { armed, .. } => {
                *armed = None;
                Ok(())
            }
        }
    }

    /// Re-aligns the private-mode registered interest to `interest`; the
    /// shared mode performs no syscall here, because its interest follows the
    /// exchange phase via [`Self::sync_desired`].
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the private re-registration fails.
    pub(super) fn update_interest(
        &mut self,
        registry: &Registry,
        stream: &mut TcpStream,
        token: Token,
        interest: Interest,
    ) -> Result<(), StartupDnsError> {
        match &mut self.0 {
            Mode::Private => registry.reregister(stream, token, interest).map_err(|e| {
                StartupDnsError::Transport {
                    kind: e.kind(),
                    detail: "reregister",
                }
            }),
            Mode::Shared { .. } => Ok(()),
        }
    }

    /// Re-aligns the shared registration to the current exchange phase's
    /// desired interest: registers the stream the first time it is observed,
    /// re-registers it only when the desired interest changes, and deregisters
    /// (or no-ops after a close) when the exchange is idle.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the external registration, re-registration, or
    /// deregistration fails.
    pub(super) fn sync_desired(
        &mut self,
        registry: &Registry,
        stream: Option<&mut TcpStream>,
        desired: Option<Interest>,
    ) -> Result<(), StartupDnsError> {
        let (token, armed) = match &mut self.0 {
            Mode::Shared { token, armed } => (*token, armed),
            Mode::Private => return Ok(()),
        };
        let Some(stream) = stream else {
            *armed = None;
            return Ok(());
        };
        if *armed == desired {
            return Ok(());
        }
        let was_armed = *armed;
        match desired {
            Some(interest) => {
                let result = if was_armed.is_some() {
                    registry.reregister(stream, token, interest)
                } else {
                    registry.register(stream, token, interest)
                };
                result.map_err(|e| StartupDnsError::Transport {
                    kind: e.kind(),
                    detail: "shared",
                })?;
            }
            None => {
                registry
                    .deregister(stream)
                    .map_err(|e| StartupDnsError::Transport {
                        kind: e.kind(),
                        detail: "deregister",
                    })?;
            }
        }
        *armed = desired;
        Ok(())
    }

    /// Closes the transport's registration exactly once. In private mode the
    /// source is deregistered against the DNS-private poll; a `NotFound`
    /// deregister is the benign already-closed case, any other failure is
    /// surfaced as a lifecycle `Transport` error because it leaks a registry
    /// registration. In shared mode the socket belongs to the owner's registry:
    /// dropping it is the deregistration at the kernel layer (closing the fd
    /// removes it from any poll set, and mio keeps no token-keyed table), so
    /// the same token is reusable on a fresh source and `armed` clears to keep
    /// the registration state consistent with the closed stream.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the private deregistration fails.
    pub(super) fn close(
        &mut self,
        registry: &Registry,
        stream: Option<&mut TcpStream>,
    ) -> Result<(), StartupDnsError> {
        match &mut self.0 {
            Mode::Private => stream.map_or(Ok(()), |stream| match registry.deregister(stream) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StartupDnsError::Transport {
                    kind: e.kind(),
                    detail: "deregister",
                }),
            }),
            Mode::Shared { armed, .. } => {
                *armed = None;
                Ok(())
            }
        }
    }

    /// Clears the shared registration cache for an abandoned source during
    /// owner shutdown.
    pub(super) const fn abandon(&mut self) {
        if let Mode::Shared { armed, .. } = &mut self.0 {
            *armed = None;
        }
    }
}

#[cfg(test)]
impl Registration {
    pub(super) const fn shared_armed(&self) -> Option<Interest> {
        match &self.0 {
            Mode::Shared { armed, .. } => *armed,
            Mode::Private => None,
        }
    }

    pub(super) const fn set_shared_armed(&mut self, armed: Option<Interest>) {
        if let Mode::Shared { armed: slot, .. } = &mut self.0 {
            *slot = armed;
        }
    }
}
