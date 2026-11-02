/// The reason a startup exchange failed, captured at the step where the
/// failure was first observable (connect, send, recv, deadline, or a `DoT`
/// TLS-layer cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    Connect,
    Send,
    Receive,
    Timeout,
    /// The `DoT` certificate's SPKI digest did not match the configured
    /// `#pin-sha256=` value.
    PinMismatch,
    /// The `DoT` certificate's `SAN` (or legacy `CN`) did not name the
    /// resolver's `FQDN`/SNI.
    NameMismatch,
    /// The `DoT` chain did not validate against the configured trust anchors
    /// (an empty root store rejects any self-signed cert as `UnknownIssuer`).
    NoTrustAnchor,
    /// A `DoT` TLS-layer failure outside certificate identity: rustls setup
    /// or build failure, protocol error, alert, `EOF`, or socket error.
    TlsProtocol,
}

impl FailureReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            FailureReason::Connect => "connect",
            FailureReason::Send => "send",
            FailureReason::Receive => "receive",
            FailureReason::Timeout => "timeout",
            FailureReason::PinMismatch => "pin_mismatch",
            FailureReason::NameMismatch => "san_mismatch",
            FailureReason::NoTrustAnchor => "no_anchor",
            FailureReason::TlsProtocol => "tls_protocol",
        }
    }
}
/// The reason a name was never attempted inside the startup window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAttemptedReason {
    /// The fixed startup window closed before any exchange for the name was
    /// attempted (the only not-attempted state the window produces).
    WindowClosed,
}

impl NotAttemptedReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            NotAttemptedReason::WindowClosed => "window_closed",
        }
    }
}
/// The per-name terminal outcome of the startup window, carried by the
/// per-name `startup_name` records. A name is reported from its actual latest
/// exchange results: a validated negative (NXDOMAIN or empty NODATA answer)
/// stays distinct from an attempted positive with no eligible bindings and
/// from an exchange failure with its reason, so the final entry never collapses
/// distinct outcome classes into one catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameOutcome {
    /// At least one family holds an eligible non-retired positive binding.
    Resolved,
    /// The latest published outcome for the name was a validated negative
    /// (NXDOMAIN, or an NODATA answer with no eligible bindings).
    Negative,
    /// The latest published outcome was a positive answer whose candidates
    /// were all ineligible, so no binding was published.
    NoEligible,
    /// The latest concluded exchange for the name failed with this reason.
    Failed(FailureReason),
    /// No exchange for the name concluded inside the window.
    NotAttempted(NotAttemptedReason),
}

impl Default for NameOutcome {
    fn default() -> Self {
        NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed)
    }
}
/// The per-resolver verdict of the post-window probe sweep, recorded once each
/// probed resolver's exchange concludes. `Ok` and `Failed` are recorded only
/// for resolvers the sweep actually probed; a resolver the sweep skipped (the
/// active resolver at sweep begin) stays `NotProbed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    Ok,
    Failed(FailureReason),
    NotProbed,
}

impl ProbeVerdict {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ProbeVerdict::Ok => "ok",
            ProbeVerdict::Failed(_) => "failed",
            ProbeVerdict::NotProbed => "not_probed",
        }
    }
}
