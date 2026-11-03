use crate::log::RejectReason;

/// A typed refusal to serve a connection: the single source of truth mapping
/// forward to both the fixed HTTP body and the fixed `RejectReason` log
/// vocabulary. The refuse path never reverse-infers a reason from a byte
/// match, so a new refusal class cannot silently default to `BadRequest`.
#[derive(Clone, Copy)]
pub(super) enum Refusal {
    BadRequest,
    Forbidden,
    NoResolvedAddresses,
    DialFailed,
    SetupTimeout,
}

const BODY_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n";
const BODY_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n";
const BODY_502_NO_RESOLVED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 22\r\n\r\nno resolved addresses\n";
const BODY_502_DIAL_FAILED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 27\r\n\r\nupstream connection failed\n";
const BODY_504: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 23\r\n\r\nsetup deadline expired\n";

impl Refusal {
    pub(super) const fn descriptor(self) -> RefusalWire {
        match self {
            Refusal::BadRequest => RefusalWire {
                body: BODY_400,
                reason: RejectReason::BadRequest,
            },
            Refusal::Forbidden => RefusalWire {
                body: BODY_403,
                reason: RejectReason::Forbidden,
            },
            Refusal::NoResolvedAddresses => RefusalWire {
                body: BODY_502_NO_RESOLVED,
                reason: RejectReason::DialFailed,
            },
            Refusal::DialFailed => RefusalWire {
                body: BODY_502_DIAL_FAILED,
                reason: RejectReason::DialFailed,
            },
            Refusal::SetupTimeout => RefusalWire {
                body: BODY_504,
                reason: RejectReason::SetupTimeout,
            },
        }
    }
}

pub(super) struct RefusalWire {
    pub(super) body: &'static [u8],
    pub(super) reason: RejectReason,
}
