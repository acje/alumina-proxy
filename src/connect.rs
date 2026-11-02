use std::fmt;

use crate::config::{Allowlist, FixedHostname};

/// Maximum CONNECT request-head size, including headers and the terminating
/// CRLF sequence. The bound applies to the head only, never to tunnel bytes
/// that may arrive in the same read as the delimiter.
pub const CONNECT_LIMIT: usize = 8 * 1024;

/// Maximum number of header lines a CONNECT head may carry. Every line yielded
/// after the request line counts toward the bound, so a head may carry at most
/// `MAX_HEADER_LINES` header fields.
pub const MAX_HEADER_LINES: usize = 16;

const END_OF_HEAD: &[u8] = b"\r\n\r\n";
const HTTP_11: &[u8] = b"HTTP/1.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    hostname: FixedHostname,
    port: u16,
}

impl ConnectRequest {
    /// The normalized lowercase hostname (no trailing dot, no port).
    #[must_use]
    pub fn hostname(&self) -> &str {
        self.hostname.as_str()
    }

    /// The validated destination port (1..=65535) from the CONNECT line.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The fixed-capacity validated hostname type, for gate validation that
    /// compares an SNI against the approved CONNECT host without allocation.
    #[must_use]
    pub const fn fixed_hostname(&self) -> &FixedHostname {
        &self.hostname
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    TooLong,
    MethodNotConnect,
    UnsupportedVersion,
    TargetNotAuthorityForm,
    MalformedRequestLine { detail: &'static str },
    BareLineFeed,
    BareCarriageReturn,
    ObsFold,
    InvalidHostname { detail: &'static str },
    WrongPort { got: u16 },
    PortOutOfRange { got: u32 },
    TransferEncoding,
    NonzeroContentLength { got: u64 },
    DuplicateContentLength,
    TooManyHeaderLines,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::TooLong => write!(f, "CONNECT request-head exceeds 8 KiB"),
            ConnectError::MethodNotConnect => write!(f, "CONNECT request method is not CONNECT"),
            ConnectError::UnsupportedVersion => {
                write!(f, "CONNECT request version is not HTTP/1.1")
            }
            ConnectError::TargetNotAuthorityForm => {
                write!(f, "CONNECT target is not authority-form host:port")
            }
            ConnectError::MalformedRequestLine { detail } => {
                write!(f, "CONNECT request line malformed: {detail}")
            }
            ConnectError::BareLineFeed => write!(f, "CONNECT request contains a bare line feed"),
            ConnectError::BareCarriageReturn => {
                write!(f, "CONNECT request contains a bare carriage return")
            }
            ConnectError::ObsFold => write!(f, "CONNECT request contains obsolete line folding"),
            ConnectError::InvalidHostname { detail } => {
                write!(f, "CONNECT hostname invalid: {detail}")
            }
            ConnectError::WrongPort { got } => {
                write!(f, "CONNECT port {got} denied; port must be 1..=65535")
            }
            ConnectError::PortOutOfRange { got } => {
                write!(f, "CONNECT port {got} out of range; port must be 1..=65535")
            }
            ConnectError::TransferEncoding => write!(
                f,
                "CONNECT Transfer-Encoding is rejected for a tunnel setup"
            ),
            ConnectError::NonzeroContentLength { got } => {
                write!(f, "CONNECT Content-Length {got} rejected; only 0")
            }
            ConnectError::DuplicateContentLength => write!(f, "CONNECT duplicate Content-Length"),
            ConnectError::TooManyHeaderLines => write!(
                f,
                "CONNECT request carries more than {MAX_HEADER_LINES} header lines"
            ),
        }
    }
}

/// The payload-less finite discriminant of a CONNECT-head parse rejection.
/// The projected kind is keyed only by variant identity — never by an
/// attacker-controlled port, length, or detail string — so per-cause
/// capture/fold stays bounded and exact-in-kind while defensive payloads are
/// erased at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectHeadReason {
    TooLong,
    MethodNotConnect,
    UnsupportedVersion,
    TargetNotAuthorityForm,
    MalformedRequestLine,
    BareLineFeed,
    BareCarriageReturn,
    ObsFold,
    InvalidHostname,
    WrongPort,
    PortOutOfRange,
    TransferEncoding,
    NonzeroContentLength,
    DuplicateContentLength,
    TooManyHeaderLines,
}

impl ConnectHeadReason {
    /// Projects a [`ConnectError`] onto its finite discriminant, dropping the
    /// attacker-supplied payload (`got` width / length / detail string).
    #[must_use]
    pub const fn from_connect_error(err: &ConnectError) -> ConnectHeadReason {
        use ConnectError as E;
        match err {
            E::TooLong => ConnectHeadReason::TooLong,
            E::MethodNotConnect => ConnectHeadReason::MethodNotConnect,
            E::UnsupportedVersion => ConnectHeadReason::UnsupportedVersion,
            E::TargetNotAuthorityForm => ConnectHeadReason::TargetNotAuthorityForm,
            E::MalformedRequestLine { .. } => ConnectHeadReason::MalformedRequestLine,
            E::BareLineFeed => ConnectHeadReason::BareLineFeed,
            E::BareCarriageReturn => ConnectHeadReason::BareCarriageReturn,
            E::ObsFold => ConnectHeadReason::ObsFold,
            E::InvalidHostname { .. } => ConnectHeadReason::InvalidHostname,
            E::WrongPort { .. } => ConnectHeadReason::WrongPort,
            E::PortOutOfRange { .. } => ConnectHeadReason::PortOutOfRange,
            E::TransferEncoding => ConnectHeadReason::TransferEncoding,
            E::NonzeroContentLength { .. } => ConnectHeadReason::NonzeroContentLength,
            E::DuplicateContentLength => ConnectHeadReason::DuplicateContentLength,
            E::TooManyHeaderLines => ConnectHeadReason::TooManyHeaderLines,
        }
    }

    /// The zero-based index into a fixed per-discriminant counter array.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The number of finite CONNECT-head discriminants.
    pub const COUNT: usize = 15;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Feed {
    /// The request head is not yet delimited; supply more bytes.
    Incomplete,
    /// The request head is delimited. `head_len` is the number of bytes of
    /// the byte stream the head consumed, including the CRLFCRLF delimiter.
    /// The parsed request or first policy violation is available via
    /// [`ConnectParser::result`]. Bytes beyond `head_len` (for example an
    /// early `ClientHello`) belong to the tunnel gate and must not be forwarded
    /// before the gate passes.
    Complete { head_len: usize },
}

/// Incremental CONNECT request-head parser with a fixed 8 KiB storage. Parsing
/// is independent of TCP read boundaries and of bytes coalesced after the
/// delimiter: the first CRLFCRLF sequence closes the head, the parser retains
/// only head bytes, and a `ClientHello` arriving in the same read is left to the
/// caller via `head_len`.
#[derive(Clone, Debug)]
pub struct ConnectParser {
    head: [u8; CONNECT_LIMIT],
    head_len: usize,
    scan_cursor: usize,
    result: Option<Result<ConnectRequest, ConnectError>>,
}

impl Default for ConnectParser {
    fn default() -> Self {
        ConnectParser::new()
    }
}

impl ConnectParser {
    #[must_use]
    pub const fn new() -> Self {
        ConnectParser {
            head: [0u8; CONNECT_LIMIT],
            head_len: 0,
            scan_cursor: 0,
            result: None,
        }
    }

    /// The parsed request or first policy violation, present once the head is
    /// delimited.
    #[must_use]
    pub const fn result(&self) -> Option<&Result<ConnectRequest, ConnectError>> {
        self.result.as_ref()
    }

    /// Feeds bytes into the parser, returning `Complete` once the head is
    /// delimited and on every subsequent feed. Terminal re-entry consumes no
    /// bytes and preserves the original parse result without parsing again.
    ///
    /// # Errors
    ///
    /// Returns `TooLong` when the head bytes (excluding any tunnel bytes
    /// coalesced after the delimiter) exceed `CONNECT_LIMIT`.
    pub fn feed(&mut self, data: &[u8]) -> Result<Feed, ConnectError> {
        if self.result.is_some() {
            return Ok(Feed::Complete {
                head_len: self.head_len,
            });
        }
        let room = CONNECT_LIMIT - self.head_len;
        let take = data.len().min(room);
        if take > 0 {
            self.head[self.head_len..self.head_len + take].copy_from_slice(&data[..take]);
            self.head_len += take;
        }
        if let Some(delim) = self.find_delimiter() {
            let head_len = delim + END_OF_HEAD.len();
            let head = &self.head[..delim];
            self.result = Some(parse_request(head));
            self.head_len = head_len;
            return Ok(Feed::Complete { head_len });
        }
        if take < data.len() {
            return Err(ConnectError::TooLong);
        }
        Ok(Feed::Incomplete)
    }

    /// Incrementally locates the `\r\n\r\n` head terminator, scanning only the
    /// window appended since the previous feed. The head is capped at
    /// `CONNECT_LIMIT` (8 KiB), so the whole scan is bounded by a fixed
    /// constant; the cursor turns the per-feed full-head rescan from O(N²) into
    /// O(N) across feeds (W1-L1b-F6).
    fn find_delimiter(&mut self) -> Option<usize> {
        if self.head_len < END_OF_HEAD.len() {
            return None;
        }
        let start = self.scan_cursor.min(self.head_len - END_OF_HEAD.len());
        for i in start..=self.head_len - END_OF_HEAD.len() {
            if &self.head[i..i + END_OF_HEAD.len()] == END_OF_HEAD {
                return Some(i);
            }
        }
        self.scan_cursor = self.head_len - (END_OF_HEAD.len() - 1);
        None
    }
}

fn parse_request(head: &[u8]) -> Result<ConnectRequest, ConnectError> {
    if bare_line_feed(head).is_some() {
        return Err(ConnectError::BareLineFeed);
    }
    if bare_carriage_return(head).is_some() {
        return Err(ConnectError::BareCarriageReturn);
    }
    let mut lines = Lines::new(head);
    let request_line = lines.next().ok_or(ConnectError::MalformedRequestLine {
        detail: "empty head",
    })?;
    let request = parse_request_line(request_line)?;
    let mut content_length: Option<u64> = None;
    let mut header_lines = 0usize;
    while let Some(line) = lines.next() {
        header_lines += 1;
        if header_lines > MAX_HEADER_LINES {
            return Err(ConnectError::TooManyHeaderLines);
        }
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(ConnectError::ObsFold);
        }
        let colon =
            line.iter()
                .position(|&b| b == b':')
                .ok_or(ConnectError::MalformedRequestLine {
                    detail: "header without colon",
                })?;
        let name = &line[..colon];
        if name.is_empty() || !is_tchar_header_name(name) {
            return Err(ConnectError::MalformedRequestLine {
                detail: "header name contains whitespace or non-tchar",
            });
        }
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            let parsed = parse_content_length(value).ok_or(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            })?;
            match content_length {
                Some(_) => return Err(ConnectError::DuplicateContentLength),
                None => content_length = Some(parsed),
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(ConnectError::TransferEncoding);
        }
    }
    if let Some(len) = content_length.filter(|&len| len != 0) {
        return Err(ConnectError::NonzeroContentLength { got: len });
    }
    Ok(request)
}

/// Returns the index of the first bare line feed, or `None` when every line
/// feed is preceded by a carriage return.
fn bare_line_feed(head: &[u8]) -> Option<usize> {
    (0..head.len()).find(|&i| head[i] == 0x0a && (i == 0 || head[i - 1] != 0x0d))
}

/// Returns the index of the first bare carriage return, or `None` when every
/// carriage return is immediately followed by a line feed. A `0x0d` at the end
/// of the head is a bare carriage return because the head excludes the CRLFCRLF
/// delimiter, so its `0x0a` cannot follow within the head.
fn bare_carriage_return(head: &[u8]) -> Option<usize> {
    (0..head.len()).find(|&i| head[i] == 0x0d && head.get(i + 1) != Some(&0x0a))
}

struct Lines<'a> {
    buf: &'a [u8],
    next: usize,
}

impl<'a> Lines<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Lines { buf, next: 0 }
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.next > self.buf.len() {
            return None;
        }
        let rest = &self.buf[self.next..];
        if let Some(crlf) = rest.windows(2).position(|w| w == b"\r\n") {
            let line = &rest[..crlf];
            self.next += crlf + 2;
            Some(line)
        } else {
            self.next = self.buf.len() + 1;
            Some(rest)
        }
    }
}

fn parse_request_line(line: &[u8]) -> Result<ConnectRequest, ConnectError> {
    let method_end =
        line.iter()
            .position(|&b| b == b' ')
            .ok_or(ConnectError::MalformedRequestLine {
                detail: "not exactly three tokens",
            })?;
    if &line[..method_end] != b"CONNECT" {
        return Err(ConnectError::MethodNotConnect);
    }
    let after_method = method_end + 1;
    let target_end = line[after_method..]
        .iter()
        .position(|&b| b == b' ')
        .map(|p| after_method + p)
        .ok_or(ConnectError::MalformedRequestLine {
            detail: "not exactly three tokens",
        })?;
    let version = &line[target_end + 1..];
    if version.contains(&b' ') {
        // A space inside the version token means the target itself contained a
        // space (e.g. `CONNECT host :443 HTTP/1.1`): the request line has more
        // than the three CONNECT tokens, so it is malformed, never a genuine
        // version mismatch (W1-L1b-F2).
        return Err(ConnectError::MalformedRequestLine {
            detail: "not exactly three tokens",
        });
    }
    if version != HTTP_11 {
        return Err(ConnectError::UnsupportedVersion);
    }
    parse_target(&line[after_method..target_end])
}

fn is_tchar_header_name(name: &[u8]) -> bool {
    name.iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

/// Parses a Content-Length value as canonical decimal digits; signs,
/// non-digit characters, and leading zeros are rejected.
fn parse_content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
        return None;
    }
    let mut total: u64 = 0;
    for &b in value {
        let digit = u64::from(b.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        total = total.checked_mul(10)?.checked_add(digit)?;
    }
    Some(total)
}

fn parse_target(target: &[u8]) -> Result<ConnectRequest, ConnectError> {
    if target.starts_with(b"/")
        || target.starts_with(b"*")
        || target.windows(3).any(|w| w == b"://")
    {
        return Err(ConnectError::TargetNotAuthorityForm);
    }
    let Some(colon) = target.iter().rposition(|&b| b == b':') else {
        return Err(ConnectError::TargetNotAuthorityForm);
    };
    let host = &target[..colon];
    let port = &target[colon + 1..];
    if port.is_empty() || !port.iter().all(u8::is_ascii_digit) {
        return Err(ConnectError::MalformedRequestLine {
            detail: "port is not numeric",
        });
    }
    if port.len() > 1 && port[0] == b'0' {
        return Err(ConnectError::MalformedRequestLine {
            detail: "port has a leading zero",
        });
    }
    let port_u32: u32 = std::str::from_utf8(port)
        .ok()
        .and_then(|p| p.parse().ok())
        .ok_or(ConnectError::MalformedRequestLine {
            detail: "port is not numeric",
        })?;
    if port_u32 == 0 {
        return Err(ConnectError::WrongPort { got: 0 });
    }
    let port =
        u16::try_from(port_u32).map_err(|_| ConnectError::PortOutOfRange { got: port_u32 })?;
    if host.contains(&b':') && !host.starts_with(b"[") {
        return Err(ConnectError::InvalidHostname {
            detail: "IPv6 literal rejected",
        });
    }
    if host.starts_with(b"[") || host.is_empty() {
        return Err(ConnectError::InvalidHostname {
            detail: "address literal rejected",
        });
    }
    let normalized = FixedHostname::normalize(host).ok_or(ConnectError::InvalidHostname {
        detail: "hostname is not a lowercase ASCII FQDN",
    })?;
    Ok(ConnectRequest {
        hostname: normalized,
        port,
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Whether the request hostname and port exactly match one allowlist entry.
/// The normalized `<fqdn>` must equal the entry's bare name and the CONNECT
/// port must equal the entry's port, so a same-name different-port request is
/// denied (403) even when the hostname is allowlisted.
#[must_use]
pub fn is_allowlisted(request: &ConnectRequest, allowlist: &Allowlist) -> bool {
    allowlist.iter().any(|entry| {
        entry.as_str().as_bytes() == request.hostname().as_bytes() && entry.port() == request.port()
    })
}

#[cfg(test)]
mod tests;
