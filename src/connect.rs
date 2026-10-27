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
mod tests {
    use super::*;
    use crate::config::{Config, parse_config_document};

    const HEAD: &str = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";

    fn config() -> Config {
        parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n",
        )
        .expect("valid config")
    }

    fn parse_full(bytes: &[u8]) -> Result<ConnectRequest, ConnectError> {
        let mut parser = ConnectParser::new();
        match parser.feed(bytes).expect("no limit error") {
            Feed::Complete { .. } => parser.result().copied().expect("complete has result"),
            Feed::Incomplete => Err(ConnectError::MalformedRequestLine {
                detail: "incomplete",
            }),
        }
    }

    #[test]
    fn parses_valid_connect_with_content_length_zero() {
        let req = parse_full(HEAD.as_bytes()).expect("valid");
        assert_eq!(req.hostname(), "sub.example.org");
        assert!(is_allowlisted(&req, config().allowlist()));
    }

    #[test]
    fn accepts_uppercase_hostname_and_normalizes() {
        let head = "CONNECT SUB.Example.ORG:443 HTTP/1.1\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("valid");
        assert_eq!(req.hostname(), "sub.example.org");
    }

    #[test]
    fn coalesced_tunnel_bytes_do_not_block_completion() {
        let mut parser = ConnectParser::new();
        let head = HEAD.as_bytes();
        let mut combined = Vec::new();
        combined.extend_from_slice(head);
        combined.push(0x16);
        match parser.feed(&combined).expect("feed") {
            Feed::Complete { head_len } => {
                let req = parser.result().copied().expect("settled");
                assert_eq!(req.expect("parse").hostname(), "sub.example.org");
                assert_eq!(head_len, head.len(), "consumed must stop at the delimiter");
            }
            Feed::Incomplete => panic!("coalesced ClientHello must not block the CONNECT head"),
        }
    }

    #[test]
    fn complete_reentry_preserves_terminal_result_without_reparse() {
        let mut parser = ConnectParser::new();
        let terminal_feed = parser.feed(HEAD.as_bytes()).expect("complete");
        let terminal_result = parser.result().copied().expect("settled");
        parser.head[0] = b'X';

        assert_eq!(parser.feed(b"ignored replay"), Ok(terminal_feed));
        assert_eq!(parser.result().copied(), Some(terminal_result));
    }

    #[test]
    fn fragmented_feed_is_boundary_independent() {
        let mut parser = ConnectParser::new();
        for chunk in HEAD.as_bytes().chunks(5) {
            match parser.feed(chunk).expect("no limit") {
                Feed::Incomplete => {}
                Feed::Complete { .. } => {
                    let req = parser.result().copied().expect("settled");
                    assert_eq!(req.expect("parse").hostname(), "sub.example.org");
                    return;
                }
            }
        }
        panic!("never completed");
    }

    #[test]
    fn rejects_zero_port() {
        let head = "CONNECT sub.example.org:0 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::WrongPort { got: 0 })
        );
    }

    #[test]
    fn accepts_non_443_port_and_reports_it() {
        let head = "CONNECT sub.example.org:8443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("any 1..=65535 port parses");
        assert_eq!(req.hostname(), "sub.example.org");
        assert_eq!(req.port(), 8443);
    }

    #[test]
    fn rejects_leading_zero_port() {
        let head = "CONNECT sub.example.org:0443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "port has a leading zero",
            })
        );
    }

    #[test]
    fn rejects_port_out_of_range() {
        let head = "CONNECT sub.example.org:65536 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::PortOutOfRange { got: 65536 })
        );
    }

    #[test]
    fn rejects_allowlist_port_mismatch() {
        let head = "CONNECT sub.example.org:8443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("parses");
        assert!(!is_allowlisted(&req, config().allowlist()));
    }

    #[test]
    fn rejects_ip_literal() {
        let head = "CONNECT 1.2.3.4:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::InvalidHostname {
                detail: "hostname is not a lowercase ASCII FQDN",
            })
        );
    }

    #[test]
    fn rejects_http2_version() {
        let head = "CONNECT sub.example.org:443 HTTP/2.0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_http_1_0_connect() {
        let head = b"CONNECT sub.example.org:443 HTTP/1.0\r\n\r\n";
        assert_eq!(parse_full(head), Err(ConnectError::UnsupportedVersion));
    }

    #[test]
    fn rejects_bare_http_version_prefix() {
        let head = "CONNECT sub.example.org:443 HTTP/\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_non_connect_method() {
        let head = "GET sub.example.org:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MethodNotConnect)
        );
    }

    #[test]
    fn rejects_lowercase_connect_method() {
        let head = "connect sub.example.org:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MethodNotConnect),
            "the CONNECT method match must be byte-exact"
        );
    }

    #[test]
    fn rejects_single_token_request_line() {
        let head = "CONNECT\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "not exactly three tokens",
            })
        );
    }

    #[test]
    fn rejects_two_token_request_line() {
        let head = "CONNECT sub.example.org:443\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "not exactly three tokens",
            })
        );
    }

    #[test]
    fn rejects_space_in_target_as_malformed_request_line() {
        // `CONNECT host :443 HTTP/1.1` mis-splits at the first space after the
        // method, leaving a space inside the version token; that is a malformed
        // request line (four tokens), never a genuine version mismatch
        // (W1-L1b-F2).
        let head = "CONNECT host :443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "not exactly three tokens",
            })
        );
    }

    #[test]
    fn rejects_origin_form_target() {
        let head = "CONNECT /index.html HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TargetNotAuthorityForm)
        );
    }

    #[test]
    fn rejects_asterisk_form_target() {
        let head = "CONNECT * HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TargetNotAuthorityForm)
        );
    }

    #[test]
    fn rejects_absolute_form_target() {
        let head = "CONNECT http://sub.example.org:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TargetNotAuthorityForm)
        );
    }

    #[test]
    fn rejects_target_without_port() {
        let head = "CONNECT sub.example.org HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TargetNotAuthorityForm)
        );
    }

    #[test]
    fn rejects_header_whitespace_before_colon() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length : 0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "header name contains whitespace or non-tchar",
            })
        );
    }

    #[test]
    fn rejects_empty_header_name() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\n: x\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "header name contains whitespace or non-tchar",
            })
        );
    }

    #[test]
    fn rejects_plus_in_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: +0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            })
        );
    }

    #[test]
    fn rejects_leading_zero_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 000\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            })
        );
    }

    #[test]
    fn rejects_transfer_encoding() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TransferEncoding)
        );
    }

    #[test]
    fn rejects_nonzero_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::NonzeroContentLength { got: 5 })
        );
    }

    #[test]
    fn rejects_bare_lf() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\n\r\n\r\n";
        assert_eq!(parse_full(head.as_bytes()), Err(ConnectError::BareLineFeed));
    }

    #[test]
    fn rejects_bare_carriage_return_in_header_value() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nX-Test: a\rb\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::BareCarriageReturn)
        );
    }

    #[test]
    fn rejects_bare_carriage_return_before_delimiter() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nX-Test: a\r\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::BareCarriageReturn)
        );
    }

    #[test]
    fn rejects_obs_fold() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\n Authorization: x\r\n\r\n";
        assert_eq!(parse_full(head.as_bytes()), Err(ConnectError::ObsFold));
    }

    #[test]
    fn rejects_over_limit() {
        let mut parser = ConnectParser::new();
        let filler = vec![b'a'; CONNECT_LIMIT + 1];
        assert_eq!(parser.feed(&filler), Err(ConnectError::TooLong));
    }

    #[test]
    fn over_limit_applies_to_head_not_trailing() {
        let mut parser = ConnectParser::new();
        let head = HEAD.as_bytes();
        let mut big = Vec::with_capacity(CONNECT_LIMIT + 16);
        big.extend_from_slice(head);
        big.extend_from_slice(&[0x16; CONNECT_LIMIT]);
        match parser.feed(&big).expect("feed") {
            Feed::Complete { .. } => {
                let req = parser.result().copied().expect("settled");
                assert_eq!(req.expect("parse").hostname(), "sub.example.org");
            }
            Feed::Incomplete => panic!("trailing bytes must not count toward the head bound"),
        }
    }

    fn head_with_header_fields(n: usize) -> Vec<u8> {
        let mut head = Vec::with_capacity(64 + n * 10);
        head.extend_from_slice(b"CONNECT sub.example.org:443 HTTP/1.1\r\n");
        for _ in 0..n {
            head.extend_from_slice(b"X-Hdr: v\r\n");
        }
        head.extend_from_slice(b"\r\n");
        head
    }

    #[test]
    fn rejects_header_line_count_above_bound() {
        let head = head_with_header_fields(MAX_HEADER_LINES + 1);
        assert_eq!(
            parse_full(&head),
            Err(ConnectError::TooManyHeaderLines),
            "each header field yields one line after the request line, so \
             {MAX_HEADER_LINES} + 1 fields exceed the {MAX_HEADER_LINES}-line bound"
        );
    }

    #[test]
    fn allows_header_line_count_at_bound() {
        let head = head_with_header_fields(MAX_HEADER_LINES);
        let req = parse_full(&head).expect("16 header fields yield 16 lines, the bound");
        assert_eq!(req.hostname(), "sub.example.org");
    }

    #[test]
    fn lines_next_without_cr_does_not_underflow() {
        let mut lines = Lines::new(&[0x0a]);
        assert!(lines.next().is_some());
    }

    #[test]
    fn not_allowlisted_host_is_forbidden() {
        let req = parse_full(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n").expect("parse");
        assert!(!is_allowlisted(&req, config().allowlist()));
    }

    #[test]
    fn rejects_duplicate_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        let err = parse_full(head.as_bytes()).expect_err("doubled CL must be rejected");
        assert_eq!(err, ConnectError::DuplicateContentLength);
        assert_eq!(
            ConnectHeadReason::from_connect_error(&err),
            ConnectHeadReason::DuplicateContentLength,
            "the duplicate-CL guard must project onto its own enforcement cause"
        );
    }

    #[test]
    fn rejects_duplicate_content_length_with_differing_values() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::DuplicateContentLength),
            "any second CL header is rejected regardless of value"
        );
    }

    #[test]
    fn rejects_unbracketed_ipv6_literal() {
        let head = "CONNECT ::1:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::InvalidHostname {
                detail: "IPv6 literal rejected",
            })
        );
    }

    #[test]
    fn rejects_bracketed_ipv6_literal() {
        let head = "CONNECT [::1]:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::InvalidHostname {
                detail: "address literal rejected",
            })
        );
    }

    #[test]
    fn rejects_empty_hostname() {
        let head = "CONNECT :443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::InvalidHostname {
                detail: "address literal rejected",
            })
        );
    }

    #[test]
    fn rejects_colon_in_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 1:\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            })
        );
    }

    #[test]
    fn rejects_alpha_in_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 1a\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            })
        );
    }

    #[test]
    fn rejects_content_length_u64_overflow() {
        let head =
            "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            }),
            "2^64 must overflow the checked arithmetic, not wrap to zero"
        );
    }

    #[test]
    fn accepts_content_length_zero_with_trailing_whitespace() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0 \t\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("trailing space+tab trimmed before parse");
        assert_eq!(req.hostname(), "sub.example.org");
    }

    #[test]
    fn rejects_lowercase_content_length_nonzero() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\ncontent-length: 5\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::NonzeroContentLength { got: 5 }),
            "header-name matching must be case-insensitive"
        );
    }

    #[test]
    fn rejects_uppercase_content_length_nonzero() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nCONTENT-LENGTH: 5\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::NonzeroContentLength { got: 5 }),
            "header-name matching must be case-insensitive"
        );
    }

    #[test]
    fn accepts_lowercase_content_length_zero() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\ncontent-length: 0\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("lowercase CL: 0 is accepted");
        assert_eq!(req.hostname(), "sub.example.org");
    }

    #[test]
    fn rejects_lowercase_transfer_encoding() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TransferEncoding),
            "header-name matching must be case-insensitive"
        );
    }

    #[test]
    fn accepts_trailing_dot_connect_and_allowlists() {
        let head = "CONNECT sub.example.org.:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("trailing dot normalized away");
        assert_eq!(req.hostname(), "sub.example.org");
        assert!(
            is_allowlisted(&req, config().allowlist()),
            "normalized trailing-dot hostname must still authorize against the allowlist"
        );
    }

    #[test]
    fn rejects_raw_utf8_hostname() {
        let head = "CONNECT bücher.example:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::InvalidHostname {
                detail: "hostname is not a lowercase ASCII FQDN",
            }),
            "raw non-ASCII bytes must be rejected by normalize"
        );
    }

    #[test]
    fn accepts_ascii_punycode_hostname() {
        let head = "CONNECT xn--bcher-kva.example:443 HTTP/1.1\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("A-label form is ASCII and accepted");
        assert_eq!(req.hostname(), "xn--bcher-kva.example");
    }

    #[test]
    fn scan_cursor_advances_past_scanned_bytes_on_miss() {
        let mut parser = ConnectParser::new();
        let head = b"CONNECT sub.example.org:443 HTTP/1.1\r\nHost: x\r\n";
        parser
            .feed(head)
            .expect("delimiter-free head stays incomplete");
        assert_eq!(
            parser.scan_cursor,
            parser.head_len - (END_OF_HEAD.len() - 1),
            "a miss must advance the cursor to the last position a delimiter could still start"
        );
    }

    #[test]
    fn incremental_scan_finds_delimiter_straddling_feed_boundary() {
        let mut parser = ConnectParser::new();
        parser
            .feed(b"CONNECT sub.example.org:443 HTTP/1.1\r\nHo")
            .expect("incomplete");
        parser.feed(b"st: x\r\n\r").expect("incomplete");
        let f = parser.feed(b"\n").expect("complete");
        assert!(
            matches!(f, Feed::Complete { .. }),
            "a delimiter split across feeds must still close the head"
        );
    }
}
