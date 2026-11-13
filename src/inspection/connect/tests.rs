use super::*;
use crate::config::{Config, parse_config_document};

const HEAD: &str = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";

fn config() -> Config {
    parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n",
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
    let head =
        "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
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
    let head =
        "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n";
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
