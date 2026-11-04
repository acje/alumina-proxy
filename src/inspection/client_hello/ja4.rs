use std::fmt;

use super::{ALPN, MAX_CIPHERS, MAX_EXTENSIONS, SERVER_NAME, TLS10, TLS12, TLS13, is_grease};

/// Error returned when JA4 fingerprinting input exceeds a fixed capacity.
///
/// The public [`ja4_fingerprint`] boundary is fallible so an out-of-contract
/// caller passing more non-GREASE ciphers than `MAX_CIPHERS` or more
/// non-GREASE, non-SNI, non-ALPN extensions than `MAX_EXTENSIONS` receives an
/// explicit error instead of an out-of-bounds panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ja4Error {
    /// More than `MAX_CIPHERS` non-GREASE cipher suites were offered.
    TooManyCiphers,
    /// More than `MAX_EXTENSIONS` non-GREASE, non-SNI, non-ALPN extensions were
    /// offered.
    TooManyExtensions,
}

impl fmt::Display for Ja4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ja4Error::TooManyCiphers => {
                write!(f, "more than MAX_CIPHERS non-GREASE cipher suites offered")
            }
            Ja4Error::TooManyExtensions => write!(
                f,
                "more than MAX_EXTENSIONS non-GREASE, non-SNI, non-ALPN extensions offered"
            ),
        }
    }
}

/// Computes the canonical `FoxIO` `JA4` client fingerprint as the fixed 36-byte
/// ASCII string `t{ver}{sni}{cc:02}{ec:02}{alpn}_{chash}_{ehash}` per the
/// `alumina-xfbq8` amendment (docs/alumina-proxy.md:879-895). Pure and
/// allocation-free: the SHA-256 inputs are fed incrementally through a
/// stack-based `ring::digest::Context`, and the sorted cipher/extension lists
/// are materialized in fixed-capacity stack buffers.
///
/// `version` is the highest non-GREASE offered version; `ciphers` and
/// `extensions` are the retained wire-order lists; `alpn` is the raw first
/// ALPN value; `sigalgs` the retained `signature_algorithms` values in wire
/// order. SNI presence (`d`/`i`) is derived from `extensions` containing
/// extension `0x0000`.
///
/// # Errors
///
/// Returns [`Ja4Error::TooManyCiphers`] when `ciphers` holds more than
/// `MAX_CIPHERS` non-GREASE suites and [`Ja4Error::TooManyExtensions`] when
/// `extensions` holds more than `MAX_EXTENSIONS` non-GREASE, non-SNI, non-ALPN
/// types, rather than indexing out of bounds.
pub fn ja4_fingerprint(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    alpn: &[u8],
    sigalgs: &[u16],
) -> Result<[u8; 36], Ja4Error> {
    let ver = version_token(version);
    let sni = if extensions.contains(&SERVER_NAME) {
        b'd'
    } else {
        b'i'
    };
    let cc = count_token(non_grease_count(ciphers));
    let ec = count_token(non_grease_count(extensions));
    let alpn = alpn_token(alpn);
    let chash = cipher_hash12(ciphers)?;
    let ehash = ehash12(extensions, sigalgs)?;

    let mut out = [0u8; 36];
    out[0] = b't';
    out[1..3].copy_from_slice(&ver);
    out[3] = sni;
    out[4..6].copy_from_slice(&cc);
    out[6..8].copy_from_slice(&ec);
    out[8..10].copy_from_slice(&alpn);
    out[10] = b'_';
    out[11..23].copy_from_slice(&chash);
    out[23] = b'_';
    out[24..36].copy_from_slice(&ehash);
    Ok(out)
}

const fn version_token(version: u16) -> [u8; 2] {
    match version {
        TLS13 => *b"13",
        TLS12 => *b"12",
        0x0302 => *b"11",
        TLS10 => *b"10",
        _ => *b"00",
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "count capped at 99 fits u8"
)]
const fn count_token(count: usize) -> [u8; 2] {
    let c = if count > 99 { 99 } else { count } as u8;
    [b'0' + c / 10, b'0' + c % 10]
}

const fn is_alnum(b: u8) -> bool {
    b.is_ascii_digit() || b.is_ascii_lowercase() || b.is_ascii_uppercase()
}

const fn hex_nibble(v: u8) -> u8 {
    let n = v & 0x0f;
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

const fn alpn_token(alpn: &[u8]) -> [u8; 2] {
    if alpn.is_empty() {
        return *b"00";
    }
    if alpn.len() == 1 {
        let c = alpn[0];
        if is_alnum(c) {
            return [c, c];
        }
        return [hex_nibble(c >> 4), hex_nibble(c)];
    }
    let first = alpn[0];
    let last = alpn[alpn.len() - 1];
    if is_alnum(first) && is_alnum(last) {
        [first, last]
    } else {
        [hex_nibble(first >> 4), hex_nibble(last)]
    }
}

fn non_grease_count(values: &[u16]) -> usize {
    values.iter().filter(|&&v| !is_grease(v)).count()
}

#[expect(clippy::cast_possible_truncation, reason = "nibble extraction fits u8")]
fn feed_u16_hex(ctx: &mut ring::digest::Context, value: u16) {
    let mut buf = [0u8; 4];
    for (i, slot) in buf.iter_mut().enumerate() {
        let shift = 12 - 4 * i;
        *slot = hex_nibble((value >> shift) as u8);
    }
    ctx.update(&buf);
}

fn hash12_finish(ctx: ring::digest::Context) -> [u8; 12] {
    let digest = ctx.finish();
    let bytes = digest.as_ref();
    let mut out = [0u8; 12];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = bytes[i / 2];
        let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
        *slot = hex_nibble(nibble);
    }
    out
}

fn cipher_hash12(ciphers: &[u16]) -> Result<[u8; 12], Ja4Error> {
    let mut sorted = [0u16; MAX_CIPHERS];
    let mut n = 0usize;
    for &c in ciphers {
        if !is_grease(c) {
            if n == MAX_CIPHERS {
                return Err(Ja4Error::TooManyCiphers);
            }
            sorted[n] = c;
            n += 1;
        }
    }
    if n == 0 {
        return Ok([b'0'; 12]);
    }
    sorted[..n].sort_unstable();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut first = true;
    for &c in &sorted[..n] {
        if !first {
            ctx.update(b",");
        }
        first = false;
        feed_u16_hex(&mut ctx, c);
    }
    Ok(hash12_finish(ctx))
}

fn ehash12(extensions: &[u16], sigalgs: &[u16]) -> Result<[u8; 12], Ja4Error> {
    let mut sorted = [0u16; MAX_EXTENSIONS];
    let mut n = 0usize;
    for &e in extensions {
        if !is_grease(e) && e != SERVER_NAME && e != ALPN {
            if n == MAX_EXTENSIONS {
                return Err(Ja4Error::TooManyExtensions);
            }
            sorted[n] = e;
            n += 1;
        }
    }
    if n == 0 {
        return Ok([b'0'; 12]);
    }
    sorted[..n].sort_unstable();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut first = true;
    for &e in &sorted[..n] {
        if !first {
            ctx.update(b",");
        }
        first = false;
        feed_u16_hex(&mut ctx, e);
    }
    if sigalgs.iter().any(|&s| !is_grease(s)) {
        ctx.update(b"_");
    }
    first = true;
    for &s in sigalgs {
        if is_grease(s) {
            continue;
        }
        if !first {
            ctx.update(b",");
        }
        first = false;
        feed_u16_hex(&mut ctx, s);
    }
    Ok(hash12_finish(ctx))
}

#[cfg(test)]
mod tests {
    use super::alpn_token;

    #[test]
    fn ja4_alpn_tokens() {
        assert_eq!(alpn_token(&[]), *b"00");
        assert_eq!(alpn_token(b"h2"), *b"h2");
        assert_eq!(alpn_token(b"x"), *b"xx");
        assert_eq!(alpn_token(b"h"), *b"hh");
        assert_eq!(alpn_token(&[0xab]), *b"ab");
        assert_eq!(alpn_token(&[0x20]), *b"20");
        assert_eq!(alpn_token(&[0x20, 0x61]), *b"21");
        assert_eq!(alpn_token(&[0x30, 0xab, 0xcd, 0x31]), *b"01");
        assert_eq!(alpn_token(&[0xab, 0xcd]), *b"ad");
        assert_eq!(alpn_token(&[0xba, 0xad]), *b"bd");
    }
}
