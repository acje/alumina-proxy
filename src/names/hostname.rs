pub const FQDN_MAX_LEN: usize = crate::names::rules::FQDN_MAX_LEN;

/// Fixed-capacity validated hostname (lowercase ASCII FQDN without a trailing
/// dot), used on serving paths and protocol gates to avoid per-request or
/// per-connection allocation. The label rules mirror the config `Fqdn` type;
/// the numeric-shorthand (IP-literal-looking) form is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedHostname {
    bytes: [u8; FQDN_MAX_LEN],
    len: u8,
}

impl ApprovedHostname {
    /// The normalized lowercase bytes, without a trailing dot.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The normalized name as a `&str`; always ASCII by construction.
    ///
    /// # Panics
    ///
    /// Panics only if the normalized bytes are not valid UTF-8, impossible by
    /// construction because normalization accepts ASCII input only.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "ApprovedHostname normalization keeps only ASCII bytes, so they are always valid UTF-8"
    )]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("ApprovedHostname is ASCII")
    }

    /// Normalizes `input` into a legal lowercase FQDN without a trailing dot,
    /// returning `None` for empty, over-length, non-ASCII, IP-literal-shaped,
    /// or malformed names. A single trailing dot is stripped before the
    /// `FQDN_MAX_LEN` bound is applied, so a 254-byte input consisting of a
    /// valid 253-byte name plus a trailing dot is accepted; any other 254-byte
    /// input is rejected without copying outside the fixed buffer.
    #[must_use]
    pub fn normalize(input: &[u8]) -> Option<ApprovedHostname> {
        let len = normalized_len(input)?;
        let mut out = ApprovedHostname {
            bytes: [0u8; FQDN_MAX_LEN],
            len: u8::try_from(len).ok()?,
        };
        for (i, &b) in input[..len].iter().enumerate() {
            out.bytes[i] = b.to_ascii_lowercase();
        }
        if !is_legal(&out.bytes[..usize::from(out.len)]) {
            return None;
        }
        Some(out)
    }
}

/// Returns the byte length to copy after stripping one trailing dot and
/// bounding the name, or `None` for an empty, over-length, non-ASCII, or
/// dot-only input.
const fn normalized_len(input: &[u8]) -> Option<usize> {
    if input.is_empty() || input.len() > FQDN_MAX_LEN + 1 {
        return None;
    }
    if !input.is_ascii() {
        return None;
    }
    let len = if input[input.len() - 1] == b'.' {
        input.len() - 1
    } else {
        input.len()
    };
    if len == 0 || len > FQDN_MAX_LEN {
        return None;
    }
    Some(len)
}

/// Whether every label of the normalized name is legal and the whole name is
/// not an IP-literal shape.
fn is_legal(name: &[u8]) -> bool {
    name.split(|&b| b == b'.')
        .all(|label| crate::names::rules::classify_label(label).is_ok())
        && !crate::names::rules::is_ip_literal_shape(name)
}

#[cfg(test)]
mod tests;
