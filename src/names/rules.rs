pub(crate) const FQDN_MAX_LEN: usize = 253;
const MAX_LABEL: usize = 63;

pub(crate) enum LabelFault {
    Empty,
    TooLong,
    BadHyphen,
    DisallowedByte,
}

pub(crate) fn classify_label(label: &[u8]) -> Result<(), LabelFault> {
    if label.is_empty() {
        return Err(LabelFault::Empty);
    }
    if label.len() > MAX_LABEL {
        return Err(LabelFault::TooLong);
    }
    if label.starts_with(b"-") || label.ends_with(b"-") {
        return Err(LabelFault::BadHyphen);
    }
    if !label
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(LabelFault::DisallowedByte);
    }
    Ok(())
}

pub(crate) fn is_ip_literal_shape(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes[0].is_ascii_digit()
        && bytes.iter().all(|b| *b == b'.' || b.is_ascii_digit())
}
