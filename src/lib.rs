#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod alloc;
pub mod boot;
pub mod cache;
pub mod client_hello;
pub mod config;
pub mod connect;
pub mod dns;
pub mod eligibility;
mod enforcement;
#[cfg(any(test, debug_assertions))]
pub mod fault;
pub mod fuzz;
pub mod gate;
mod incident_report;
pub mod inventory;
pub mod log;
pub mod preflight;
pub mod resolver;
pub mod runtime;
pub mod schedule;
pub mod serve;
pub mod serving;
pub mod startup_dns;
pub mod worker;

mod name_rules {
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
}
