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
