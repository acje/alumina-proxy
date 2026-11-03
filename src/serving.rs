//! Legacy public facade: the serving reactor lives canonically in
//! [`crate::runtime::reactor`].

pub use crate::runtime::reactor::{ServeError, Serving, Shutdown};
