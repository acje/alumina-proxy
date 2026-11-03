//! Legacy public facade: serving storage lives canonically in
//! [`crate::runtime::storage`].

pub use crate::runtime::storage::{
    ServeStorage, ServingMode, StartupDecision, StartupError, StartupOutcome,
};
