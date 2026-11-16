//! Test/debug-only: spec L17 requires the fuzz loop under test, not a shipped release surface.
#[cfg(any(test, debug_assertions))]
pub mod fuzz;
