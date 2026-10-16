//! Intruder-style fuzzing: templates with payload positions, four attack modes,
//! payload sources and processing, and a concurrent engine.

pub mod engine;
pub mod plan;

pub use engine::{run, EngineConfig, FuzzResult, Outcome, StoreMode};
pub use plan::{load_payloads, process, Mode, Plan, Template, DEFAULT_MARKER, PROCESSORS};
