//! Fuzzing: templates with payload positions, four attack modes, payload sources (lists,
//! files and generators) and processing, and a concurrent engine.

pub mod engine;
pub mod plan;
pub mod sets;

pub use engine::{run, EngineConfig, FuzzResult, Outcome, StoreMode};
pub use plan::{names_script, process, Chain, Mode, Plan, Template, DEFAULT_MARKER, PROCESSORS};
pub use sets::{load_payloads, parse_oob, source_file, Gen, OobForm, Set};
