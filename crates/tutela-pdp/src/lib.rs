//! Tutela's embedded decision engine (`tutela-pdp`).
//!
//! Phase A, first part: the model language and its compiler ([`model`]). It
//! reads a product's `tutela.resources.toml` ([`docs/MANIFEST.md`]), checks
//! it, and returns a compiled [`model::Model`] or every problem it found. It
//! also compares two models and classifies each change as narrowing, neutral
//! or widening.
//!
//! Planned, not here yet (Phase A, next step): the evaluator `Pdp::check`,
//! `Pdp::batch`, `Pdp::list_filter` and `Pdp::write_check`
//! ([`docs/CONTRACTS.md`] section 6.5).
//!
//! [`docs/MANIFEST.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/MANIFEST.md
//! [`docs/CONTRACTS.md`]: https://github.com/f8fvwgzc/tutela/blob/main/docs/CONTRACTS.md

pub mod model;
