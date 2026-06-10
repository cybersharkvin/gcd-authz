//! `bank-experiment` — the big-N evaluation harness (the Galloway driver).
//!
//! Runs the shared attack corpus through every condition × model, records each
//! trial in SQLite, and emits the headline: per attack class, the **bypass rate**
//! of the negative controls (A/B/D) vs the **block rate** of GCD (C), with
//! Clopper-Pearson confidence intervals — plus overhead percentiles and the
//! `G_s` correctness oracle.
//!
//! Modules: [`contracts`] (typed corpus/trial/summary), [`corpus`] (the embedded
//! attacks), [`scopes`] (the evaluated authorization scopes), [`driver`] (live +
//! synthetic trials), [`db`] (SQLite), [`stats`] (CIs + percentiles), [`report`]
//! (the Galloway table), [`oracle`] (the step-3 correctness gate).

pub mod contracts;
pub mod corpus;
pub mod db;
pub mod driver;
pub mod oracle;
pub mod report;
pub mod scopes;
pub mod stats;
