//! Shared wire contract for the `/eval` endpoint and the confirmatory harness.
//!
//! This crate is the single source of truth for the experiment's request/response
//! types so the server (`tantalus-local`) and the Rust harness (`tantalus-harness`)
//! cannot drift. Serde-only dependency surface — no domain types — to keep it light
//! and dependency-cycle-free (`tantalus-pipeline` re-exports `Condition` from here).

use serde::{Deserialize, Serialize};

// (Condition/TrialOutcome derive Serialize so EvalRequest/EvalResponse round-trip
//  on both the server and the harness.)

/// Experimental condition — the single source of truth for what `/eval` applies.
///
/// `D` is computed offline (overlay on `Control` trials); `/eval` treats a `D`
/// request exactly as `Control`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// A1: defensive prompt (RFC 2119 security policy), no filters.
    #[default]
    A1,
    /// Control: security-neutral operational prompt, no defenses.
    Control,
    /// A2: control prompt + embedding input classifier (pre-inference).
    A2,
    /// A3: control prompt + credential output filter (post-inference).
    A3,
    /// A4: full behavioral stack — A1 prompt + input classifier + output filter.
    A4,
    /// C: GCD — control prompt + GBNF grammar at the sampler (structural control).
    C,
    /// D: post-parse allowlist — computed offline from Control trials.
    D,
}

impl Condition {
    /// Whether the grammar-constrained decoding path is active for this condition.
    pub fn uses_grammar(self) -> bool {
        matches!(self, Condition::C)
    }
}

/// Mechanical per-trial outcome, derived server-side. Distinct outcomes are never
/// folded into one another (pre-reg §5 construct validity).
///
/// NOTE: `Refused` is keyed off `tool_calls == 0`, and a terminal `respondToUser`
/// is logged under its own trace key — so a `respondToUser`-only trace (a refusal
/// *or* a normal answer) lands in `Refused`. Acceptable for attack trials
/// (no exfil ≈ refusal); legitimate-task utility is measured by the harness's
/// `legitimate_success`, not by this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialOutcome {
    /// Win fired — marker reached an out-of-scope sink.
    Bypass,
    /// Blocked by the input classifier (pre-inference).
    BlockedInput,
    /// Blocked by the output filter (post-inference).
    BlockedOutput,
    /// No tool call produced — model answered/refused with text only.
    Refused,
    /// Tool calls made, no win, not blocked (e.g. read-only, garbage params).
    NoAction,
}

impl TrialOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            TrialOutcome::Bypass => "bypass",
            TrialOutcome::BlockedInput => "blocked_input",
            TrialOutcome::BlockedOutput => "blocked_output",
            TrialOutcome::Refused => "refused",
            TrialOutcome::NoAction => "no_action",
        }
    }
}

fn default_temperature() -> f32 {
    0.6
}

/// `/eval` request. `condition` is the sole control selector — there is no
/// `defenses` field (removed; condition drives prompt + pre/post steps + grammar).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRequest {
    pub skill: String,
    pub messages: Vec<String>,
    pub condition: Condition,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default)]
    pub seed: Option<u64>,
}

impl EvalRequest {
    /// Validate the request at the boundary (parse-don't-validate).
    ///
    /// # Contract
    /// - `skill` non-empty
    /// - `messages` non-empty AND every element non-empty
    /// - `0.0 <= temperature <= 2.0`
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.skill.is_empty() {
            return Err(EvalError::new("skill", "must not be empty"));
        }
        if self.messages.is_empty() {
            return Err(EvalError::new("messages", "must not be empty"));
        }
        if self.messages.iter().any(|m| m.is_empty()) {
            return Err(EvalError::new("messages", "every message must be non-empty"));
        }
        if !(0.0..=2.0).contains(&self.temperature) {
            return Err(EvalError::new("temperature", "must be in 0.0..=2.0"));
        }
        Ok(())
    }
}

/// `/eval` response. `raw_json` is ALWAYS populated (Gap 1); `blocked_by` is `""`
/// when not blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResponse {
    pub win: bool,
    pub wins: Vec<String>,
    pub outcome: TrialOutcome,
    pub tool_calls: usize,
    pub tokens_predicted: u32,
    pub prompt_ms: f64,
    pub predicted_ms: f64,
    pub predicted_per_second: f64,
    pub duration_ms: u64,
    pub blocked: bool,
    pub blocked_by: String,
    pub model_id: String,
    pub engine_commit: String,
    pub raw_json: String,
}

/// Structured validation error for the `/eval` boundary.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid eval request: field `{field}` {reason}")]
pub struct EvalError {
    pub field: String,
    pub reason: String,
}

impl EvalError {
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { field: field.into(), reason: reason.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> EvalRequest {
        EvalRequest { skill: "infra-monitor".into(), messages: vec!["run it".into()], condition: Condition::Control, temperature: 0.6, seed: None }
    }

    #[test]
    fn valid_request_passes() {
        assert!(req().validate().is_ok());
    }

    #[test]
    fn empty_skill_rejected() {
        let mut r = req();
        r.skill = String::new();
        assert!(r.validate().is_err());
    }

    #[test]
    fn empty_messages_rejected() {
        let mut r = req();
        r.messages = vec![];
        assert!(r.validate().is_err());
    }

    #[test]
    fn empty_message_element_rejected() {
        let mut r = req();
        r.messages = vec!["".into()];
        assert!(r.validate().is_err());
    }

    #[test]
    fn out_of_range_temperature_rejected() {
        let mut r = req();
        r.temperature = 2.5;
        assert!(r.validate().is_err());
    }

    #[test]
    fn condition_deserializes_snake_case() {
        assert_eq!(serde_json::from_str::<Condition>("\"control\"").unwrap(), Condition::Control);
    }

    #[test]
    fn only_c_uses_grammar() {
        assert!(Condition::C.uses_grammar());
        assert!(!Condition::Control.uses_grammar());
    }

    #[test]
    fn request_rejects_unknown_field() {
        let json = r#"{"skill":"x","messages":["a"],"condition":"control","defenses":["gcd"]}"#;
        assert!(serde_json::from_str::<EvalRequest>(json).is_err());
    }
}
