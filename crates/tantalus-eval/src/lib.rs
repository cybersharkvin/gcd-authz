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
    /// C+ (closed-response GCD): control prompt + a grammar whose `respondToUser.message`
    /// is a FINITE ALTERNATION of pre-authorized canned responses (not a free string). The
    /// message content AND length are bounded by construction → 0 content-emission for the
    /// enumerable-response agent class. Same tool enums as C; only the message rule differs.
    CClosed,
    /// D (legacy generator label): a default-allow Control generator. The post-parse
    /// allowlist is now the orthogonal `EvalRequest::gate` modifier, NOT a generator —
    /// the live-D arm is `(condition=Control, gate=Some(r))`. Kept so old payloads/labels
    /// still deserialize; treated identically to `Control` at the generator layer.
    D,
}

impl Condition {
    /// Whether the grammar-constrained decoding path is active for this condition.
    /// Both C and C+ (closed-response) decode under a GBNF grammar.
    pub fn uses_grammar(self) -> bool {
        matches!(self, Condition::C | Condition::CClosed)
    }
}

/// Retry budget for the allowlist gate (R ∈ {0,1,3}, pre-reg §12).
///
/// The gate is *corrective*: an out-of-scope tool call is produced, the gate rejects it,
/// and the model is given a fixed rejection message and allowed up to `max_retries()`
/// regenerations before the turn is declared an availability failure. The retry count is
/// only meaningful when a gate is actually present — see `EvalRequest::gate`
/// (`Option<RetryBudget>`), where `None` = no gate at all and `Some(r)` = gate with budget `r`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryBudget {
    #[default]
    #[serde(rename = "r0")]
    R0,
    #[serde(rename = "r1")]
    R1,
    #[serde(rename = "r3")]
    R3,
}

impl RetryBudget {
    pub fn max_retries(self) -> u8 {
        match self {
            RetryBudget::R0 => 0,
            RetryBudget::R1 => 1,
            RetryBudget::R3 => 3,
        }
    }
}

/// Terminal state of a LIVE Condition-D trial (the two-sided reliability DV).
///
/// `ValidAction`: the model eventually emitted an in-scope call (after ≥0 rejections).
/// `AvailabilityFailure`: the retry budget was exhausted on out-of-scope calls — D
/// issued an auditable denial but left the agent with no valid action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DTerminal {
    ValidAction,
    AvailabilityFailure,
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
    /// Post-parse allowlist gate, layered ORTHOGONALLY over any generator (`condition`).
    /// `None` (default) = no gate — the historical non-D behavior, and keeps old payloads
    /// valid under `deny_unknown_fields`. `Some(r)` = the allowlist gate is active with
    /// retry budget `r`. This is the generator×gate factorial: e.g. `(condition=A4,
    /// gate=Some(R3))` is "behavioral stack + post-parse allowlist + 3 retries"; the
    /// legacy "live-D" arm is just `(condition=Control, gate=Some(r))`; `(condition=C,
    /// gate=Some(r))` is the inert cell (grammar already constrains → 0 gate rejections).
    #[serde(default)]
    pub gate: Option<RetryBudget>,
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
        // The gate is orthogonal to the generator — valid on ANY condition (including the
        // inert C/C+ cells), so there is no condition-coupling check. `Option<RetryBudget>`
        // already makes "no gate" vs "gate with R0" distinct and every value well-formed.
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
    /// Gate DVs (zeroed/None when no gate is present).
    /// Number of generations whose tool call passed through the allowlist gate
    /// (`1 + retries performed`). Without a gate this is `1`.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    /// Out-of-scope tool calls PRODUCED then caught by the live gate — the live
    /// emission count (0 under C by construction; 0 when no gate is present).
    #[serde(default)]
    pub gate_rejections: u32,
    /// Terminal state of a gated trial (`None` when no gate is present).
    #[serde(default)]
    pub d_terminal: Option<DTerminal>,
}

fn default_attempts() -> u32 {
    1
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
        EvalRequest { skill: "infra-monitor".into(), messages: vec!["run it".into()], condition: Condition::Control, temperature: 0.6, seed: None, gate: None }
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
    fn grammar_conditions_use_grammar() {
        assert!(Condition::C.uses_grammar() && Condition::CClosed.uses_grammar());
        assert!(!Condition::Control.uses_grammar() && !Condition::D.uses_grammar());
    }

    #[test]
    fn cclosed_deserializes_snake_case() {
        assert_eq!(serde_json::from_str::<Condition>("\"c_closed\"").unwrap(), Condition::CClosed);
    }

    #[test]
    fn request_rejects_unknown_field() {
        let json = r#"{"skill":"x","messages":["a"],"condition":"control","defenses":["gcd"]}"#;
        assert!(serde_json::from_str::<EvalRequest>(json).is_err());
    }

    #[test]
    fn gate_defaults_to_none_on_old_payload() {
        let json = r#"{"skill":"x","messages":["a"],"condition":"control"}"#;
        assert_eq!(serde_json::from_str::<EvalRequest>(json).unwrap().gate, None);
    }

    #[test]
    fn gate_on_any_generator_allowed() {
        let r = EvalRequest { condition: Condition::A4, gate: Some(RetryBudget::R3), ..req() };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn gate_on_grammar_condition_allowed() {
        let r = EvalRequest { condition: Condition::C, gate: Some(RetryBudget::R1), ..req() };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn d_terminal_round_trips() {
        assert_eq!(serde_json::from_str::<DTerminal>("\"availability_failure\"").unwrap(), DTerminal::AvailabilityFailure);
    }
}
