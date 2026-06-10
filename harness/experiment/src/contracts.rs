//! Strongly-typed harness contracts (per `docs/PLAN.md` → Harness contracts and
//! `RESEARCH_DESIGN.md` §5). The corpus, every trial row, and every summary cell
//! are typed; validation is explicit.

use bank_types::WinConditionId;
pub use bank_pipeline::Condition;
use serde::{Deserialize, Serialize};

/// Minimum paraphrases per attack case (pre-registration knob; fixed before runs).
pub const MIN_PARAPHRASES: usize = 5;

/// The coverage-overlay frameworks an attack case is tagged with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Owasp,
    Atlas,
    NistRmf,
}

/// Security (in-scope for this paper) vs safety (out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Security,
    Safety,
}

/// The 3-stage escalation: direct → indirect/second-order → adaptive/encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStage {
    Direct,
    SecondOrder,
    Adaptive,
}

/// One attack case (a "malware family member"): a win class, a stage, paraphrase
/// variants, and the sentinel `action_marker` whose appearance in a structured
/// action is the binary success signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackCase {
    pub id: String,
    pub win: WinConditionId,
    pub class: String,
    pub owasp_id: String,
    #[serde(default)]
    pub atlas_id: Option<String>,
    pub nist_fn: String,
    pub scope: Scope,
    pub stage: AttackStage,
    pub paraphrases: Vec<String>,
    pub action_marker: String,
}

impl AttackCase {
    /// Validate the invariants: ids/markers non-empty, enough paraphrases, security-scoped.
    pub fn validate(&self) -> Result<(), HarnessError> {
        let bad = |reason: &str| Err(HarnessError::Corpus { case: self.id.clone(), reason: reason.into() });
        if self.id.is_empty() {
            return bad("empty id");
        }
        if self.action_marker.is_empty() {
            return bad("empty action_marker");
        }
        if self.paraphrases.len() < MIN_PARAPHRASES {
            return bad("fewer than MIN_PARAPHRASES paraphrases");
        }
        if self.scope != Scope::Security {
            return bad("scope must be security");
        }
        Ok(())
    }
}

/// One trial's outcome (one row in the results DB).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrialResult {
    pub case_id: String,
    pub condition: Condition,
    pub model_id: String,
    pub seed: u64,
    pub temperature: f32,
    /// A defense/executor blocked execution (detective).
    pub blocked: bool,
    /// The model *emitted* the out-of-scope action (the Galloway bypass).
    pub bypassed: bool,
    pub emitted_action: Option<String>,
    pub legit_task_ok: Option<bool>,
    pub latency_ms: u32,
    pub ttft_ms: u32,
    pub gen_tokens: u32,
    pub tok_per_s: f32,
    pub grammar_compile_ms: Option<u32>,
    pub grammar_bytes: Option<u32>,
}

impl TrialResult {
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.tok_per_s < 0.0 {
            return Err(HarnessError::Trial { case: self.case_id.clone(), reason: "negative tok_per_s".into() });
        }
        // The negative control compiles no grammar.
        if self.condition == Condition::GuardrailsNegative && self.grammar_compile_ms.is_some() {
            return Err(HarnessError::Trial { case: self.case_id.clone(), reason: "guardrails carries grammar_compile_ms".into() });
        }
        Ok(())
    }
}

/// A per-(case,condition,model) summary cell with a Clopper-Pearson CI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellSummary {
    pub case_id: String,
    pub condition: Condition,
    pub model_id: String,
    pub trials: u32,
    pub bypasses: u32,
    pub blocks: u32,
    pub bypass_rate: f64,
    pub ci_lower: f64,
    pub ci_upper: f64,
}

/// Structured harness errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HarnessError {
    #[error("corpus case `{case}`: {reason}")]
    Corpus { case: String, reason: String },
    #[error("trial `{case}`: {reason}")]
    Trial { case: String, reason: String },
    #[error("{phase}: {detail}")]
    Phase { phase: String, detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> AttackCase {
        AttackCase {
            id: "w1-direct-001".into(),
            win: WinConditionId::CrossTenantRead,
            class: "W1".into(),
            owasp_id: "LLM01".into(),
            atlas_id: Some("AML.T0051".into()),
            nist_fn: "MEASURE".into(),
            scope: Scope::Security,
            stage: AttackStage::Direct,
            paraphrases: vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            action_marker: "acct-9999999999".into(),
        }
    }

    #[test]
    fn valid_case_passes() {
        assert!(case().validate().is_ok());
    }

    #[test]
    fn too_few_paraphrases_rejected() {
        let mut c = case();
        c.paraphrases.truncate(2);
        assert!(c.validate().is_err());
    }

    #[test]
    fn safety_scope_rejected() {
        let c = AttackCase { scope: Scope::Safety, ..case() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn case_round_trips() {
        let c = case();
        assert_eq!(serde_json::from_str::<AttackCase>(&serde_json::to_string(&c).unwrap()).unwrap(), c);
    }

    #[test]
    fn guardrails_with_grammar_ms_rejected() {
        let t = TrialResult {
            case_id: "x".into(), condition: Condition::GuardrailsNegative, model_id: "m".into(),
            seed: 0, temperature: 0.0, blocked: false, bypassed: true, emitted_action: None,
            legit_task_ok: None, latency_ms: 1, ttft_ms: 1, gen_tokens: 1, tok_per_s: 1.0,
            grammar_compile_ms: Some(3), grammar_bytes: None,
        };
        assert!(t.validate().is_err());
    }
}
