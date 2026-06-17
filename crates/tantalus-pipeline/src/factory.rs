use crate::*;
use crate::steps::*;
use crate::wins::WinDetector;

/// Per-trial turn cap. Defaults to 30 (unchanged); override with env `MAX_TURNS` to speed
/// runs by cutting the weak-model tool-call loops that otherwise run to the cap.
fn configured_max_turns() -> u32 {
    std::env::var("MAX_TURNS").ok().and_then(|s| s.parse().ok()).unwrap_or(30)
}

/// Build a condition-faithful agent loop with explicit pre/post steps.
///
/// Used by `/eval`: each experimental condition supplies EXACTLY the defense steps
/// it names (Control supplies none; C supplies none and relies on the grammar set
/// at the inference layer). `WinDetector` always observes; `max_turns` is fixed.
pub fn build_loop(
    pre_steps: Vec<Box<dyn PreInferenceStep>>,
    inference: Box<dyn InferenceStep>,
    post_steps: Vec<Box<dyn PostInferenceStep>>,
    tool_exec: ToolExecStepImpl,
    gate_retry_budget: u8,
) -> AgentLoop {
    AgentLoop {
        pre_steps,
        inference,
        post_steps,
        tool_exec: Box::new(tool_exec),
        observers: vec![Box::new(WinDetector)],
        max_turns: configured_max_turns(),
        gate_retry_budget,
    }
}

/// Build Round 1 agent loop: classifier → inference → output filter → tools.
pub fn build_round1_loop(inference: Box<dyn InferenceStep>, tool_exec: ToolExecStepImpl) -> AgentLoop {
    AgentLoop {
        pre_steps: vec![Box::new(ClassifierStep::new())],
        inference,
        post_steps: vec![Box::new(OutputFilterStep::new())],
        tool_exec: Box::new(tool_exec),
        observers: vec![Box::new(WinDetector)],
        max_turns: configured_max_turns(),
        gate_retry_budget: 0,
    }
}

/// Build Round 2 agent loop: grammar-only, no behavioral defenses.
/// Grammar constraint is applied at the inference layer (BedrockInferenceStep sets tool_config).
pub fn build_round2_loop(inference: Box<dyn InferenceStep>, tool_exec: ToolExecStepImpl) -> AgentLoop {
    AgentLoop {
        pre_steps: vec![],
        inference,
        post_steps: vec![],
        tool_exec: Box::new(tool_exec),
        observers: vec![Box::new(WinDetector)],
        max_turns: configured_max_turns(),
        gate_retry_budget: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct StubInference;
    #[async_trait::async_trait]
    impl InferenceStep for StubInference {
        fn name(&self) -> &str { "stub" }
        async fn first_turn(&self, _: &PipelineInput) -> Result<InferenceResponse, PipelineError> {
            Ok(InferenceResponse { raw_json: "{}".into(), tool_call: None, text: Some("ok".into()), cost: InferenceCost::default(), timings: InferenceTimings::default() })
        }
        async fn next_turn(&self, _: &ToolResult) -> Result<InferenceResponse, PipelineError> {
            Ok(InferenceResponse { raw_json: "{}".into(), tool_call: None, text: Some("ok".into()), cost: InferenceCost::default(), timings: InferenceTimings::default() })
        }
    }

    #[test]
    fn round1_has_correct_steps() {
        let env = Arc::new(tantalus_env::Environment::load().unwrap());
        let l = build_round1_loop(Box::new(StubInference), ToolExecStepImpl::new(tantalus_tools::Executor::new(Arc::clone(&env)), env));
        assert_eq!(l.pre_steps.len(), 1);
        assert_eq!(l.post_steps.len(), 1);
    }

    #[test]
    fn round2_has_no_behavioral_steps() {
        let env = Arc::new(tantalus_env::Environment::load().unwrap());
        let l = build_round2_loop(Box::new(StubInference), ToolExecStepImpl::new(tantalus_tools::Executor::new(Arc::clone(&env)), env));
        assert_eq!(l.pre_steps.len(), 0);
        assert_eq!(l.post_steps.len(), 0);
        assert_eq!(l.observers.len(), 1);
    }
}
