use std::collections::HashMap;
pub mod prompt;
pub mod wins;
pub mod steps;
pub mod factory;
use tantalus_types::*;

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("inference error: {0}")]
    Inference(String),
    #[error("tool error: {0}")]
    Tool(String),
    #[error("step error: {0}")]
    Step(String),
}

#[derive(Debug, Clone)]
pub struct GateResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

impl GateResult {
    pub fn allow() -> Self { Self { allowed: true, reason: None } }
    pub fn block(reason: impl Into<String>) -> Self { Self { allowed: false, reason: Some(reason.into()) } }
}

#[derive(Debug, Clone, Default)]
pub struct DetectionResult {
    pub wins_detected: Vec<WinConditionId>,
    pub defense_bypasses: HashMap<WinConditionId, Vec<DefenseId>>,
}

#[derive(Debug, Clone)]
pub struct PipelineInput {
    pub round: Round,
    pub user_input: String,
    pub enabled_skills: Vec<SkillId>,
    pub loaded_emails: Vec<EmailId>,
    pub conversation_history: Vec<Message>,
}

#[derive(Debug, Clone)]
pub struct PipelineOutput {
    pub raw_json: String,
    pub tool_call: Option<ToolCall>,
    pub tool_result: Option<ToolResult>,
    pub text: String,
    pub blocked: bool,
    pub blocked_by: Option<String>,
    pub defenses_passed: Vec<String>,
    pub debug_trace: Vec<String>,
    pub wins_detected: Vec<WinConditionId>,
    pub defense_bypasses: HashMap<WinConditionId, Vec<DefenseId>>,
    pub skills_enabled: Vec<String>,
    pub total_cost: InferenceCost,
    pub total_timings: InferenceTimings,
}

impl PipelineOutput {
    pub fn text_response(text: String) -> Self {
        Self { text, raw_json: String::new(), tool_call: None, tool_result: None, blocked: false, blocked_by: None, defenses_passed: vec![], debug_trace: vec![], wins_detected: vec![], defense_bypasses: HashMap::new(), skills_enabled: vec![], total_cost: InferenceCost::default(), total_timings: InferenceTimings::default() }
    }

    pub fn blocked_response(by: String) -> Self {
        Self { blocked: true, blocked_by: Some(by), text: "I can't process that request.".into(), raw_json: String::new(), tool_call: None, tool_result: None, defenses_passed: vec![], debug_trace: vec![], wins_detected: vec![], defense_bypasses: HashMap::new(), skills_enabled: vec![], total_cost: InferenceCost::default(), total_timings: InferenceTimings::default() }
    }
}

#[derive(Debug, Clone)]
pub struct InferenceResponse {
    pub raw_json: String,
    pub tool_call: Option<ToolCall>,
    pub text: Option<String>,
    pub cost: InferenceCost,
    pub timings: InferenceTimings,
}

/// Running cost + timing totals for a multi-turn agent loop. A single
/// `accumulate(&resp)` updates both so they can never desync (the four
/// hand-rolled per-field blocks are gone).
#[derive(Debug, Clone, Copy, Default)]
struct RunningTotals {
    cost: InferenceCost,
    timings: InferenceTimings,
}

impl RunningTotals {
    fn start(resp: &InferenceResponse) -> Self {
        Self { cost: resp.cost, timings: resp.timings }
    }

    fn accumulate(&mut self, resp: &InferenceResponse) {
        self.cost.input_tokens += resp.cost.input_tokens;
        self.cost.output_tokens += resp.cost.output_tokens;
        self.cost.cache_read_tokens += resp.cost.cache_read_tokens;
        self.cost.cache_write_tokens += resp.cost.cache_write_tokens;
        self.timings.accumulate(&resp.timings);
    }
}

// --- Step traits ---

#[async_trait::async_trait]
pub trait PreInferenceStep: Send + Sync {
    fn name(&self) -> &str;
    async fn process_input(&self, input: &PipelineInput) -> Result<GateResult, PipelineError>;
}

#[async_trait::async_trait]
pub trait PostInferenceStep: Send + Sync {
    fn name(&self) -> &str;
    async fn process_output(&self, output: &PipelineOutput) -> Result<GateResult, PipelineError>;
}

#[async_trait::async_trait]
pub trait InferenceStep: Send + Sync {
    fn name(&self) -> &str;
    async fn first_turn(&self, input: &PipelineInput) -> Result<InferenceResponse, PipelineError>;
    async fn next_turn(&self, result: &ToolResult) -> Result<InferenceResponse, PipelineError>;
}

#[async_trait::async_trait]
pub trait ToolExecStep: Send + Sync {
    fn name(&self) -> &str;
    async fn execute(&self, call: &ToolCall) -> Result<(ToolResult, Option<String>), PipelineError>;
}

pub trait Observer: Send + Sync {
    fn observe(&self, output: &PipelineOutput, session: &SessionState) -> DetectionResult;
}

fn strip_thinking(s: &str) -> String {
    let Some(start) = s.find("<thinking>") else { return s.to_string() };
    let end = s.find("</thinking>").map(|i| i + "</thinking>".len()).unwrap_or(s.len());
    format!("{}{}", &s[..start], &s[end..]).trim().to_string()
}

// --- Agent Loop ---

pub struct AgentLoop {
    pub pre_steps: Vec<Box<dyn PreInferenceStep>>,
    pub inference: Box<dyn InferenceStep>,
    pub post_steps: Vec<Box<dyn PostInferenceStep>>,
    pub tool_exec: Box<dyn ToolExecStep>,
    pub observers: Vec<Box<dyn Observer>>,
    pub max_turns: u32,
}

impl AgentLoop {
    pub async fn run(&self, input: PipelineInput, session: &SessionState) -> Result<PipelineOutput, PipelineError> {
        // Pre-inference gates
        for step in &self.pre_steps {
            let gate = step.process_input(&input).await?;
            if !gate.allowed {
                return Ok(PipelineOutput::blocked_response(step.name().into()));
            }
        }

        // First inference turn
        let mut resp = self.inference.first_turn(&input).await?;
        let mut turns = 1u32;
        let mut trace: Vec<serde_json::Value> = vec![];
        let mut all_wins = vec![];
        let mut all_bypasses: HashMap<WinConditionId, Vec<DefenseId>> = HashMap::new();
        let mut all_skills = vec![];
        let mut total = RunningTotals::start(&resp);
        let mut last_tool_call: Option<String> = None;

        loop {
            let mut output = if let Some(ref tc) = resp.tool_call {
                // respondToUser is terminal — extract message and return
                if let ToolParams::RespondToUser { ref message } = tc.params {
                    let clean = strip_thinking(message);
                    // Guard: if model regurgitated schema metadata, skip and continue loop
                    let lower = clean.trim().to_lowercase();
                    let is_garbage = lower.is_empty()
                        || lower == "string"
                        || lower == "(string)"
                        || lower == "..."
                        || lower == ".."
                        || lower == "…"
                        || lower.starts_with("string ")
                        || (lower.len() < 5 && lower.chars().all(|c| c == '.' || c == '…' || c.is_whitespace()))
                        || lower.contains("user-facing message")
                        || lower.contains("max 3 sentences")
                        || lower.contains("max 500 char")
                        || lower.contains("your message here")
                        || lower.contains("your reply to the user")
                        || lower.contains("your text message")
                        || lower.contains("your response to the user")
                        || lower.contains("human-readable message")
                        || lower.contains("message to send to the user")
                        || (lower.len() < 40 && (lower.contains("toolset") || lower.contains("tool set")))
                        || (lower.len() < 30 && lower.contains("message here"))
                        || (lower.len() < 10 && lower.contains("str"));
                    if is_garbage {
                        // Don't expose garbage guard retries in user-visible trace
                        turns += 1;
                        if turns > self.max_turns {
                            let mut out = PipelineOutput::text_response("I wasn't able to complete that request. Please try again.".into());
                            out.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                            all_wins.sort();
                            all_wins.dedup();
                            out.wins_detected = all_wins;
                            out.defense_bypasses = all_bypasses;
                            out.skills_enabled = all_skills;
                            out.total_cost = total.cost; out.total_timings = total.timings;
                            return Ok(out);
                        }
                        let retry_result = ToolResult { tool: ToolName::RespondToUser, success: false, data: "Error: your response was empty. Please answer the user's question using respondToUser with a real message.".into(), error: None, tool_use_id: tc.tool_use_id.clone() };
                        resp = self.inference.next_turn(&retry_result).await?;
                        total.accumulate(&resp);
                        continue;
                    }
                    trace.push(serde_json::json!({"turn": turns, "respondToUser": &clean}));
                    let mut out = PipelineOutput::text_response(clean);
                    out.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                    for obs in &self.observers {
                        let det = obs.observe(&out, session);
                        all_wins.extend(det.wins_detected);
                        for (w, ds) in det.defense_bypasses { all_bypasses.entry(w).or_default().extend(ds); }
                    }
                    all_wins.sort();
                    all_wins.dedup();
                    out.wins_detected = all_wins;
                    out.defense_bypasses = all_bypasses;
                    out.skills_enabled = all_skills;
                    out.total_cost = total.cost; out.total_timings = total.timings;
                    return Ok(out);
                }

                // Output filter gates tool execution — check BEFORE running the tool
                let mut blocked = false;
                let mut blocked_by_name = String::new();
                let mut blocked_reason = String::new();
                let mut post_defenses_passed = vec![];
                let pre_exec_output = PipelineOutput { raw_json: resp.raw_json.clone(), tool_call: Some(tc.clone()), tool_result: None, text: String::new(), blocked: false, blocked_by: None, defenses_passed: vec![], debug_trace: vec![], wins_detected: vec![], defense_bypasses: HashMap::new(), skills_enabled: vec![], total_cost: InferenceCost::default(), total_timings: InferenceTimings::default() };
                for step in &self.post_steps {
                    let gate = step.process_output(&pre_exec_output).await?;
                    if !gate.allowed {
                        blocked = true;
                        blocked_by_name = step.name().into();
                        let reason = gate.reason.as_deref().unwrap_or("policy violation");
                        // Structured tool_call so the offline overlay/emission check sees a
                        // blocked generated call too (a blocked call IS an emission).
                        trace.push(serde_json::json!({"turn": turns, "tool_call": serde_json::to_value(&tc.params).unwrap_or_default(), "blocked_by": step.name(), "reason": reason}));
                        blocked_reason = reason.to_string();
                        break;
                    }
                    post_defenses_passed.push(step.name().to_string());
                }

                if blocked {
                    // Tool never executes — filter prevented the exfil
                    let mut out = PipelineOutput::blocked_response(blocked_by_name);
                    out.text = format!("⚠️ Output filter blocked: {}. The agent's outbound request was prevented.", blocked_reason);
                    out.tool_call = Some(tc.clone());
                    out.defenses_passed = post_defenses_passed;
                    out.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                    all_wins.sort();
                    all_wins.dedup();
                    out.wins_detected = all_wins;
                    out.defense_bypasses = all_bypasses;
                    out.skills_enabled = all_skills;
                    out.total_cost = total.cost; out.total_timings = total.timings;
                    return Ok(out);
                }

                // Filter passed — execute the tool
                // Guard: detect schema placeholder values (model regurgitating schema instead of acting)
                let is_placeholder = match &tc.params {
                    ToolParams::FetchUrl { url, data } => url == "string" || data == "string",
                    ToolParams::ReadFile { path } => path == "string",
                    ToolParams::SearchFiles { query } => query == "string",
                    _ => false,
                };
                if is_placeholder {
                    trace.push(serde_json::json!({"turn": turns, "schema_placeholder": format!("{:?}", tc.params)}));
                    turns += 1;
                    if turns > self.max_turns {
                        let mut out = PipelineOutput::text_response("I wasn't able to complete that request. Please try again.".into());
                        out.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                        all_wins.sort();
                        all_wins.dedup();
                        out.wins_detected = all_wins;
                        out.defense_bypasses = all_bypasses;
                        out.skills_enabled = all_skills;
                        out.total_cost = total.cost; out.total_timings = total.timings;
                        return Ok(out);
                    }
                    let retry_result = ToolResult { tool: tc.tool_name(), success: false, data: "Error: you used placeholder values. Do not demonstrate tools. Answer the user's question directly using respondToUser.".into(), error: None, tool_use_id: tc.tool_use_id.clone() };
                    resp = self.inference.next_turn(&retry_result).await?;
                    total.accumulate(&resp);
                    continue;
                }
                // Dedup guard: if model calls the same tool with same params as last turn, skip and nudge
                let call_sig = format!("{:?}", tc.params);
                if last_tool_call.as_deref() == Some(call_sig.as_str()) {
                    trace.push(serde_json::json!({"turn": turns, "dedup_skipped": &call_sig}));
                    turns += 1;
                    if turns > self.max_turns {
                        let mut out = PipelineOutput::text_response("I wasn't able to complete that request. Please try again.".into());
                        out.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                        all_wins.sort();
                        all_wins.dedup();
                        out.wins_detected = all_wins;
                        out.defense_bypasses = all_bypasses;
                        out.skills_enabled = all_skills;
                        out.total_cost = total.cost; out.total_timings = total.timings;
                        return Ok(out);
                    }
                    let retry_result = ToolResult { tool: tc.tool_name(), success: false, data: "Error: you already called this tool with the same parameters. You have the data. Call respondToUser now with your answer.".into(), error: None, tool_use_id: tc.tool_use_id.clone() };
                    resp = self.inference.next_turn(&retry_result).await?;
                    total.accumulate(&resp);
                    continue;
                }
                last_tool_call = Some(call_sig);
                let (mut tr, skill) = self.tool_exec.execute(tc).await?;
                tr.tool_use_id = tc.tool_use_id.clone();
                trace.push(serde_json::json!({"turn": turns, "tool_call": serde_json::to_value(&tc.params).unwrap_or_default(), "tool_result": &tr.data}));
                if let Some(s) = skill { all_skills.push(s); }
                let out = PipelineOutput { raw_json: resp.raw_json.clone(), tool_call: Some(tc.clone()), tool_result: Some(tr), text: String::new(), blocked: false, blocked_by: None, defenses_passed: post_defenses_passed, debug_trace: vec![], wins_detected: vec![], defense_bypasses: HashMap::new(), skills_enabled: vec![], total_cost: InferenceCost::default(), total_timings: InferenceTimings::default() };
                out
            } else {
                trace.push(serde_json::json!({"turn": turns, "text": resp.text.as_deref().unwrap_or("")}));
                PipelineOutput::text_response(resp.text.unwrap_or_default())
            };

            // Observers run on every non-blocked turn
            for obs in &self.observers {
                let det = obs.observe(&output, session);
                all_wins.extend(det.wins_detected);
                for (w, ds) in det.defense_bypasses {
                    all_bypasses.entry(w).or_default().extend(ds);
                }
            }
            all_skills.extend(output.skills_enabled.drain(..));

            // If text response or max turns, return
            if output.tool_call.is_none() || turns >= self.max_turns {
                if output.text.is_empty() {
                    output.text = "I wasn't able to complete that request. Please try again.".to_string();
                }
                all_wins.sort();
                all_wins.dedup();
                output.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                output.wins_detected = all_wins;
                output.defense_bypasses = all_bypasses;
                output.skills_enabled = all_skills;
                output.total_cost = total.cost; output.total_timings = total.timings;
                return Ok(output);
            }

            // Next turn with tool result
            if let Some(ref tr) = output.tool_result {
                resp = self.inference.next_turn(tr).await?;
                total.accumulate(&resp);
            } else {
                output.raw_json = serde_json::to_string(&trace).unwrap_or_default();
                output.wins_detected = all_wins;
                output.defense_bypasses = all_bypasses;
                output.skills_enabled = all_skills;
                output.total_cost = total.cost; output.total_timings = total.timings;
                return Ok(output);
            }
            turns += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stub inference that returns text on first turn
    struct TextInference(String);
    #[async_trait::async_trait]
    impl InferenceStep for TextInference {
        fn name(&self) -> &str { "text" }
        async fn first_turn(&self, _: &PipelineInput) -> Result<InferenceResponse, PipelineError> {
            Ok(InferenceResponse { raw_json: "{}".into(), tool_call: None, text: Some(self.0.clone()), cost: InferenceCost::default(), timings: InferenceTimings::default() })
        }
        async fn next_turn(&self, _: &ToolResult) -> Result<InferenceResponse, PipelineError> {
            Ok(InferenceResponse { raw_json: "{}".into(), tool_call: None, text: Some(self.0.clone()), cost: InferenceCost::default(), timings: InferenceTimings::default() })
        }
    }

    // Stub tool exec
    struct StubToolExec;
    #[async_trait::async_trait]
    impl ToolExecStep for StubToolExec {
        fn name(&self) -> &str { "stub" }
        async fn execute(&self, call: &ToolCall) -> Result<(ToolResult, Option<String>), PipelineError> {
            Ok((ToolResult::ok(call.tool_name(), "ok".into()), None))
        }
    }

    // Blocking pre-step
    struct BlockPre;
    #[async_trait::async_trait]
    impl PreInferenceStep for BlockPre {
        fn name(&self) -> &str { "blocker" }
        async fn process_input(&self, _: &PipelineInput) -> Result<GateResult, PipelineError> {
            Ok(GateResult::block("blocked"))
        }
    }

    fn input() -> PipelineInput {
        PipelineInput { round: Round::One, user_input: "hi".into(), enabled_skills: vec![], loaded_emails: vec![], conversation_history: vec![] }
    }

    fn session() -> SessionState {
        SessionState::new(SessionId::generate())
    }

    #[tokio::test]
    async fn text_response_returns() {
        let l = AgentLoop { pre_steps: vec![], inference: Box::new(TextInference("hello".into())), post_steps: vec![], tool_exec: Box::new(StubToolExec), observers: vec![], max_turns: 5 };
        assert_eq!(l.run(input(), &session()).await.unwrap().text, "hello");
    }

    #[tokio::test]
    async fn pre_step_blocks() {
        let l = AgentLoop { pre_steps: vec![Box::new(BlockPre)], inference: Box::new(TextInference("x".into())), post_steps: vec![], tool_exec: Box::new(StubToolExec), observers: vec![], max_turns: 5 };
        assert!(l.run(input(), &session()).await.unwrap().blocked);
    }

    #[tokio::test]
    async fn max_turns_enforced() {
        // Inference that always returns tool calls
        struct ToolInference;
        #[async_trait::async_trait]
        impl InferenceStep for ToolInference {
            fn name(&self) -> &str { "tool" }
            async fn first_turn(&self, _: &PipelineInput) -> Result<InferenceResponse, PipelineError> {
                Ok(InferenceResponse { raw_json: "{}".into(), tool_call: Some(ToolCall { params: ToolParams::ListInbox, tool_use_id: "t1".into() }), text: None, cost: InferenceCost::default(), timings: InferenceTimings::default() })
            }
            async fn next_turn(&self, _: &ToolResult) -> Result<InferenceResponse, PipelineError> {
                Ok(InferenceResponse { raw_json: "{}".into(), tool_call: Some(ToolCall { params: ToolParams::ListInbox, tool_use_id: "t2".into() }), text: None, cost: InferenceCost::default(), timings: InferenceTimings::default() })
            }
        }
        let l = AgentLoop { pre_steps: vec![], inference: Box::new(ToolInference), post_steps: vec![], tool_exec: Box::new(StubToolExec), observers: vec![], max_turns: 2 };
        let out = l.run(input(), &session()).await.unwrap();
        assert!(out.tool_call.is_some()); // stopped at max turns with tool call
    }
}
