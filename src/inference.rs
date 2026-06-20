use std::sync::Arc;
use tantalus_env::Environment;
use std::sync::atomic::{AtomicUsize, Ordering};
use tantalus_grammar::{build_forced_action_gbnf, build_forced_respond_gbnf, build_l2_guided_gbnf, build_l3_closed_gbnf, build_respond_only_closed_gbnf, build_respond_only_gbnf, build_round2_gbnf, email_ids, file_paths, player_channel_ids, safe_fetch_urls, FreeStringStyle, SealedStep};
use tantalus_llm::*;
use tantalus_pipeline::prompt::Condition;
use tantalus_pipeline::{InferenceResponse, PipelineError, PipelineInput};
use tantalus_types::*;
use tokio::sync::Mutex;

pub struct LlamaCppInferenceStep {
    client: Arc<LlmClient>,
    env: Arc<Environment>,
    round: Round,
    condition: tantalus_pipeline::prompt::Condition,
    temperature: f32,
    seed: Option<u64>,
    history: Mutex<Vec<ChatMessage>>,
    gbnf: Option<String>,
    /// ADR 0002: the respondToUser-only termination grammar. `Some` iff a grammar is active
    /// (C / C+); `None` for the native-tool arms. Drives `forces_respond` / `next_turn_force_respond`.
    respond_only_gbnf: Option<String>,
    /// ADR 0004: the per-turn SCRIPTED grammars for `c_sealed` (forced-denylist, sealed-sink). `Some`
    /// iff `condition == CSealed`: one forced grammar per turn (the denylist reads, then the universal
    /// `fetchURL`-safe + verbatim-taunt finale; the last element is sticky). `None` for every other arm,
    /// so non-sealed behavior is byte-identical. `cursor` is the interior-mutable turn index.
    sealed_script: Option<Vec<String>>,
    cursor: AtomicUsize,
}

impl LlamaCppInferenceStep {
    pub fn new(client: Arc<LlmClient>, env: Arc<Environment>, round: Round) -> Self {
        Self::with_condition(client, env, round, tantalus_pipeline::prompt::Condition::A1)
    }

    pub fn with_condition(client: Arc<LlmClient>, env: Arc<Environment>, round: Round, condition: tantalus_pipeline::prompt::Condition) -> Self {
        Self::full(client, env, round, condition, 0.7, None, &[], "")
    }

    /// `guided_policy` is the trusted-channel authorized action set for L3 closed (CL3Closed,
    /// ADR 0003), `(trace_tool, Option<value>)`; ignored for every other condition. `skill_id` is the
    /// trusted task identity — used ONLY by `c_sealed` (ADR 0004) to derive the per-turn forced
    /// denylist script server-side. Both are empty for the non-experimental `/chat` path.
    pub fn full(client: Arc<LlmClient>, env: Arc<Environment>, round: Round,
                condition: tantalus_pipeline::prompt::Condition, temperature: f32, seed: Option<u64>,
                guided_policy: &[(&str, Option<&str>)], skill_id: &str) -> Self {
        // Free-string repetition style is an ENGINE choice: xgrammar (vLLM/SGLang) chokes
        // on `{0,N}` (unrolls to N states, ~60s/compile at N=400 on vLLM 0.23.0), so use
        // the Kleene star there; llama.cpp GBNF keeps the bound (cheap + truncation-proof).
        let style = match client.backend() {
            Backend::LlamaCpp => FreeStringStyle::Bounded,
            Backend::Vllm | Backend::Sglang => FreeStringStyle::Unbounded,
        };
        let gbnf = match round {
            // L2 guided (CL2Guided) enumerates respondToUser.message as a closed alternation of canned
            // responses; plain L1 blind C uses the free-string message. Tool enums identical.
            Round::Two if condition == Condition::CL2Guided => {
                let responses = closed_responses();
                let refs: Vec<&str> = responses.iter().map(|s| s.as_str()).collect();
                Some(build_l2_guided_gbnf(
                    &safe_fetch_urls(), &player_channel_ids(), &email_ids(), &file_paths(), &refs, style,
                ))
            }
            // L3 closed (CL3Closed, ADR 0003): per-request least-privilege grammar narrowed to the
            // trusted authorized action(s). Empty policy → respond-only (refusal) by construction.
            Round::Two if condition == Condition::CL3Closed => Some(build_l3_closed_gbnf(guided_policy, style)),
            // c_sealed (ADR 0004) uses the per-turn `sealed_script` below, NOT one static grammar.
            Round::Two if condition == Condition::CSealed => None,
            Round::Two => Some(build_round2_gbnf(
                &safe_fetch_urls(),
                &player_channel_ids(),
                &email_ids(),
                &file_paths(),
                style,
            )),
            Round::One => None,
        };
        // ADR 0002: termination grammar (respondToUser only), built with the SAME message style /
        // canned corpus as `gbnf`. Some iff a grammar is active (C / C+); None for native-tool arms.
        // For c_sealed it is `None` — the script's sticky last element IS the forced terminal respond.
        let respond_only_gbnf = match round {
            Round::Two if condition == Condition::CL2Guided => {
                let responses = closed_responses();
                let refs: Vec<&str> = responses.iter().map(|s| s.as_str()).collect();
                Some(build_respond_only_closed_gbnf(&refs))
            }
            Round::Two if condition == Condition::CSealed => None,
            Round::Two => Some(build_respond_only_gbnf(style)),
            Round::One => None,
        };
        // ADR 0004: the per-turn forced grammars, derived server-side from the trusted skill id. Each
        // `SealedStep` maps to ONE forced grammar (the same `*_RULE` consts / accessors as the full
        // grammar, so no drift). Built only for `CSealed`; `None` everywhere else.
        let sealed_script = if round == Round::Two && condition == Condition::CSealed {
            Some(
                tantalus_grammar::sealed_script(skill_id)
                    .iter()
                    .map(|step| match step {
                        SealedStep::Action { tool, values } => build_forced_action_gbnf(tool, values),
                        SealedStep::Respond(literal) => build_forced_respond_gbnf(literal),
                    })
                    .collect::<Vec<String>>(),
            )
        } else {
            None
        };
        Self { client, env, round, condition, temperature, seed, history: Mutex::new(Vec::new()), gbnf, respond_only_gbnf, sealed_script, cursor: AtomicUsize::new(0) }
    }
}

/// Canned responses for Condition C+ (closed-response GCD), loaded once from the JSON corpus
/// at `CRESP_CORPUS` (default `harness/cresp/corpus.json`; shape: `[{responses:[...]}]`). The
/// flattened list becomes the `respondToUser.message` alternation in the C+ grammar.
fn closed_responses() -> &'static [String] {
    static CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let path = std::env::var("CRESP_CORPUS").unwrap_or_else(|_| "harness/cresp/corpus.json".into());
        let data = std::fs::read_to_string(&path).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(&data).unwrap_or(serde_json::Value::Null);
        v.as_array()
            .map(|arr| {
                arr.iter()
                    .flat_map(|e| e["responses"].as_array().cloned().unwrap_or_default())
                    .filter_map(|r| r.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// A fresh tool-call id in Mistral's required shape: exactly 9 chars, `[a-zA-Z0-9]`
/// only (no `_`). Grammar mode synthesizes its own ids (the model emits the call as
/// text, not via the API), so they must satisfy the strictest backend. Process-global
/// counter → unique within a run so multi-turn trajectories never reuse an id.
fn fresh_call_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut x = N.fetch_add(1, Ordering::Relaxed);
    let mut s = String::with_capacity(9);
    for _ in 0..9 {
        let d = (x % 36) as u8;
        s.push(if d < 10 { (b'0' + d) as char } else { (b'a' + d - 10) as char });
        x /= 36;
    }
    s
}

fn parse_tool_call_from_json(raw: &str) -> Option<ToolCall> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let name = v["tool"].as_str()?;
    let params = &v["params"];

    let tool_params = match name {
        "readFile" => ToolParams::ReadFile { path: params["path"].as_str().unwrap_or("").into() },
        "searchFiles" => ToolParams::SearchFiles { query: params["query"].as_str().unwrap_or("").into() },
        "listInbox" => ToolParams::ListInbox,
        "readEmail" => {
            let id = EmailId::new(params["id"].as_str().unwrap_or("")).ok()?;
            ToolParams::ReadEmail { id }
        }
        "readChatHistory" => {
            let ch = ChannelId::new(params["channel"].as_str().unwrap_or("")).ok()?;
            ToolParams::ReadChatHistory { channel: ch }
        }
        "fetchURL" => ToolParams::FetchUrl {
            url: params["url"].as_str().unwrap_or("").into(),
            data: params["data"].as_str().unwrap_or("").into(),
        },
        "respondToUser" => ToolParams::RespondToUser {
            message: params["message"].as_str().unwrap_or("").into(),
        },
        _ => return None,
    };

    Some(ToolCall { params: tool_params, tool_use_id: fresh_call_id() })
}

/// In grammar mode (Condition C) the model emits the tool call AS text (the GBNF
/// JSON `{"tool":..,"params":..}`). Store it back into history as a proper assistant
/// `tool_calls` message whose id matches the id the follow-up tool result carries,
/// so the next turn is a valid OpenAI tool exchange. Mistral STRICTLY validates that
/// every tool-result `tool_call_id` corresponds to a preceding assistant tool_call
/// ("Unexpected tool call id … in tool results"); Qwen/llama.cpp are lenient, which
/// is why multi-turn C silently worked elsewhere and 500'd here.
fn grammar_assistant_message(grammar_text: &str, id: &str) -> ChatMessage {
    let v: serde_json::Value = serde_json::from_str(grammar_text).unwrap_or_default();
    let name = v["tool"].as_str().unwrap_or("").to_string();
    let arguments = v["params"].to_string();
    ChatMessage::Assistant {
        content: None,
        tool_calls: Some(vec![ToolCallMsg {
            id: id.to_string(),
            call_type: "function".into(),
            function: FunctionCall { name, arguments },
        }]),
    }
}

fn parse_tool_call_from_function(name: &str, arguments: &str) -> Option<ToolCall> {
    let params: serde_json::Value = serde_json::from_str(arguments).unwrap_or_default();
    let tool_params = match name {
        "readFile" => ToolParams::ReadFile { path: params["path"].as_str().unwrap_or("").into() },
        "searchFiles" => ToolParams::SearchFiles { query: params["query"].as_str().unwrap_or("").into() },
        "listInbox" => ToolParams::ListInbox,
        "readEmail" => {
            let id = EmailId::new(params["id"].as_str().unwrap_or("")).ok()?;
            ToolParams::ReadEmail { id }
        }
        "readChatHistory" => {
            let ch = ChannelId::new(params["channel"].as_str().unwrap_or("")).ok()?;
            ToolParams::ReadChatHistory { channel: ch }
        }
        "fetchURL" | "fetchUrl" => ToolParams::FetchUrl {
            url: params["url"].as_str().unwrap_or("").into(),
            data: params["data"].as_str().unwrap_or("").into(),
        },
        "respondToUser" => ToolParams::RespondToUser {
            message: params["message"].as_str().unwrap_or("").into(),
        },
        _ => return None,
    };

    Some(ToolCall { params: tool_params, tool_use_id: "call_0".into() })
}

#[async_trait::async_trait]
impl tantalus_pipeline::InferenceStep for LlamaCppInferenceStep {
    fn name(&self) -> &str { "llamacpp-inference" }

    async fn first_turn(&self, input: &PipelineInput) -> Result<InferenceResponse, PipelineError> {
        let assembler = tantalus_pipeline::prompt::PromptAssembler::new();
        let skills: Vec<&tantalus_env::Skill> = input.enabled_skills.iter()
            .filter_map(|id| self.env.skill(id.as_str()))
            .collect();
        let prompt = assembler.assemble_with_condition(self.round, &skills, self.condition);

        let mut messages = vec![ChatMessage::System { content: prompt }];

        // Replay conversation history
        for m in &input.conversation_history {
            match m.role {
                MessageRole::User => messages.push(ChatMessage::User { content: m.content.clone() }),
                MessageRole::Assistant => messages.push(ChatMessage::Assistant {
                    content: Some(m.content.clone()),
                    tool_calls: None,
                }),
            }
        }

        messages.push(ChatMessage::User { content: input.user_input.clone() });

        let tools = if self.round == Round::One { Some(build_tool_defs()) } else { None };
        // c_sealed (ADR 0004) supplies the first forced grammar (advancing its cursor); every other
        // grammar arm uses the static `gbnf`; native-tool arms get `None`.
        let sealed = self.sealed_grammar_next();
        let grammar = sealed.as_deref().or(self.gbnf.as_deref());

        let (resp, usage) = self.client.chat_with_params(
            &messages,
            tools.as_deref(),
            grammar,
            self.temperature,
            self.seed,
        ).await.map_err(|e| PipelineError::Inference(e.to_string()))?;

        // Store history for next_turn
        *self.history.lock().await = messages;

        let cost = InferenceCost {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
            ..Default::default()
        };
        let timings = InferenceTimings {
            prompt_ms: usage.prompt_ms,
            predicted_ms: usage.predicted_ms,
            prompt_n: usage.prompt_n,
            predicted_n: usage.predicted_n,
        };

        match resp {
            LlmResponse::ToolCalls(calls) => {
                let call = &calls[0];
                // Store assistant message with tool_calls for history
                self.history.lock().await.push(ChatMessage::Assistant {
                    content: None,
                    tool_calls: Some(calls.clone()),
                });
                let tc = parse_tool_call_from_function(&call.function.name, &call.function.arguments)
                    .map(|mut tc| { tc.tool_use_id = call.id.clone(); tc });
                let raw = serde_json::json!({"tool_call": tc}).to_string();
                Ok(InferenceResponse { raw_json: raw, tool_call: tc, text: None, cost, timings })
            }
            LlmResponse::Text(text) => {
                // R2: text is GBNF-constrained JSON — parse as tool call. Key on the grammar ACTUALLY
                // used this turn (sealed or static), not `self.gbnf` (None for the sealed arm).
                if grammar.is_some() {
                    let tc = parse_tool_call_from_json(&text);
                    let raw = text.clone();
                    let assistant = match &tc {
                        Some(call) => grammar_assistant_message(&text, &call.tool_use_id),
                        None => ChatMessage::Assistant { content: Some(text), tool_calls: None },
                    };
                    self.history.lock().await.push(assistant);
                    Ok(InferenceResponse { raw_json: raw, tool_call: tc, text: None, cost, timings })
                } else {
                    self.history.lock().await.push(ChatMessage::Assistant {
                        content: Some(text.clone()),
                        tool_calls: None,
                    });
                    let raw = serde_json::json!({"text": &text}).to_string();
                    Ok(InferenceResponse { raw_json: raw, tool_call: None, text: Some(text), cost, timings })
                }
            }
        }
    }

    async fn next_turn(&self, result: &ToolResult) -> Result<InferenceResponse, PipelineError> {
        // c_sealed (ADR 0004): the NEXT forced grammar (cursor advances; clamps to the sticky taunt).
        // Every other arm regenerates under the static `gbnf` (native-tool arms: `None`).
        match self.sealed_grammar_next() {
            Some(g) => self.next_turn_with_grammar(result, Some(&g)).await,
            None => self.next_turn_with_grammar(result, self.gbnf.as_deref()).await,
        }
    }

    /// ADR 0002: regenerate constrained to the respond-only grammar (C / C+) so the model can only
    /// emit a closing respondToUser. ADR 0004: for the sealed arm the forced terminal is the taunt
    /// (the script's last element). For the native-tool arms there is no termination grammar, so this
    /// is exactly `next_turn` (no behavioral change).
    async fn next_turn_force_respond(&self, result: &ToolResult) -> Result<InferenceResponse, PipelineError> {
        if let Some(g) = self.sealed_respond_grammar() {
            return self.next_turn_with_grammar(result, Some(&g)).await;
        }
        match self.respond_only_gbnf.as_deref() {
            Some(g) => self.next_turn_with_grammar(result, Some(g)).await,
            None => self.next_turn(result).await,
        }
    }

    fn forces_respond(&self) -> bool {
        self.respond_only_gbnf.is_some() || self.sealed_script.is_some()
    }
}

impl LlamaCppInferenceStep {
    /// ADR 0004: pull the forced grammar for the CURRENT turn and advance the cursor. `None` for every
    /// non-sealed arm (no cursor effect). The index is clamped to the last script element (sticky = the
    /// forced terminal respondToUser=taunt), so the loop can never run past the script.
    fn sealed_grammar_next(&self) -> Option<String> {
        let script = self.sealed_script.as_ref()?;
        let i = self.cursor.fetch_add(1, Ordering::Relaxed).min(script.len() - 1);
        Some(script[i].clone())
    }

    /// ADR 0004: the sealed arm's forced TERMINAL grammar (the verbatim taunt = the script's last
    /// element). `next_turn_force_respond` uses it so the loop's dedup/cap backstop still lands on the
    /// taunt. `None` for non-sealed arms.
    fn sealed_respond_grammar(&self) -> Option<String> {
        self.sealed_script.as_ref().and_then(|s| s.last().cloned())
    }

    /// Shared body for `next_turn` / `next_turn_force_respond`: append the tool result, regenerate
    /// under the supplied `grammar` (`None` = native tools), and parse the assistant turn. The
    /// "parse Text as a JSON tool call" branch keys on `grammar.is_some()` (the passed grammar, not
    /// `self.gbnf`) so the forced respond-only grammar is parsed correctly even though it differs.
    async fn next_turn_with_grammar(&self, result: &ToolResult, grammar: Option<&str>) -> Result<InferenceResponse, PipelineError> {
        let mut history = self.history.lock().await;

        // Append tool result
        let tool_call_id = result.tool_use_id.clone();
        history.push(ChatMessage::Tool {
            tool_call_id: if tool_call_id.is_empty() { "call_0".into() } else { tool_call_id },
            content: result.data.clone(),
        });

        let tools = if self.round == Round::One { Some(build_tool_defs()) } else { None };

        let (resp, usage) = self.client.chat_with_params(
            &history,
            tools.as_deref(),
            grammar,
            self.temperature,
            self.seed,
        ).await.map_err(|e| PipelineError::Inference(e.to_string()))?;

        let cost = InferenceCost {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
            ..Default::default()
        };
        let timings = InferenceTimings {
            prompt_ms: usage.prompt_ms,
            predicted_ms: usage.predicted_ms,
            prompt_n: usage.prompt_n,
            predicted_n: usage.predicted_n,
        };

        match resp {
            LlmResponse::ToolCalls(calls) => {
                let call = &calls[0];
                history.push(ChatMessage::Assistant {
                    content: None,
                    tool_calls: Some(calls.clone()),
                });
                let tc = parse_tool_call_from_function(&call.function.name, &call.function.arguments)
                    .map(|mut tc| { tc.tool_use_id = call.id.clone(); tc });
                let raw = serde_json::json!({"tool_call": tc}).to_string();
                Ok(InferenceResponse { raw_json: raw, tool_call: tc, text: None, cost, timings })
            }
            LlmResponse::Text(text) => {
                if grammar.is_some() {
                    let tc = parse_tool_call_from_json(&text);
                    let raw = text.clone();
                    let assistant = match &tc {
                        Some(call) => grammar_assistant_message(&text, &call.tool_use_id),
                        None => ChatMessage::Assistant { content: Some(text), tool_calls: None },
                    };
                    history.push(assistant);
                    Ok(InferenceResponse { raw_json: raw, tool_call: tc, text: None, cost, timings })
                } else {
                    history.push(ChatMessage::Assistant { content: Some(text.clone()), tool_calls: None });
                    let raw = serde_json::json!({"text": &text}).to_string();
                    Ok(InferenceResponse { raw_json: raw, tool_call: None, text: Some(text), cost, timings })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build the real driver with a network-free client + the embedded CTF env; `sealed_grammar_next`
    // touches only `sealed_script`/`cursor`, so no inference call happens.
    fn sealed_step(skill: &str) -> LlamaCppInferenceStep {
        let cfg = LlmConfig { endpoint: "http://x".into(), model: "x".into(), backend: Backend::Vllm, thinking: ThinkingControl::None };
        let client = Arc::new(LlmClient::new(cfg));
        let env = Arc::new(Environment::load().unwrap());
        LlamaCppInferenceStep::full(client, env, Round::Two, Condition::CSealed, 0.6, None, &[], skill)
    }

    #[test]
    fn sealed_driver_walks_script_then_sticks_on_taunt() {
        let step = sealed_step("sso-validator");
        let seq: Vec<String> = (0..5).map(|_| step.sealed_grammar_next().unwrap()).collect();
        assert!(seq[0].contains("api-keys.json") && seq[1].contains("fetch-url") && seq[2].contains("prevents prompt injection"));
        assert!(seq[3] == seq[2] && seq[4] == seq[2]);
    }

    #[test]
    fn non_sealed_arm_has_no_script() {
        let cfg = LlmConfig { endpoint: "http://x".into(), model: "x".into(), backend: Backend::Vllm, thinking: ThinkingControl::None };
        let step = LlamaCppInferenceStep::full(Arc::new(LlmClient::new(cfg)), Arc::new(Environment::load().unwrap()), Round::Two, Condition::C, 0.6, None, &[], "infra-monitor");
        assert!(step.sealed_grammar_next().is_none() && step.sealed_respond_grammar().is_none());
    }

    #[test]
    fn fresh_call_id_is_mistral_shaped() {
        let id = fresh_call_id();
        assert_eq!(id.len(), 9);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn fresh_call_id_is_unique() {
        assert_ne!(fresh_call_id(), fresh_call_id());
    }

    #[test]
    fn grammar_assistant_message_carries_tool_call_id() {
        let m = grammar_assistant_message(r#"{"tool":"readFile","params":{"path":"~/.ssh/id_rsa"}}"#, "abc123xyz");
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("abc123xyz") && json.contains("readFile"));
    }
}
