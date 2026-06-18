use std::sync::Arc;
use tantalus_env::Environment;
use tantalus_grammar::{build_closed_response_gbnf, build_respond_only_closed_gbnf, build_respond_only_gbnf, build_round2_gbnf, email_ids, file_paths, player_channel_ids, safe_fetch_urls, FreeStringStyle};
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
}

impl LlamaCppInferenceStep {
    pub fn new(client: Arc<LlmClient>, env: Arc<Environment>, round: Round) -> Self {
        Self::with_condition(client, env, round, tantalus_pipeline::prompt::Condition::A1)
    }

    pub fn with_condition(client: Arc<LlmClient>, env: Arc<Environment>, round: Round, condition: tantalus_pipeline::prompt::Condition) -> Self {
        Self::full(client, env, round, condition, 0.7, None)
    }

    pub fn full(client: Arc<LlmClient>, env: Arc<Environment>, round: Round,
                condition: tantalus_pipeline::prompt::Condition, temperature: f32, seed: Option<u64>) -> Self {
        // Free-string repetition style is an ENGINE choice: xgrammar (vLLM/SGLang) chokes
        // on `{0,N}` (unrolls to N states, ~60s/compile at N=400 on vLLM 0.23.0), so use
        // the Kleene star there; llama.cpp GBNF keeps the bound (cheap + truncation-proof).
        let style = match client.backend() {
            Backend::LlamaCpp => FreeStringStyle::Bounded,
            Backend::Vllm | Backend::Sglang => FreeStringStyle::Unbounded,
        };
        let gbnf = match round {
            // C+ (CClosed) enumerates respondToUser.message as a closed alternation of canned
            // responses; plain C uses the free-string message. Tool enums identical.
            Round::Two if condition == Condition::CClosed => {
                let responses = closed_responses();
                let refs: Vec<&str> = responses.iter().map(|s| s.as_str()).collect();
                Some(build_closed_response_gbnf(
                    &safe_fetch_urls(), &player_channel_ids(), &email_ids(), &file_paths(), &refs, style,
                ))
            }
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
        let respond_only_gbnf = match round {
            Round::Two if condition == Condition::CClosed => {
                let responses = closed_responses();
                let refs: Vec<&str> = responses.iter().map(|s| s.as_str()).collect();
                Some(build_respond_only_closed_gbnf(&refs))
            }
            Round::Two => Some(build_respond_only_gbnf(style)),
            Round::One => None,
        };
        Self { client, env, round, condition, temperature, seed, history: Mutex::new(Vec::new()), gbnf, respond_only_gbnf }
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
        let grammar = self.gbnf.as_deref();

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
                // R2: text is GBNF-constrained JSON — parse as tool call
                if self.gbnf.is_some() {
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
        self.next_turn_with_grammar(result, self.gbnf.as_deref()).await
    }

    /// ADR 0002: regenerate constrained to the respond-only grammar (C / C+) so the model can only
    /// emit a closing respondToUser. For the native-tool arms there is no respond-only grammar, so
    /// this is exactly `next_turn` (no behavioral change).
    async fn next_turn_force_respond(&self, result: &ToolResult) -> Result<InferenceResponse, PipelineError> {
        match self.respond_only_gbnf.as_deref() {
            Some(g) => self.next_turn_with_grammar(result, Some(g)).await,
            None => self.next_turn(result).await,
        }
    }

    fn forces_respond(&self) -> bool {
        self.respond_only_gbnf.is_some()
    }
}

impl LlamaCppInferenceStep {
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
