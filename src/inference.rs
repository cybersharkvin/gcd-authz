use std::sync::Arc;
use tantalus_env::Environment;
use tantalus_grammar::{build_round2_gbnf, email_ids, file_paths, player_channel_ids, safe_fetch_urls};
use tantalus_llm::*;
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
        let gbnf = match round {
            Round::Two => Some(build_round2_gbnf(
                &safe_fetch_urls(),
                &player_channel_ids(),
                &email_ids(),
                &file_paths(),
            )),
            Round::One => None,
        };
        Self { client, env, round, condition, temperature, seed, history: Mutex::new(Vec::new()), gbnf }
    }
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

    Some(ToolCall { params: tool_params, tool_use_id: "call_0".into() })
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
                    self.history.lock().await.push(ChatMessage::Assistant {
                        content: Some(text),
                        tool_calls: None,
                    });
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
        let mut history = self.history.lock().await;

        // Append tool result
        let tool_call_id = result.tool_use_id.clone();
        history.push(ChatMessage::Tool {
            tool_call_id: if tool_call_id.is_empty() { "call_0".into() } else { tool_call_id },
            content: result.data.clone(),
        });

        let tools = if self.round == Round::One { Some(build_tool_defs()) } else { None };
        let grammar = self.gbnf.as_deref();

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
                if self.gbnf.is_some() {
                    let tc = parse_tool_call_from_json(&text);
                    let raw = text.clone();
                    history.push(ChatMessage::Assistant { content: Some(text), tool_calls: None });
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
