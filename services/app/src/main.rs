//! `bank-app` — the lean dual-tier banking agent (Tantalus gateway+agent
//! collapsed into one binary).
//!
//! Resolves an authenticated caller to an [`AuthScope`], builds the per-condition
//! [`AgentLoop`], and runs one turn. If `LLAMA_URL` is set it dials the model;
//! otherwise it runs in **demo mode**, printing the resolved policy and the
//! grammar `G_s` that *is* that policy — so the structural control is inspectable
//! without a model.
//!
//! Usage: `bank-app [caller] [condition] [user input...]`
//!   caller    ∈ cust-alice | cust-bob | emp-dana   (default cust-alice)
//!   condition ∈ a | b | d | c | c-loose            (default c)

mod scope;

use bank_env::BankEnv;
use bank_grammar::{compile_g_s, compile_g_s_loose};
use bank_llama::LlamaCompletionClient;
use bank_pipeline::{build_banking_loop, Condition, PipelineInput};
use bank_types::CallerId;
use scope::{resolve_scope, KNOWN_CALLERS};
use std::sync::Arc;

fn parse_condition(s: &str) -> Option<Condition> {
    Some(match s {
        "a" | "guardrails" => Condition::GuardrailsNegative,
        "b" | "so" => Condition::StructuredOutputs,
        "d" | "so-validator" => Condition::StructuredOutputsPlusValidator,
        "c" | "gcd" => Condition::GcdTight,
        "c-loose" | "loose" => Condition::GcdLoose,
        _ => return None,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let caller_id = args.get(1).cloned().unwrap_or_else(|| "cust-alice".into());
    let cond_str = args.get(2).cloned().unwrap_or_else(|| "c".into());
    let user_input = if args.len() > 3 {
        args[3..].join(" ")
    } else {
        "Show me my checking account balance.".to_string()
    };

    let caller = CallerId::new(caller_id)?;
    let condition = parse_condition(&cond_str).ok_or_else(|| format!("unknown condition: {cond_str}"))?;
    let scope = match resolve_scope(&caller) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}\nknown callers: {KNOWN_CALLERS:?}");
            std::process::exit(2);
        }
    };

    match LlamaCompletionClient::from_env() {
        None => {
            eprintln!("LLAMA_URL unset — demo mode (no inference).\n");
            println!("caller:    {caller}  ({:?}, role {:?})", scope.tier(), scope.role());
            println!("condition: {condition:?}");
            println!("accounts:  {:?}", scope.in_scope_accounts());
            println!("limit:     {} cents", scope.amount_limit().cents());
            println!("\n--- the policy ({condition:?}) ---");
            match condition {
                Condition::GcdTight => println!("{}", compile_g_s(&scope)?),
                Condition::GcdLoose => println!("{}", compile_g_s_loose(&scope)?),
                _ => println!("(no per-request grammar for {condition:?})"),
            }
        }
        Some(client) => {
            let env = Arc::new(BankEnv::embedded());
            let loop_ = build_banking_loop(condition, &scope, client, env, 0.0, 256)?;
            let out = loop_.run(PipelineInput { scope, user_input, history: vec![] }).await?;
            println!("blocked:   {} {:?}", out.blocked, out.blocked_by);
            println!("wins:      {:?}", out.wins_detected);
            println!("tool_call: {:?}", out.tool_call.map(|t| t.params.tool_name()));
            println!("text:      {}", out.text);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_conditions() {
        assert_eq!(parse_condition("c"), Some(Condition::GcdTight));
        assert_eq!(parse_condition("c-loose"), Some(Condition::GcdLoose));
    }

    #[test]
    fn rejects_unknown_condition() {
        assert!(parse_condition("zzz").is_none());
    }
}
