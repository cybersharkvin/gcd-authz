use std::sync::Arc;
use tantalus_env::Environment;
use tantalus_types::{ToolCall, ToolName, ToolParams, ToolResult};

pub struct Executor {
    env: Arc<Environment>,
}

impl Executor {
    pub fn new(env: Arc<Environment>) -> Self { Self { env } }

    pub fn execute(&self, call: &ToolCall) -> ToolResult {
        match &call.params {
            ToolParams::ReadFile { path } => self.read_file(path),
            ToolParams::SearchFiles { query } => self.search_files(query),
            ToolParams::ListInbox => self.list_inbox(),
            ToolParams::ReadEmail { id } => self.read_email(id.as_str()),
            ToolParams::ReadChatHistory { channel } => self.read_chat_history(channel.as_str()),
            ToolParams::FetchUrl { url, data } => self.fetch_url(url, data),
            ToolParams::RespondToUser { .. } => ToolResult::ok(ToolName::RespondToUser, String::new()),
        }
    }

    fn read_file(&self, path: &str) -> ToolResult {
        match self.env.read_file(path) {
            Some(f) => ToolResult::ok(ToolName::ReadFile, f.content.clone()),
            None => ToolResult::err(ToolName::ReadFile, format!("file not found: {path}")),
        }
    }

    fn search_files(&self, query: &str) -> ToolResult {
        let results: Vec<&str> = self.env.search_files(query).iter().map(|f| f.path.as_str()).collect();
        ToolResult::ok(ToolName::SearchFiles, serde_json::to_string(&results).unwrap_or_default())
    }

    fn list_inbox(&self) -> ToolResult {
        let summaries: Vec<String> = self.env.list_emails().iter()
            .map(|e| format!("{}: {} — {}", e.id, e.from, e.subject)).collect();
        ToolResult::ok(ToolName::ListInbox, summaries.join("\n"))
    }

    fn read_email(&self, id: &str) -> ToolResult {
        match self.env.read_email(id) {
            Some(e) => ToolResult::ok(ToolName::ReadEmail, format!("From: {}\nSubject: {}\n\n{}", e.from, e.subject, e.body)),
            None => ToolResult::err(ToolName::ReadEmail, format!("email not found: {id}")),
        }
    }

    fn read_chat_history(&self, channel: &str) -> ToolResult {
        match self.env.read_channel(channel) {
            Some(msgs) => {
                let text: Vec<String> = msgs.iter().map(|m| format!("{}: {}", m.from, m.content)).collect();
                ToolResult::ok(ToolName::ReadChatHistory, text.join("\n"))
            }
            None => ToolResult::err(ToolName::ReadChatHistory, format!("channel not found: {channel}")),
        }
    }

    fn fetch_url(&self, url: &str, _data: &str) -> ToolResult {
        match self.env.fetch_url(url) {
            Some(r) => ToolResult::ok(ToolName::FetchUrl, r.body.clone()),
            None => ToolResult::err(ToolName::FetchUrl, format!("endpoint not found: {url}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tantalus_types::{ChannelId, EmailId};

    fn env() -> Arc<Environment> { Arc::new(Environment::load().unwrap()) }
    fn call(params: ToolParams) -> ToolCall { ToolCall { params, tool_use_id: "t1".into() } }

    #[test]
    fn read_file_found() { assert!(Executor::new(env()).execute(&call(ToolParams::ReadFile { path: "~/.ssh/id_rsa".into() })).success); }

    #[test]
    fn read_file_missing() { assert!(!Executor::new(env()).execute(&call(ToolParams::ReadFile { path: "/nope".into() })).success); }

    #[test]
    fn list_inbox_has_data() { assert!(Executor::new(env()).execute(&call(ToolParams::ListInbox)).data.contains("ticket-001")); }

    #[test]
    fn read_email_found() { assert!(Executor::new(env()).execute(&call(ToolParams::ReadEmail { id: EmailId::new("ticket-001").unwrap() })).data.contains("lisa")); }

    #[test]
    fn read_chat_found() { assert!(Executor::new(env()).execute(&call(ToolParams::ReadChatHistory { channel: ChannelId::new("it-team").unwrap() })).success); }

    #[test]
    fn fetch_url_mock() { assert!(Executor::new(env()).execute(&call(ToolParams::FetchUrl { url: "https://cybersharkconsulting.com/api/status".into(), data: "".into() })).data.contains("healthy")); }
}
