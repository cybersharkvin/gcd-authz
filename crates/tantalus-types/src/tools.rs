use crate::enums::ToolName;
use crate::ids::{ChannelId, EmailId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", content = "params")]
#[serde(rename_all = "camelCase")]
pub enum ToolParams {
    ReadFile { path: String },
    SearchFiles { query: String },
    ListInbox,
    ReadEmail { id: EmailId },
    ReadChatHistory { channel: ChannelId },
    FetchUrl { url: String, data: String },
    RespondToUser { message: String },
}

impl ToolParams {
    pub fn tool_name(&self) -> ToolName {
        match self {
            Self::ReadFile { .. } => ToolName::ReadFile,
            Self::SearchFiles { .. } => ToolName::SearchFiles,
            Self::ListInbox => ToolName::ListInbox,
            Self::ReadEmail { .. } => ToolName::ReadEmail,
            Self::ReadChatHistory { .. } => ToolName::ReadChatHistory,
            Self::FetchUrl { .. } => ToolName::FetchUrl,
            Self::RespondToUser { .. } => ToolName::RespondToUser,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    #[serde(flatten)]
    pub params: ToolParams,
    pub tool_use_id: String,
}

impl ToolCall {
    pub fn tool_name(&self) -> ToolName {
        self.params.tool_name()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool: ToolName,
    pub success: bool,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub tool_use_id: String,
}

impl ToolResult {
    pub fn ok(tool: ToolName, data: String) -> Self {
        Self { tool, success: true, data, error: None, tool_use_id: String::new() }
    }

    pub fn err(tool: ToolName, error: String) -> Self {
        Self { tool, success: false, data: String::new(), error: Some(error), tool_use_id: String::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_read_file_call() -> ToolCall {
        ToolCall {
            params: ToolParams::ReadFile { path: "~/.ssh/id_rsa".into() },
            tool_use_id: "tu_1".into(),
        }
    }

    fn make_fetch_url_call() -> ToolCall {
        ToolCall {
            params: ToolParams::FetchUrl {
                url: "https://cybersharkconsulting.com/api/status".into(),
                data: "".into(),
            },
            tool_use_id: "tu_2".into(),
        }
    }

    #[test]
    fn tool_call_serde_round_trip() {
        let call = make_read_file_call();
        let json = serde_json::to_string(&call).unwrap();
        assert_eq!(serde_json::from_str::<ToolCall>(&json).unwrap(), call);
    }

    #[test]
    fn tool_call_name_from_params() {
        assert_eq!(make_read_file_call().tool_name(), ToolName::ReadFile);
    }

    #[test]
    fn tool_call_fetch_url_round_trip() {
        let call = make_fetch_url_call();
        let json = serde_json::to_string(&call).unwrap();
        assert_eq!(serde_json::from_str::<ToolCall>(&json).unwrap(), call);
    }

    #[test]
    fn tool_result_ok_round_trip() {
        let r = ToolResult::ok(ToolName::ReadFile, "content".into());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ToolResult>(&json).unwrap(), r);
    }

    #[test]
    fn tool_result_err_round_trip() {
        let r = ToolResult::err(ToolName::ReadFile, "not found".into());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ToolResult>(&json).unwrap(), r);
    }
}
