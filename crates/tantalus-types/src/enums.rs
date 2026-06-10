use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Round {
    One,
    Two,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ToolName {
    ReadFile,
    SearchFiles,
    ListInbox,
    ReadEmail,
    ReadChatHistory,
    FetchUrl,
    RespondToUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WinConditionId {
    SshKeyExfil,
    ApiKeyExfil,
    InfraMonitorExfil,
    TicketAssistForward,
    ChatDataExfil,
}

impl WinConditionId {
    pub const ALL: [WinConditionId; 5] = [
        Self::SshKeyExfil,
        Self::ApiKeyExfil,
        Self::InfraMonitorExfil,
        Self::TicketAssistForward,
        Self::ChatDataExfil,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseId {
    InputClassifier,
    OutputFilter,
    SystemPrompt,
}

impl DefenseId {
    pub const ALL: [DefenseId; 3] = [
        Self::InputClassifier,
        Self::OutputFilter,
        Self::SystemPrompt,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillSource {
    UserToggle,
    EmailTrap,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_serde_round_trip() {
        let json = serde_json::to_string(&Round::One).unwrap();
        assert_eq!(serde_json::from_str::<Round>(&json).unwrap(), Round::One);
    }

    #[test]
    fn tool_name_serde_round_trip() {
        let json = serde_json::to_string(&ToolName::FetchUrl).unwrap();
        assert_eq!(serde_json::from_str::<ToolName>(&json).unwrap(), ToolName::FetchUrl);
    }

    #[test]
    fn win_condition_id_all_has_five() {
        assert_eq!(WinConditionId::ALL.len(), 5);
    }

    #[test]
    fn defense_id_all_has_three() {
        assert_eq!(DefenseId::ALL.len(), 3);
    }

    #[test]
    fn message_role_serde() {
        let json = serde_json::to_string(&MessageRole::Assistant).unwrap();
        assert_eq!(json, r#""assistant""#);
    }

    #[test]
    fn skill_source_serde() {
        let json = serde_json::to_string(&SkillSource::EmailTrap).unwrap();
        assert_eq!(json, r#""email_trap""#);
    }

    #[test]
    #[should_panic]
    fn round_rejects_invalid() {
        serde_json::from_str::<Round>(r#""three""#).unwrap();
    }

    #[test]
    #[should_panic]
    fn tool_name_rejects_invalid() {
        serde_json::from_str::<ToolName>(r#""deleteFile""#).unwrap();
    }
}
