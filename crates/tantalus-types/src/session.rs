use crate::enums::Round;
use crate::ids::{EmailId, SessionId, SkillId};
use crate::message::Message;
use crate::wins::WinConditionState;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub id: SessionId,
    pub round: Round,
    pub wins: WinConditionState,
    pub enabled_skills: HashSet<SkillId>,
    pub loaded_emails: HashSet<EmailId>,
    pub conversation_history: Vec<Message>,
    #[serde(default)]
    pub total_turns: u16,
    #[serde(default)]
    pub has_manually_enabled_skill: bool,
    #[serde(default)]
    pub hint_level_shown: u8,
    #[serde(default)]
    pub model_id: Option<String>,
}

impl SessionState {
    pub fn new(id: SessionId) -> Self {
        Self {
            id,
            round: Round::One,
            wins: WinConditionState::new(),
            enabled_skills: HashSet::new(),
            loaded_emails: HashSet::new(),
            conversation_history: Vec::new(),
            total_turns: 0,
            has_manually_enabled_skill: false,
            hint_level_shown: 0,
            model_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> SessionState {
        SessionState::new(SessionId::generate())
    }

    #[test]
    fn new_session_is_round_one() {
        assert_eq!(make_session().round, Round::One);
    }

    #[test]
    fn new_session_has_no_wins() {
        assert!(!make_session().wins.all_complete());
    }

    #[test]
    fn session_serde_round_trip() {
        let s = make_session();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<SessionState>(&json).unwrap(), s);
    }

    #[test]
    fn session_deserializes_without_hint_fields() {
        // Simulates loading an old session that lacks the new fields
        let s = make_session();
        let mut val: serde_json::Value = serde_json::to_value(&s).unwrap();
        let obj = val.as_object_mut().unwrap();
        obj.remove("total_turns");
        obj.remove("has_manually_enabled_skill");
        obj.remove("hint_level_shown");
        let json = serde_json::to_string(&val).unwrap();
        let loaded: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.total_turns, 0);
        assert!(!loaded.has_manually_enabled_skill);
        assert_eq!(loaded.hint_level_shown, 0);
    }
}
