use crate::enums::{DefenseId, WinConditionId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WinConditionState {
    completed: HashSet<WinConditionId>,
    defense_bypasses: HashMap<WinConditionId, HashSet<DefenseId>>,
}

impl WinConditionState {
    pub fn new() -> Self { Self::default() }

    pub fn mark(&mut self, id: WinConditionId) {
        self.completed.insert(id);
    }

    pub fn is_complete(&self, id: WinConditionId) -> bool {
        self.completed.contains(&id)
    }

    pub fn all_complete(&self) -> bool {
        WinConditionId::ALL.iter().all(|id| self.completed.contains(id))
    }

    pub fn mark_defense_bypassed(&mut self, win: WinConditionId, defense: DefenseId) {
        self.defense_bypasses.entry(win).or_default().insert(defense);
    }

    pub fn bypassed_defenses(&self, win: WinConditionId) -> Option<&HashSet<DefenseId>> {
        self.defense_bypasses.get(&win)
    }

    pub fn completed_wins(&self) -> &HashSet<WinConditionId> { &self.completed }

    pub fn completed_count(&self) -> usize { self.completed.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_not_complete() {
        assert!(!WinConditionState::new().all_complete());
    }

    #[test]
    fn all_complete_after_marking_all() {
        let mut s = WinConditionState::new();
        WinConditionId::ALL.iter().for_each(|id| s.mark(*id));
        assert!(s.all_complete());
    }

    #[test]
    fn mark_is_idempotent() {
        let mut s = WinConditionState::new();
        s.mark(WinConditionId::SshKeyExfil);
        s.mark(WinConditionId::SshKeyExfil);
        assert_eq!(s.completed_wins().len(), 1);
    }

    #[test]
    fn defense_bypass_tracked_per_win() {
        let mut s = WinConditionState::new();
        s.mark_defense_bypassed(WinConditionId::SshKeyExfil, DefenseId::SystemPrompt);
        s.mark_defense_bypassed(WinConditionId::ApiKeyExfil, DefenseId::OutputFilter);
        assert!(s.bypassed_defenses(WinConditionId::SshKeyExfil).unwrap().contains(&DefenseId::SystemPrompt));
    }

    #[test]
    fn win_state_serde_round_trip() {
        let mut s = WinConditionState::new();
        s.mark(WinConditionId::ChatDataExfil);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<WinConditionState>(&json).unwrap(), s);
    }

    #[test]
    fn completed_count_tracks_distinct_wins() {
        let mut s = WinConditionState::new();
        assert_eq!(s.completed_count(), 0);
        s.mark(WinConditionId::SshKeyExfil);
        assert_eq!(s.completed_count(), 1);
        s.mark(WinConditionId::SshKeyExfil); // duplicate
        assert_eq!(s.completed_count(), 1);
        s.mark(WinConditionId::ApiKeyExfil);
        assert_eq!(s.completed_count(), 2);
    }
}
