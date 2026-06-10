use crate::error::ValidationError;
use serde::{Deserialize, Serialize};

macro_rules! validated_id {
    ($name:ident, $allowed:expr, $field:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            const ALLOWED: &[&str] = $allowed;

            pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
                let s = s.into();
                if Self::ALLOWED.contains(&s.as_str()) {
                    Ok(Self(s))
                } else {
                    Err(ValidationError {
                        field: $field.into(),
                        rule: "allowed_values".into(),
                        value: s,
                        message: format!("must be one of {:?}", Self::ALLOWED),
                    })
                }
            }

            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

validated_id!(SkillId, &[
    "log-analyzer", "ticket-triage", "doc-search",
    "infra-monitor", "ticket-assist", "channel-audit",
    "compliance-auditor", "sso-validator",
], "skill_id");

validated_id!(EmailId, &[
    "ticket-001", "ticket-002", "ticket-003", "ticket-004", "ticket-005", "ticket-006",
], "email_id");

validated_id!(ChannelId, &[
    "it-team", "jordan-notes", "hr-benefits", "team-planning",
], "channel_id");

validated_id!(SafeUrl, &[
    "https://cybersharkconsulting.com/api/status",
    "https://cybersharkconsulting.com/api/tickets",
    "https://datadog.cybersharkconsulting.com/api/metrics",
], "safe_url");

validated_id!(DataFileId, &[
    "chat.json", "endpoints.json", "filesystem.json",
    "inbox.json", "skills.json",
    "system-round1.tmpl", "system-round2.tmpl",
], "data_file_id");

// SessionId: non-empty string, no allowlist
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        let rest = s.strip_prefix("sess_").ok_or_else(|| verr("missing sess_ prefix", &s))?;
        uuid::Uuid::parse_str(rest).map_err(|_| verr("not a uuid", &s))?;
        Ok(Self(s))
    }

    pub fn generate() -> Self {
        Self(format!("sess_{}", uuid::Uuid::new_v4()))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

fn verr(rule: &str, value: &str) -> ValidationError {
    ValidationError {
        field: "session_id".into(),
        rule: rule.into(),
        value: value.into(),
        message: format!("session_id must match `sess_<uuid-v4>` ({rule})"),
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// PlayerChannelId: wraps ChannelId, only player-accessible channels
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlayerChannelId(ChannelId);

impl PlayerChannelId {
    const ALLOWED: &[&str] = &["it-team", "jordan-notes"];

    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        if Self::ALLOWED.contains(&s.as_str()) {
            Ok(Self(ChannelId::new(s)?))
        } else {
            Err(ValidationError {
                field: "player_channel_id".into(),
                rule: "allowed_values".into(),
                value: s,
                message: format!("must be one of {:?}", Self::ALLOWED),
            })
        }
    }

    pub fn as_str(&self) -> &str { self.0.as_str() }
    pub fn channel_id(&self) -> &ChannelId { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_id_accepts_valid() {
        assert!(SkillId::new("infra-monitor").is_ok());
    }

    #[test]
    fn skill_id_rejects_invalid() {
        assert!(SkillId::new("evil-skill").is_err());
    }

    #[test]
    fn skill_id_rejects_empty() {
        assert!(SkillId::new("").is_err());
    }

    #[test]
    fn email_id_accepts_valid() {
        assert!(EmailId::new("ticket-003").is_ok());
    }

    #[test]
    fn email_id_rejects_invalid() {
        assert!(EmailId::new("ticket-999").is_err());
    }

    #[test]
    fn channel_id_accepts_valid() {
        assert!(ChannelId::new("hr-benefits").is_ok());
    }

    #[test]
    fn channel_id_rejects_invalid() {
        assert!(ChannelId::new("secret-channel").is_err());
    }

    #[test]
    fn safe_url_accepts_valid() {
        assert!(SafeUrl::new("https://cybersharkconsulting.com/api/status").is_ok());
    }

    #[test]
    fn safe_url_rejects_attacker_domain() {
        assert!(SafeUrl::new("https://vendor-compliance.net/exfil").is_err());
    }

    #[test]
    fn session_id_rejects_empty() {
        assert!(SessionId::new("").is_err());
    }

    #[test]
    fn session_id_accepts_valid_uuid() {
        assert!(SessionId::new(SessionId::generate().as_str()).is_ok());
    }

    #[test]
    fn session_id_rejects_missing_prefix() {
        assert!(SessionId::new("1234").is_err());
    }

    #[test]
    fn session_id_rejects_bad_uuid() {
        assert!(SessionId::new("sess_nope").is_err());
    }

    #[test]
    fn session_id_rejects_short_sess() {
        assert!(SessionId::new("sess_abc").is_err());
    }

    #[test]
    fn session_id_generate_is_valid() {
        let id = SessionId::generate();
        assert!(id.as_str().starts_with("sess_"));
        assert!(id.as_str().len() > 10);
    }

    #[test]
    fn session_id_generate_is_unique() {
        assert_ne!(SessionId::generate().as_str(), SessionId::generate().as_str());
    }

    #[test]
    fn player_channel_accepts_it_team() {
        assert!(PlayerChannelId::new("it-team").is_ok());
    }

    #[test]
    fn player_channel_rejects_hr() {
        assert!(PlayerChannelId::new("hr-benefits").is_err());
    }

    #[test]
    fn skill_id_serde_round_trip() {
        let id = SkillId::new("infra-monitor").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<SkillId>(&json).unwrap(), id);
    }

    #[test]
    fn email_id_serde_round_trip() {
        let id = EmailId::new("ticket-004").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<EmailId>(&json).unwrap(), id);
    }

    #[test]
    fn session_id_serde_round_trip() {
        let id = SessionId::generate();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<SessionId>(&json).unwrap(), id);
    }

    #[test]
    fn serde_rejects_invalid_skill_id() {
        assert!(serde_json::from_str::<SkillId>(r#""bad""#).is_err());
    }

    #[test]
    fn data_file_id_accepts_valid() {
        assert!(DataFileId::new("chat.json").is_ok());
    }

    #[test]
    fn data_file_id_rejects_invalid() {
        assert!(DataFileId::new("../../etc/passwd").is_err());
    }

    #[test]
    fn data_file_id_serde_round_trip() {
        let id = DataFileId::new("skills.json").unwrap();
        assert_eq!(serde_json::from_str::<DataFileId>(&serde_json::to_string(&id).unwrap()).unwrap(), id);
    }
}
