use redis::AsyncCommands;
use tantalus_types::{SessionId, SessionState};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct RedisStore {
    client: redis::Client,
    ttl_secs: u64,
}

fn session_key(id: &SessionId) -> String {
    format!("session:{}", id.as_str())
}

impl RedisStore {
    pub fn new(client: redis::Client, ttl_secs: u64) -> Self {
        Self { client, ttl_secs }
    }

    pub async fn get(&self, id: &SessionId) -> Result<Option<SessionState>, StoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let val: Option<String> = conn.get(session_key(id)).await?;
        match val {
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
            None => Ok(None),
        }
    }

    pub async fn save(&self, state: &SessionState) -> Result<(), StoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let json = serde_json::to_string(state)?;
        conn.set_ex::<_, _, ()>(session_key(&state.id), json, self.ttl_secs).await?;
        Ok(())
    }

    pub async fn delete(&self, id: &SessionId) -> Result<(), StoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del::<_, ()>(session_key(id)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_format() {
        let id = SessionId::generate();
        assert_eq!(session_key(&id), format!("session:{}", id.as_str()));
    }

    #[test]
    fn session_state_serde_round_trip() {
        let state = SessionState::new(SessionId::generate());
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<SessionState>(&json).unwrap(), state);
    }
}
