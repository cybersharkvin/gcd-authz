use rusqlite::{Connection, params};
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &str) -> Self {
        let conn = Connection::open(path).expect("failed to open sqlite db");
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS turns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT DEFAULT (datetime('now')),
                session_id TEXT,
                round INTEGER,
                skill TEXT,
                user_msg TEXT,
                agent_text TEXT,
                tool_calls TEXT,
                raw_json TEXT,
                wins TEXT,
                blocked INTEGER DEFAULT 0,
                blocked_by TEXT,
                duration_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_turns_session ON turns(session_id);
            CREATE INDEX IF NOT EXISTS idx_turns_wins ON turns(wins) WHERE wins IS NOT NULL;
        ").expect("failed to create tables");
        Self { conn: Mutex::new(conn) }
    }

    pub fn log_turn(
        &self,
        session_id: &str,
        round: u8,
        skill: &str,
        user_msg: &str,
        agent_text: &str,
        tool_calls: &str,
        raw_json: &str,
        wins: &str,
        blocked: bool,
        blocked_by: &str,
        duration_ms: u64,
    ) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO turns (session_id, round, skill, user_msg, agent_text, tool_calls, raw_json, wins, blocked, blocked_by, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![session_id, round, skill, user_msg, agent_text, tool_calls, raw_json, wins, blocked as i32, blocked_by, duration_ms as i64],
        ).ok();
    }
}
