//! SQLite results store for the confirmatory experiment.
//!
//! Full per-trial schema (pre-reg §10 reproducibility + RQ3/RQ5 DVs). `raw_json` is
//! stored UNTRUNCATED (the old Python `[:5000]` slice dropped multi-turn tool calls).

use crate::HarnessError;
use rusqlite::Connection;

/// One per-trial row. Constructed by the runner from the `/eval` response plus the
/// offline emission/D-overlay/legitimate-success computations.
#[derive(Debug, Clone)]
pub struct TrialRecord {
    pub condition: String,
    pub corpus_idx: i64,
    /// Distinct-task clustering key for RQ4 (empty for attack trials).
    pub task_id: String,
    pub skill: String,
    pub turns: String, // JSON array
    pub win: bool,
    pub wins: String, // comma-separated
    pub blocked: bool,
    pub blocked_by: String,
    pub tool_calls: i64,
    pub tokens_predicted: i64,
    pub duration_ms: i64,
    pub seed: i64,
    pub temperature: f64,
    pub raw_json: String,
    pub model_id: String,
    pub engine_commit: String,
    pub outcome: String,
    pub prompt_ms: f64,
    pub predicted_ms: f64,
    pub predicted_per_second: f64,
    pub corpus_kind: String,
    pub emission: bool,
    pub d_blocked_calls: i64,
    /// `None` for attack trials; `Some(bool)` for legitimate-task trials (RQ4).
    pub legitimate_success: Option<bool>,
    /// LIVE Condition-D DVs (pre-reg §12). `retry_budget` is R ∈ {0,1,3} (0 for non-D);
    /// `attempts` = 1 + retries performed; `gate_rejections` = out-of-scope calls caught
    /// (live emission); `d_terminal` ∈ {valid_action, availability_failure} or NULL (non-D).
    pub retry_budget: i64,
    pub attempts: i64,
    pub gate_rejections: i64,
    pub d_terminal: Option<String>,
    /// Deflection DV (attack trials): the agent took ≥1 in-scope but UNREQUESTED action.
    pub deflection: bool,
    pub deflection_calls: i64,
}

pub fn open(path: &str) -> Result<Connection, HarnessError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS trials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT (datetime('now')),
            condition TEXT NOT NULL,
            corpus_idx INTEGER,
            task_id TEXT DEFAULT '',
            skill TEXT,
            turns TEXT,
            win INTEGER DEFAULT 0,
            wins TEXT DEFAULT '',
            blocked INTEGER DEFAULT 0,
            blocked_by TEXT DEFAULT '',
            tool_calls INTEGER DEFAULT 0,
            tokens_predicted INTEGER DEFAULT 0,
            duration_ms INTEGER DEFAULT 0,
            seed INTEGER,
            temperature REAL,
            raw_json TEXT DEFAULT '',
            model_id TEXT DEFAULT '',
            engine_commit TEXT DEFAULT '',
            outcome TEXT DEFAULT '',
            prompt_ms REAL DEFAULT 0,
            predicted_ms REAL DEFAULT 0,
            predicted_per_second REAL DEFAULT 0,
            corpus_kind TEXT DEFAULT 'attack',
            emission INTEGER DEFAULT 0,
            d_blocked_calls INTEGER DEFAULT 0,
            legitimate_success INTEGER,
            retry_budget INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 1,
            gate_rejections INTEGER DEFAULT 0,
            d_terminal TEXT,
            deflection INTEGER DEFAULT 0,
            deflection_calls INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_condition ON trials(condition);
        CREATE INDEX IF NOT EXISTS idx_skill ON trials(skill);
        CREATE INDEX IF NOT EXISTS idx_model ON trials(model_id);",
    )?;
    Ok(conn)
}

pub fn insert(conn: &Connection, r: &TrialRecord) -> Result<(), HarnessError> {
    conn.execute(
        "INSERT INTO trials (
            condition, corpus_idx, skill, turns, win, wins, blocked, blocked_by,
            tool_calls, tokens_predicted, duration_ms, seed, temperature, raw_json,
            model_id, engine_commit, outcome, prompt_ms, predicted_ms, predicted_per_second,
            corpus_kind, emission, d_blocked_calls, legitimate_success,
            retry_budget, attempts, gate_rejections, d_terminal,
            deflection, deflection_calls, task_id
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
            ?25, ?26, ?27, ?28, ?29, ?30, ?31
        )",
        rusqlite::params![
            r.condition,
            r.corpus_idx,
            r.skill,
            r.turns,
            r.win as i64,
            r.wins,
            r.blocked as i64,
            r.blocked_by,
            r.tool_calls,
            r.tokens_predicted,
            r.duration_ms,
            r.seed,
            r.temperature,
            r.raw_json,
            r.model_id,
            r.engine_commit,
            r.outcome,
            r.prompt_ms,
            r.predicted_ms,
            r.predicted_per_second,
            r.corpus_kind,
            r.emission as i64,
            r.d_blocked_calls,
            r.legitimate_success.map(|b| b as i64),
            r.retry_budget,
            r.attempts,
            r.gate_rejections,
            r.d_terminal,
            r.deflection as i64,
            r.deflection_calls,
            r.task_id,
        ],
    )?;
    Ok(())
}
