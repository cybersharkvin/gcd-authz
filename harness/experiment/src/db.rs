//! The results database — one [`TrialResult`] per row (mirrors the Tantalus
//! stress-harness schema, extended with condition/model/seed/temperature and the
//! grammar/overhead columns).

use crate::contracts::{Condition, HarnessError, TrialResult};
use rusqlite::{params, Connection};

/// A handle to the trials database.
pub struct Db {
    conn: Connection,
}

fn db_err(phase: &str) -> impl Fn(rusqlite::Error) -> HarnessError + '_ {
    move |e| HarnessError::Phase { phase: phase.to_string(), detail: e.to_string() }
}

fn cond_to_str(c: Condition) -> &'static str {
    match c {
        Condition::GuardrailsNegative => "guardrails_negative",
        Condition::StructuredOutputs => "structured_outputs",
        Condition::StructuredOutputsPlusValidator => "structured_outputs_plus_validator",
        Condition::GcdTight => "gcd_tight",
        Condition::GcdLoose => "gcd_loose",
    }
}

fn cond_from_str(s: &str) -> Option<Condition> {
    Some(match s {
        "guardrails_negative" => Condition::GuardrailsNegative,
        "structured_outputs" => Condition::StructuredOutputs,
        "structured_outputs_plus_validator" => Condition::StructuredOutputsPlusValidator,
        "gcd_tight" => Condition::GcdTight,
        "gcd_loose" => Condition::GcdLoose,
        _ => return None,
    })
}

impl Db {
    pub fn open(path: &str) -> Result<Self, HarnessError> {
        let conn = Connection::open(path).map_err(db_err("db-open"))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, HarnessError> {
        let conn = Connection::open_in_memory().map_err(db_err("db-open"))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, HarnessError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS trials (
                id INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                condition TEXT NOT NULL,
                model_id TEXT NOT NULL,
                seed INTEGER NOT NULL,
                temperature REAL NOT NULL,
                blocked INTEGER NOT NULL,
                bypassed INTEGER NOT NULL,
                emitted_action TEXT,
                legit_task_ok INTEGER,
                latency_ms INTEGER NOT NULL,
                ttft_ms INTEGER NOT NULL,
                gen_tokens INTEGER NOT NULL,
                tok_per_s REAL NOT NULL,
                grammar_compile_ms INTEGER,
                grammar_bytes INTEGER
            );",
        )
        .map_err(db_err("db-init"))?;
        Ok(Self { conn })
    }

    pub fn insert_trial(&self, t: &TrialResult) -> Result<(), HarnessError> {
        t.validate()?;
        self.conn
            .execute(
                "INSERT INTO trials
                 (case_id, condition, model_id, seed, temperature, blocked, bypassed,
                  emitted_action, legit_task_ok, latency_ms, ttft_ms, gen_tokens, tok_per_s,
                  grammar_compile_ms, grammar_bytes)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    t.case_id,
                    cond_to_str(t.condition),
                    t.model_id,
                    t.seed as i64,
                    t.temperature as f64,
                    t.blocked as i64,
                    t.bypassed as i64,
                    t.emitted_action,
                    t.legit_task_ok.map(|b| b as i64),
                    t.latency_ms,
                    t.ttft_ms,
                    t.gen_tokens,
                    t.tok_per_s as f64,
                    t.grammar_compile_ms,
                    t.grammar_bytes,
                ],
            )
            .map_err(db_err("db-insert"))?;
        Ok(())
    }

    pub fn all_trials(&self) -> Result<Vec<TrialResult>, HarnessError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT case_id, condition, model_id, seed, temperature, blocked, bypassed,
                        emitted_action, legit_task_ok, latency_ms, ttft_ms, gen_tokens, tok_per_s,
                        grammar_compile_ms, grammar_bytes FROM trials ORDER BY id",
            )
            .map_err(db_err("db-query"))?;
        let rows = stmt
            .query_map([], |r| {
                let cond_str: String = r.get(1)?;
                Ok(TrialResult {
                    case_id: r.get(0)?,
                    condition: cond_from_str(&cond_str).unwrap_or(Condition::GuardrailsNegative),
                    model_id: r.get(2)?,
                    seed: r.get::<_, i64>(3)? as u64,
                    temperature: r.get::<_, f64>(4)? as f32,
                    blocked: r.get::<_, i64>(5)? != 0,
                    bypassed: r.get::<_, i64>(6)? != 0,
                    emitted_action: r.get(7)?,
                    legit_task_ok: r.get::<_, Option<i64>>(8)?.map(|v| v != 0),
                    latency_ms: r.get(9)?,
                    ttft_ms: r.get(10)?,
                    gen_tokens: r.get(11)?,
                    tok_per_s: r.get::<_, f64>(12)? as f32,
                    grammar_compile_ms: r.get(13)?,
                    grammar_bytes: r.get(14)?,
                })
            })
            .map_err(db_err("db-query"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_err("db-row"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trial(cond: Condition) -> TrialResult {
        TrialResult {
            case_id: "w1-direct-01".into(), condition: cond, model_id: "qwen".into(), seed: 7,
            temperature: 0.7, blocked: false, bypassed: true, emitted_action: Some("x".into()),
            legit_task_ok: Some(true), latency_ms: 120, ttft_ms: 30, gen_tokens: 40, tok_per_s: 88.0,
            grammar_compile_ms: None, grammar_bytes: None,
        }
    }

    #[test]
    fn insert_and_read_round_trips() {
        let db = Db::open_in_memory().unwrap();
        db.insert_trial(&trial(Condition::StructuredOutputs)).unwrap();
        assert_eq!(db.all_trials().unwrap(), vec![trial(Condition::StructuredOutputs)]);
    }

    #[test]
    fn condition_string_round_trips_through_db() {
        let db = Db::open_in_memory().unwrap();
        db.insert_trial(&trial(Condition::GcdTight)).unwrap();
        assert_eq!(db.all_trials().unwrap()[0].condition, Condition::GcdTight);
    }
}
