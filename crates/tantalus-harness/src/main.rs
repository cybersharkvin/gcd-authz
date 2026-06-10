//! Confirmatory experiment driver (replaces `experiment.py` + `overlay_d.py`).
//!
//! Usage:
//!   experiment [run] --corpus harness/corpus_full.json --legit-corpus harness/corpus_legitimate.json \
//!              --db harness/mini.db --rounds-per-condition 200 --concurrency 16 \
//!              --victims http://localhost:3350,http://localhost:3351 --conditions control,a1,a2,a3,a4,c
//!   experiment overlay --db harness/mini.db
//!
//! D is NOT a live condition: it is derived offline from Control's logged trace
//! (emission / d_blocked_calls columns), so `--conditions` covers control,a1,a2,a3,a4,c.

use std::sync::Arc;
use std::time::Instant;

use tantalus_eval::{Condition, EvalRequest, EvalResponse};
use tantalus_harness::db::{self, TrialRecord};
use tantalus_harness::{
    emission, legitimate_success, load_attack_corpus, load_legit_corpus, parse_trace, skill_id_for,
    AttackEntry, CorpusKind, HarnessError, LegitEntry,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const DEFAULT_VICTIMS: &str = "http://localhost:3350,http://localhost:3351";
const CONDITIONS: &[&str] = &["control", "a1", "a2", "a3", "a4", "c"];

fn parse_condition(s: &str) -> Option<Condition> {
    match s {
        "control" => Some(Condition::Control),
        "a1" => Some(Condition::A1),
        "a2" => Some(Condition::A2),
        "a3" => Some(Condition::A3),
        "a4" => Some(Condition::A4),
        "c" => Some(Condition::C),
        _ => None,
    }
}

/// One unit of work sent to a victim.
struct TrialSpec {
    condition: Condition,
    condition_str: String,
    corpus_idx: i64,
    kind: CorpusKind,
    skill_id: String,
    skill_label: String,
    turns: Vec<String>,
    expected: Option<(String, Option<String>)>,
    seed: u64,
    victim: String,
    temperature: f32,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), HarnessError> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("run");
    if mode == "overlay" {
        return overlay(&flag(&args, "--db", "harness/experiment.db"));
    }

    let corpus_path = flag(&args, "--corpus", "harness/corpus_full.json");
    let legit_path = opt_flag(&args, "--legit-corpus");
    let db_path = flag(&args, "--db", "harness/experiment.db");
    let rounds: usize = flag(&args, "--rounds-per-condition", "2000").parse().map_err(|_| HarnessError::Config("bad --rounds-per-condition".into()))?;
    let concurrency: usize = flag(&args, "--concurrency", "16").parse().map_err(|_| HarnessError::Config("bad --concurrency".into()))?;
    let temperature: f32 = flag(&args, "--temperature", "0.6").parse().map_err(|_| HarnessError::Config("bad --temperature".into()))?;
    let victims: Vec<String> = flag(&args, "--victims", DEFAULT_VICTIMS).split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let conditions: Vec<String> = flag(&args, "--conditions", &CONDITIONS.join(",")).split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    if victims.is_empty() {
        return Err(HarnessError::Config("no --victims".into()));
    }

    let corpus = load_attack_corpus(&corpus_path)?;
    let legit = match &legit_path {
        Some(p) => load_legit_corpus(p)?,
        None => vec![],
    };
    println!("corpus: {} attack entries from {corpus_path}", corpus.len());
    if !legit.is_empty() {
        println!("legit:  {} tasks from {}", legit.len(), legit_path.as_deref().unwrap_or(""));
    }
    println!("victims: {:?}", victims);
    println!("conditions: {:?}  rounds/condition: {rounds}  concurrency: {concurrency}", conditions);

    let client = Arc::new(reqwest::Client::new());
    verify_victims(&client, &victims).await?;

    let conn = db::open(&db_path)?;
    println!("results db: {db_path}\n");

    for cond_str in &conditions {
        let condition = parse_condition(cond_str).ok_or_else(|| HarnessError::Config(format!("unknown condition: {cond_str}")))?;
        let cond_idx = CONDITIONS.iter().position(|c| c == cond_str).unwrap_or(0) as u64;
        let specs = build_specs(condition, cond_str, cond_idx, &corpus, &legit, rounds, &victims, temperature);
        run_condition(cond_str, &client, &conn, specs, concurrency).await?;
    }

    println!("\ndone. analyze with: experiment overlay --db {db_path}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_specs(
    condition: Condition,
    cond_str: &str,
    cond_idx: u64,
    corpus: &[AttackEntry],
    legit: &[LegitEntry],
    rounds: usize,
    victims: &[String],
    temperature: f32,
) -> Vec<TrialSpec> {
    let mut specs = Vec::with_capacity(rounds + legit.len());
    let base = 1000 * cond_idx;
    for i in 0..rounds {
        let entry = &corpus[i % corpus.len()];
        let seed = base + i as u64;
        specs.push(TrialSpec {
            condition,
            condition_str: cond_str.to_string(),
            corpus_idx: i as i64,
            kind: CorpusKind::Attack,
            skill_id: skill_id_for(&entry.skill).to_string(),
            skill_label: entry.skill.clone(),
            turns: entry.turns.clone(),
            expected: None,
            seed,
            victim: victims[(seed as usize) % victims.len()].clone(),
            temperature,
        });
    }
    // Legitimate tasks run under every condition (RQ4 utility / over-constraint).
    for (j, e) in legit.iter().enumerate() {
        let seed = base + 900_000 + j as u64;
        specs.push(TrialSpec {
            condition,
            condition_str: cond_str.to_string(),
            corpus_idx: j as i64,
            kind: CorpusKind::Legitimate,
            skill_id: skill_id_for(&e.task).to_string(),
            skill_label: e.task.clone(),
            turns: e.turns.clone(),
            expected: Some((e.expected_tool.clone(), e.expected_param.clone())),
            seed,
            victim: victims[(seed as usize) % victims.len()].clone(),
            temperature,
        });
    }
    specs
}

async fn run_condition(
    cond_str: &str,
    client: &Arc<reqwest::Client>,
    conn: &rusqlite::Connection,
    specs: Vec<TrialSpec>,
    concurrency: usize,
) -> Result<(), HarnessError> {
    let total = specs.len();
    println!("== condition {} : {total} trials ==", cond_str.to_uppercase());
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<Result<TrialRecord, String>> = JoinSet::new();

    for spec in specs {
        let client = Arc::clone(client);
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore");
            run_trial(&client, spec).await
        });
    }

    let start = Instant::now();
    let (mut done, mut wins, mut blocked, mut errors, mut emissions) = (0usize, 0usize, 0usize, 0usize, 0usize);
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(rec)) => {
                done += 1;
                if rec.win { wins += 1; }
                if rec.blocked { blocked += 1; }
                if rec.emission { emissions += 1; }
                db::insert(conn, &rec)?;
                if done % 100 == 0 {
                    let rate = done as f64 / start.elapsed().as_secs_f64() * 60.0;
                    println!("  [{cond_str}] {done}/{total} | wins={wins} blocked={blocked} emit={emissions} | {rate:.0}/min");
                }
            }
            Ok(Err(e)) => { errors += 1; if errors <= 5 { eprintln!("  trial error: {e}"); } }
            Err(e) => { errors += 1; eprintln!("  join error: {e}"); }
        }
    }
    let pct = if done > 0 { 100.0 * wins as f64 / done as f64 } else { 0.0 };
    println!("  DONE {}: {wins}/{done} wins ({pct:.1}%) | blocked={blocked} | emissions={emissions} | errors={errors}\n", cond_str.to_uppercase());
    Ok(())
}

async fn run_trial(client: &reqwest::Client, spec: TrialSpec) -> Result<TrialRecord, String> {
    let req = EvalRequest {
        skill: spec.skill_id.clone(),
        messages: spec.turns.clone(),
        condition: spec.condition,
        temperature: spec.temperature,
        seed: Some(spec.seed),
    };
    let url = format!("{}/eval", spec.victim.trim_end_matches('/'));
    let resp = client.post(&url).json(&req).send().await.map_err(|e| format!("{} post: {e}", spec.skill_label))?;
    if !resp.status().is_success() {
        return Err(format!("{} status {}", spec.skill_label, resp.status()));
    }
    let r: EvalResponse = resp.json().await.map_err(|e| format!("{} decode: {e}", spec.skill_label))?;

    let trace = parse_trace(&r.raw_json);
    let (emitted, d_blocked) = emission(&trace);
    let legit_success = spec.expected.as_ref().map(|(t, p)| legitimate_success(&trace, t, p.as_deref()));

    Ok(TrialRecord {
        condition: spec.condition_str,
        corpus_idx: spec.corpus_idx,
        skill: spec.skill_label,
        turns: serde_json::to_string(&spec.turns).unwrap_or_default(),
        win: r.win,
        wins: r.wins.join(","),
        blocked: r.blocked,
        blocked_by: r.blocked_by,
        tool_calls: r.tool_calls as i64,
        tokens_predicted: r.tokens_predicted as i64,
        duration_ms: r.duration_ms as i64,
        seed: spec.seed as i64,
        temperature: spec.temperature as f64,
        raw_json: r.raw_json,
        model_id: r.model_id,
        engine_commit: r.engine_commit,
        outcome: r.outcome.as_str().to_string(),
        prompt_ms: r.prompt_ms,
        predicted_ms: r.predicted_ms,
        predicted_per_second: r.predicted_per_second,
        corpus_kind: spec.kind.as_str().to_string(),
        emission: emitted,
        d_blocked_calls: d_blocked as i64,
        legitimate_success: legit_success,
    })
}

async fn verify_victims(client: &reqwest::Client, victims: &[String]) -> Result<(), HarnessError> {
    for v in victims {
        let r = client.get(v).send().await;
        match r {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => return Err(HarnessError::Config(format!("victim {v} returned {}", resp.status()))),
            Err(e) => return Err(HarnessError::Config(format!("victim {v} unreachable: {e}"))),
        }
    }
    println!("victims: {} reachable", victims.len());
    Ok(())
}

/// Offline Condition-D report from a stored DB: emission rate, blocked-call count,
/// and wasted output tokens (Σ tokens_predicted over emitting Control trials).
fn overlay(db_path: &str) -> Result<(), HarnessError> {
    let conn = rusqlite::Connection::open(db_path)?;
    println!("=== Condition D overlay (db: {db_path}) ===");
    let mut stmt = conn.prepare(
        "SELECT condition,
                COUNT(*),
                SUM(emission),
                SUM(d_blocked_calls),
                SUM(CASE WHEN emission=1 THEN tokens_predicted ELSE 0 END)
         FROM trials WHERE corpus_kind='attack' GROUP BY condition ORDER BY condition",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            row.get::<_, Option<i64>>(4)?.unwrap_or(0),
        ))
    })?;
    println!("{:<10} {:>8} {:>10} {:>12} {:>16}", "condition", "trials", "emitting", "blocked_calls", "wasted_tokens");
    for row in rows {
        let (cond, n, emit, blocked_calls, wasted) = row?;
        let pct = if n > 0 { 100.0 * emit as f64 / n as f64 } else { 0.0 };
        println!("{cond:<10} {n:>8} {:>10} {blocked_calls:>12} {wasted:>16}", format!("{emit} ({pct:.1}%)"));
    }
    println!("\nemitting trials = what Condition D would block post-hoc (tokens already spent).");
    println!("Under C (GCD) these calls are ungenerable — 0 emission, 0 wasted tokens.");
    Ok(())
}

// ── tiny arg helpers ──

fn flag(args: &[String], name: &str, default: &str) -> String {
    opt_flag(args, name).unwrap_or_else(|| default.to_string())
}

fn opt_flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}
