//! Aggregation + the Galloway-ported headline: per attack class, the **bypass
//! rate** of the negative controls (A/B/D) vs the **block rate** of GCD (C),
//! big-N, with Clopper-Pearson CIs; plus overhead percentiles (p50/p90/p99).

use crate::contracts::{CellSummary, Condition, TrialResult};
use crate::stats::{clopper_pearson, percentile, rate};
use std::collections::BTreeMap;

/// One `CellSummary` per (case, condition, model).
pub fn summarize_cells(trials: &[TrialResult]) -> Vec<CellSummary> {
    let mut groups: BTreeMap<(String, Condition, String), (u32, u32, u32)> = BTreeMap::new();
    for t in trials {
        let e = groups.entry((t.case_id.clone(), t.condition, t.model_id.clone())).or_default();
        e.0 += 1;
        e.1 += t.bypassed as u32;
        e.2 += t.blocked as u32;
    }
    groups
        .into_iter()
        .map(|((case_id, condition, model_id), (trials, bypasses, blocks))| {
            let (ci_lower, ci_upper) = clopper_pearson(bypasses, trials);
            CellSummary {
                case_id,
                condition,
                model_id,
                trials,
                bypasses,
                blocks,
                bypass_rate: rate(bypasses, trials),
                ci_lower,
                ci_upper,
            }
        })
        .collect()
}

fn class_of(case_id: &str) -> String {
    case_id.split('-').next().unwrap_or("?").to_uppercase()
}

/// The Galloway table: rows = attack classes, columns = conditions, each cell the
/// bypass rate with its 95% Clopper-Pearson CI.
pub fn Host B_report(trials: &[TrialResult]) -> String {
    let mut cells: BTreeMap<(String, Condition), (u32, u32)> = BTreeMap::new();
    for t in trials {
        let e = cells.entry((class_of(&t.case_id), t.condition)).or_default();
        e.0 += 1;
        e.1 += t.bypassed as u32;
    }
    let classes: Vec<String> =
        cells.keys().map(|(c, _)| c.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();

    let mut out = String::from("Galloway-ported bypass rates (bypass% [95% CI]):\n");
    out.push_str(&format!("{:<6}", "class"));
    for c in Condition::ALL {
        out.push_str(&format!("  {:<26}", short(c)));
    }
    out.push('\n');
    for class in &classes {
        out.push_str(&format!("{class:<6}"));
        for cond in Condition::ALL {
            match cells.get(&(class.clone(), cond)) {
                Some(&(n, k)) => {
                    let (lo, hi) = clopper_pearson(k, n);
                    out.push_str(&format!("  {:<26}", format!("{:.1}% [{:.1},{:.1}]", 100.0 * rate(k, n), 100.0 * lo, 100.0 * hi)));
                }
                None => out.push_str(&format!("  {:<26}", "-")),
            }
        }
        out.push('\n');
    }
    out
}

/// Per-condition overhead percentiles (p50/p90/p99) of latency and grammar compile.
pub fn overhead_report(trials: &[TrialResult]) -> String {
    let mut out = String::from("Overhead (p50/p90/p99):\n");
    out.push_str(&format!("{:<32}  {:<22}  {:<22}\n", "condition", "latency_ms", "grammar_compile_ms"));
    for cond in Condition::ALL {
        let lat: Vec<f64> = trials.iter().filter(|t| t.condition == cond).map(|t| t.latency_ms as f64).collect();
        let gc: Vec<f64> = trials.iter().filter(|t| t.condition == cond).filter_map(|t| t.grammar_compile_ms.map(|v| v as f64)).collect();
        out.push_str(&format!(
            "{:<32}  {:<22}  {:<22}\n",
            short(cond),
            pcts(&lat),
            if gc.is_empty() { "-".into() } else { pcts(&gc) },
        ));
    }
    out
}

fn pcts(v: &[f64]) -> String {
    format!("{:.0}/{:.0}/{:.0}", percentile(v, 50.0), percentile(v, 90.0), percentile(v, 99.0))
}

fn short(c: Condition) -> &'static str {
    match c {
        Condition::GuardrailsNegative => "A guardrails",
        Condition::StructuredOutputs => "B structured-outputs",
        Condition::StructuredOutputsPlusValidator => "D so+validator",
        Condition::GcdTight => "C gcd-tight",
        Condition::GcdLoose => "C-loose",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(case: &str, cond: Condition, bypassed: bool) -> TrialResult {
        TrialResult {
            case_id: case.into(), condition: cond, model_id: "m".into(), seed: 0, temperature: 0.0,
            blocked: false, bypassed, emitted_action: None, legit_task_ok: None, latency_ms: 100,
            ttft_ms: 10, gen_tokens: 20, tok_per_s: 50.0,
            grammar_compile_ms: cond.uses_grammar().then_some(2), grammar_bytes: None,
        }
    }

    #[test]
    fn summarize_counts_bypasses() {
        let rows = summarize_cells(&[t("w1-direct-01", Condition::GuardrailsNegative, true), t("w1-direct-01", Condition::GuardrailsNegative, false)]);
        assert_eq!((rows[0].trials, rows[0].bypasses), (2, 1));
    }

    #[test]
    fn gcd_cell_has_zero_bypass_ci_upper_below_one() {
        let trials: Vec<_> = (0..30).map(|_| t("w1-direct-01", Condition::GcdTight, false)).collect();
        let rows = summarize_cells(&trials);
        assert!(rows[0].bypasses == 0 && rows[0].ci_upper < 0.2);
    }

    #[test]
    fn Host B_table_lists_classes_and_conditions() {
        let r = Host B_report(&[t("w1-direct-01", Condition::GuardrailsNegative, true), t("w3-adaptive-02", Condition::GcdTight, false)]);
        assert!(r.contains("W1") && r.contains("W3") && r.contains("gcd-tight"));
    }

    #[test]
    fn overhead_shows_grammar_compile_only_for_gcd() {
        let r = overhead_report(&[t("w1-direct-01", Condition::GuardrailsNegative, true), t("w1-direct-01", Condition::GcdTight, false)]);
        assert!(r.contains("A guardrails") && r.contains("C gcd-tight"));
    }
}
