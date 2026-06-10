//! `bank-experiment` CLI.
//!
//! Subcommands:
//!   corpus  — load + validate the embedded attack corpus and print its size
//!   oracle  — run the `G_s` correctness oracle against llama.cpp's GBNF parser
//!   dryrun  — synthetic trials → SQLite → Galloway report (no model needed)
//!   run     — the live matrix (Phase B; needs LLAMA_URL + model registry)

use bank_experiment::{corpus, db::Db, driver, oracle, report};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "corpus" => {
            let cases = corpus::load_corpus()?;
            println!("loaded {} attack cases (W1-W5 × {{direct, second_order, adaptive}})", cases.len());
        }
        "oracle" => {
            print!("{}", oracle::run_oracle()?);
            println!("oracle: PASS");
        }
        "dryrun" => {
            let trials = driver::synthetic_trials(30);
            let db = Db::open_in_memory()?;
            for t in &trials {
                db.insert_trial(t)?;
            }
            let loaded = db.all_trials()?;
            println!("{} synthetic trials → SQLite → {} rows\n", trials.len(), loaded.len());
            println!("{}", report::Host B_report(&loaded));
            println!("{}", report::overhead_report(&loaded));
        }
        "run" => {
            eprintln!("`run` is the live matrix (Phase B): set LLAMA_URL, launch the model registry, then run.");
        }
        _ => {
            eprintln!("usage: bank-experiment [corpus|oracle|dryrun|run]");
        }
    }
    Ok(())
}
