//! The embedded attack corpus (the "malware samples"). Each `w*.json` file is a
//! JSON array of [`AttackCase`] for one win class; [`load_corpus`] parses and
//! validates them all.

use crate::contracts::{AttackCase, HarnessError};

const FILES: [&str; 5] = [
    include_str!("../data/corpus/w1.json"),
    include_str!("../data/corpus/w2.json"),
    include_str!("../data/corpus/w3.json"),
    include_str!("../data/corpus/w4.json"),
    include_str!("../data/corpus/w5.json"),
];

/// Parse and validate the whole embedded corpus.
pub fn load_corpus() -> Result<Vec<AttackCase>, HarnessError> {
    let mut all = Vec::new();
    for raw in FILES {
        let cases: Vec<AttackCase> = serde_json::from_str(raw)
            .map_err(|e| HarnessError::Phase { phase: "corpus-parse".into(), detail: e.to_string() })?;
        for case in cases {
            case.validate()?;
            all.push(case);
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::AttackStage;
    use bank_types::WinConditionId;
    use std::collections::BTreeSet;

    #[test]
    fn corpus_loads_and_validates() {
        assert!(load_corpus().is_ok());
    }

    #[test]
    fn corpus_is_non_trivial() {
        assert!(load_corpus().unwrap().len() >= 20);
    }

    #[test]
    fn corpus_covers_all_five_win_classes() {
        let wins: BTreeSet<WinConditionId> = load_corpus().unwrap().iter().map(|c| c.win).collect();
        assert_eq!(wins.len(), WinConditionId::ALL.len());
    }

    #[test]
    fn corpus_covers_all_three_stages() {
        let stages: BTreeSet<_> = load_corpus().unwrap().iter().map(|c| format!("{:?}", c.stage)).collect();
        assert!(stages.contains(&format!("{:?}", AttackStage::Direct))
            && stages.contains(&format!("{:?}", AttackStage::SecondOrder))
            && stages.contains(&format!("{:?}", AttackStage::Adaptive)));
    }
}
