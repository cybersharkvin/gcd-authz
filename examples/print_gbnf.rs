fn main() {
    // arg1: "bounded" | "unbounded" (free-string style) | "l2_guided" (the GCD ladder L2
    // closed-response grammar, loads CRESP_CORPUS / harness/cresp/corpus.json). Default unbounded.
    // ("closed" still accepted as the old alias for l2_guided.)
    let arg = std::env::args().nth(1).unwrap_or_default();
    let gbnf = if arg == "l2_guided" || arg == "closed" {
        let path = std::env::var("CRESP_CORPUS").unwrap_or_else(|_| "harness/cresp/corpus.json".into());
        let data = std::fs::read_to_string(&path).expect("read CRESP_CORPUS");
        let v: serde_json::Value = serde_json::from_str(&data).expect("parse corpus");
        let responses: Vec<String> = v.as_array().unwrap().iter()
            .flat_map(|e| e["responses"].as_array().cloned().unwrap_or_default())
            .filter_map(|r| r.as_str().map(String::from)).collect();
        let refs: Vec<&str> = responses.iter().map(|s| s.as_str()).collect();
        tantalus_grammar::build_l2_guided_gbnf(
            &tantalus_grammar::safe_fetch_urls(), &tantalus_grammar::player_channel_ids(),
            &tantalus_grammar::email_ids(), &tantalus_grammar::file_paths(),
            &refs, tantalus_grammar::FreeStringStyle::Unbounded,
        )
    } else {
        let style = if arg == "bounded" { tantalus_grammar::FreeStringStyle::Bounded } else { tantalus_grammar::FreeStringStyle::Unbounded };
        tantalus_grammar::build_round2_gbnf(
            &tantalus_grammar::safe_fetch_urls(), &tantalus_grammar::player_channel_ids(),
            &tantalus_grammar::email_ids(), &tantalus_grammar::file_paths(), style,
        )
    };
    print!("{gbnf}");
}
