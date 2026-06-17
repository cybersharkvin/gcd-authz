fn main() {
    // arg1: "bounded" (llama.cpp {0,N}) or "unbounded" (xgrammar `*`); default unbounded.
    let style = match std::env::args().nth(1).as_deref() {
        Some("bounded") => tantalus_grammar::FreeStringStyle::Bounded,
        _ => tantalus_grammar::FreeStringStyle::Unbounded,
    };
    let gbnf = tantalus_grammar::build_round2_gbnf(
        &tantalus_grammar::safe_fetch_urls(),
        &tantalus_grammar::player_channel_ids(),
        &tantalus_grammar::email_ids(),
        &tantalus_grammar::file_paths(),
        style,
    );
    print!("{gbnf}");
}
