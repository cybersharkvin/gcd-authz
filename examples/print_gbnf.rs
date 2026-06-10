fn main() {
    let gbnf = tantalus_grammar::build_round2_gbnf(
        &tantalus_grammar::safe_fetch_urls(),
        &tantalus_grammar::player_channel_ids(),
        &tantalus_grammar::email_ids(),
        &tantalus_grammar::file_paths(),
    );
    print!("{gbnf}");
}
