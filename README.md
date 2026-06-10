# gcd-authz

**Grammar-Constrained Decoding as a positive, provable per-request authorization control for LLM agents.**

An LLM only emits text; every real-world effect is a downstream system executing that text. So the security boundary is the *emittable set itself*. By compiling the authenticated caller's authorization scope into a per-request grammar (`G_s`) and constraining the decoder to it, out-of-scope tool-call parameters become **ungenerable**:

```
output ∈ L(G_s) ⊆ Authorized(s)
```

This is the *application-allowlisting / parameterized-query* move applied to agent tool calls — a positive, structural control, different in kind from behavioral guardrails (defensive prompts, input classifiers, output filters).

This repository is the **paper-one artifact**: a self-contained, fully local (llama.cpp GBNF) experiment that ports **Galloway (2020), _Application Whitelisting as a Malicious Code Protection Control_** into the AI-agent domain — thousands of attacks against traditional AI guardrails (negative control) versus GCD/`G_s` (positive control), on a dual-tier business-banking back-office agent.

> **Scope (honest).** This artifact proves *action integrity* for structured tool-call parameters. It does **not** close *data confidentiality* through free-text fields (e.g. an email body) — that is the subject of follow-on work (a streaming embedding gate). See `docs/research/THESIS_2.md`.

## Status

Early scaffold. See `docs/PLAN.md` for the full plan and `docs/HANDOFF.md` for current state.

## Build

```bash
cargo build --workspace
cargo test --workspace
nix run .#experiment   # (planned) reproduce the experiment end-to-end
```

## Layout

- `crates/` — `bank-types`, `bank-env`, `bank-tools`, `bank-grammar` (the `G_s` compiler), `bank-llama`, `bank-pipeline`, `bank-defenses`
- `services/app` — the runnable dual-tier agent
- `harness/experiment` — the big-N evaluation harness (conditions × models × attacks)
- `docs/` — the plan, the handoff, and the research write-ups

## License

Dual-licensed under MIT or Apache-2.0.
