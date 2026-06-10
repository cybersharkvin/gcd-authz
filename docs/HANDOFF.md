# HANDOFF — gcd-authz

Bridge doc so a fresh Claude session (run from this directory) picks up exactly where the planning session left off. The planning conversation happened in the `tantalus` project; this repo was split out with its own git history.

## Where we are (2026-06-06)

- **Plan approved.** Full approved plan: `docs/PLAN.md`. Read it fully — it is the source of truth.
- **Repo scaffolded.** Cargo workspace + flake skeleton + fresh `CLAUDE.md` + research docs copied into `docs/research/`. Crates are compiling stubs (no real logic yet). First commit made.
- **Nothing of the actual artifact is implemented yet.** The stubs exist only so the workspace builds.

## How we got here (context a fresh session won't have)

1. Goal: a credibility artifact (arXiv preprint) for a Capitol Tech Offensive-Cyber-Engineering PhD approach, extending **Galloway (2020)** into AI agents.
2. The plan was **adversarially red-teamed**. Key fixes already folded into `docs/PLAN.md` — keep them:
   - Don't claim "JSON Schema can't express it" (refutable via per-request `anyOf`/`const` and local `json_schema_to_grammar` min/max). The durable claim is the **paradigm** (positive/structural vs detective/behavioral) and **Structured Outputs constrain shape, not authorization**.
   - Don't claim "ungenerable at the decoder" is the *sole* boundary while an executor re-check exists. Frame the executor check as the backstop; it also closes the **beneficiary-mutation / TOCTOU** laundering path (data-derived AuthScope fields are mutable; re-validate at execution time).
   - Big-N corpus (Galloway-style thousands), not k=30. Formal proof carries "impossible"; empirics show guardrails leak at scale.
   - Structural conditions are **model-invariant by construction**; vary models cross-family only for the behavioral baseline (A) and utility/reachability.
   - Add a **utility metric** (does `G_s` break legitimate transfers?). Demote W5 (structured-`reference` exfil) to a limitation, not a headline (free-text body is the real channel → paper 2).
   - MTP **off** for the experiment; tokenizer/grammar alignment is a **go/no-go gate**; an independent CFG engine (llguidance/Outlines/XGrammar) is the correctness oracle.

## Immediate next step

**Build step 0 — Galloway calibration**, then **step 1 — bank-types**:

- Step 0: extract the methodology from `docs/research/Application_Whitelisting_..._Galloway.pdf` (PDF has no text layer here — extract via Python zlib over FlateDecode streams; sibling extraction worked for the Amaral PDF). Pull: sample size, detection-vs-block measurement, results-table format, the positive-vs-negative argument. Mirror its structure. Pre-register attack classes / N / overhead envelope.
- Step 1: implement `crates/bank-types` for real per `docs/PLAN.md` → "Strongly-typed data contracts": the newtypes, `AuthScope` + `AuthScope::build` validation, `ToolParams`/`ToolCall`, `WinConditionId`, error types. Unit-test the validators.

Then follow the build sequence in `docs/PLAN.md` (steps 2→8). Reference (read-only) the Tantalus source for the reuse patterns:
`/REDACTED/stuffs/things/tantalus/tantalus-rs/` — esp. `crates/tantalus-types/src/ids.rs` (newtype pattern), `crates/tantalus-pipeline/src/{lib.rs,embed.rs,wins.rs}` (InferenceStep trait, reqwest client, Observer), `crates/tantalus-grammar/src/lib.rs` (dynamic-enum schema builder to generalize).

## Reproducibility reminders
Local-only. No cloud. Pin model weights by hash + llama.cpp fork commit (or stock GGUF for the public artifact). `nix run .#experiment` is the target.
