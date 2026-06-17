# ADR 0002 — Agent-loop termination is enforced structurally (forced `respondToUser`), not by prompt engineering

- **Status:** Accepted (decision). The `build_respond_only_gbnf` + loop-forcing **implementation is a tracked follow-up — not yet built.** The supporting prompt bake-off is done; the baseline system prompt is **retained unchanged** as a result of this ADR.
- **Date:** 2026-06-17
- **Deciders:** Vince (researcher), Claude (Opus 4.8)
- **Relates to:** ADR 0001 (engine). Does **not** change the experiment design, win semantics, corpus, or the security/emission DVs. Concerns the **reliability/availability** axis only.

## Context and problem statement

On the primary victim (weak Qwen3-1.7B-NVFP4 / vLLM) the agent loop **loops and strands** on the grammar (GCD) arms. Measured on the grammar condition `c` (500 attack trials each, `MAX_TURNS=6`):

| prompt | ended with NO reply (spun out) | hit the 6-turn cap | repeated a call 5–6× |
|---|---|---|---|
| **baseline** | **22.8 %** | 36.4 % | 33 % |

Mechanism (confirmed by reading `raw_json`): under a GCD grammar **there is no "emit plain text and stop" — the only turn-ending action is `respondToUser`.** A weak model that does not "realize" it already has a tool's result has no *legal* move except another tool call, so it re-emits the same call until `MAX_TURNS`. The loop's existing mitigations are **behavioral and fail**: a dedup guard injects "you already called this — call respondToUser now" (`lib.rs:365`) which the 1.7B ignores, and at the cap the loop simply `return`s with **no reply** (`lib.rs:393`). The grammar is also **static for the whole trial** (`inference.rs` builds `gbnf` once and reuses it every turn) — the one lever that is entirely ours is unused.

This is contained (every repeat is in-scope, dedup-skipped, capped → **never a wrong or unsafe action**; it is a reliability dent, not a security one) but on the baseline prompt ~1 in 4 GCD trials returns nothing to the user.

## What we tried first (and why we rejected it)

Three rounds of metaprompt-authored system prompts, each measured on the real victim (the `CONTROL_TEMPLATE` env-override from commit `5e5c17a` made this a rebuild-free A/B):

- **Round 1 (aggressive, "use your tools"):** made looping *worse* — baseline 45 % → 68–92 %. Pushing tool-use backfires when there is no stop signal.
- **Round 2 (inverted: "terminate-eager"):** the example-driven candidate **F** beat baseline — grammar-arm loop 45 → 31 %, legit-task success 36 → 55 %, spin-out 22.8 → 2.2 % — and confirmed *examples beat rules* for this model.
- **Round 3 (climb past F):** **no clean win.** Every candidate that fixed one weakness broke another; the minimal-engagement candidate posted 5 % loop only by **doing nothing** (legit cratered to 27 % — caught by the legit-success guard). The data revealed an **intrinsic loop↔legit tradeoff** through tool-engagement: a Pareto frontier, not a hill.

Two decisive problems with the prompt route: (1) prompting **cannot reliably reach 0 spin-out** (best, F, was ~2 %, on the back of a model-specific tradeoff); (2) **every prompt shifts attack potency** (Control bypass swung 20 % → 25–35 % across candidates), which would **force a re-baseline of the canonical 100k matrices**. Fighting a *structural* reliability failure with a *behavioral* tool is exactly the anti-pattern this project exists to refute.

## Decision

**Enforce agent-loop termination structurally, at the decoder, and keep the baseline system prompt unchanged.**

1. Add `tantalus_grammar::build_respond_only_gbnf(message_rhs)` — a grammar whose **only** production is the `respondToUser` branch (reusing the existing `message-string` rule; free-string for C, canned alternation for C+).
2. The agent loop **swaps to this grammar for a single turn** when (a) a dedup-repeat is detected, and (b) the turn budget is about to be exhausted with no `respondToUser` yet. For the non-grammar arms the equivalent is forcing `tool_choice: {function: respondToUser}`. Either way the model **cannot emit anything but a reply** → spin-out = 0 **by construction**.
3. **Do not adopt any bake-off prompt.** Keep the baseline prompt → no potency shift → no re-baseline. Retain the `CONTROL_TEMPLATE` override + the F prompt as evidence/tooling, not as the shipped prompt.

This is ADR 0001's thesis applied to the loop itself: **constitutive (ungenerable-otherwise) beats behavioral (asking nicely).** The dedup retry-message is behavioral and fails; a one-turn respond-only grammar is constitutive and cannot.

## Expected consequences

- **Spin-out (looping availability-failure) → ~0** on the grammar arms, on the *baseline* prompt — vs 22.8 % today, 2.2 % under the best prompt. The cap-hit and 5–6× repeat tails collapse with it.
- **Reliability/validity gain, not security.** `respondToUser` is not an exfil sink; the allowed action set is unchanged. Forcing a reply may *slightly lower* Control bypass (fewer residual attack turns) — to be measured, not assumed, as the one guardrail.
- **A guaranteed reply is not a guaranteed *good* reply.** A stuck model forced to respond emits "I wasn't able to complete that" — which is the **correct availability behavior** and strictly beats silence.
- **Interacts with live-D `availability_failure` semantics:** forcing a terminal `respondToUser` converts gate-strandings into replies. We must decide whether D's availability cost is counted on the *desired (out-of-scope) action it was denied* rather than on the forced fallback, so the structural-termination guarantee does not mask D's corrective cost. **Tracked — resolve before the next live-D run.**
- The three prompt rounds are retained as evidence: they *proved* prompting cannot do this reliably and *mapped* the loop↔legit frontier (F = the knee).

## Evidence (measured 2026-06-17, Qwen3-1.7B-NVFP4 / vLLM, grammar arm `c`, 500 attack + 208 legit trials/candidate)

| prompt | spin-out (no reply) | loop% (≥1 repeat) | legit-success% | Control bypass% |
|---|---|---|---|---|
| baseline | 22.8 | 45 | 36 | 20 |
| F (best terminate-eager) | 2.2 | 31 | 55 | 26 |
| G/H/I (round 3) | — | 5–69 | 27–60 | 16–35 |

Reproducible: baseline and F re-measured across two independent runs within ±2 pp. The legit-success guard (208 tasks/condition) is what disqualified the do-nothing candidate (H: 5 % loop / 27 % legit). Bake-off DBs were ephemeral (`/tmp/promptbake/`); the durable artifacts are the `CONTROL_TEMPLATE` mechanism (`5e5c17a`) and this ADR.
