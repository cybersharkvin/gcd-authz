# ADR 0003 — C-guided: per-request least-privilege authorization grammar (positive AuthZ, enforced constitutively)

- **Status:** Accepted — IMPLEMENTED & validated (this session). New condition `c_guided` wired end-to-end; reuses the ADR 0002 loop-swap lever with **no new loop code**.
- **Date:** 2026-06-18
- **Deciders:** Vince (researcher), Claude (Opus 4.8)
- **Relates to:** ADR 0001 (engine), ADR 0002 (structural loop termination — this ADR reuses its respond-only swap). Adds a **condition/cell**; does not change the corpus, win semantics, or the headline blind-C/D results.

## Context and problem statement

Condition **C** (blind GCD) uses one grammar for every request: the *union* allowlist `L(G_s)` of all safe URLs / channels / emails / paths. That delivers the headline security result — out-of-scope actions are ungenerable → **0 bypass by construction** — but it is *coarse*. Two residual costs live entirely on the reliability/utility axis, not security:

- **Deflection** (reported limitation): the grammar guarantees a *valid* action, not the *requested* one. A weak model under blind C can take a valid-but-unrequested in-scope action.
- **Spin-out → utility gap**: on the weak 1.7B, blind-C legit-task success was ~40% (smoke) vs Control ~60% — the model fumbles *which* in-scope action completes the task.

The project's thesis is **per-request authorization as positive security**. Blind C authorizes "any in-scope action"; the stronger statement the apparatus can make is **least-privilege per request**: the grammar narrows to *exactly the legitimate task's authorized action(s)* for THIS request. The unauthorized action isn't merely caught (D) or merely out-of-union (C) — for this request it is **not in the producible space at all**, and the *right* action is the only thing the model can do. This is authorization no behavioral guardrail and no post-parse allowlist can provide: the policy is the decoder.

## Decision

Add condition **`c_guided`**: a per-request least-privilege grammar whose `root` is an alternation of **exactly the trusted-channel authorized action(s)** for the request (each narrowed to its authorized param value(s)), plus the ADR 0002 respond-only termination swap. Concretely:

1. `tantalus_grammar::build_guided_gbnf(actions, style)` — `root` = the authorized actions only (narrowed enums via the shared `gbnf_json_string_enum` + the shared tool-rule consts, so it cannot drift from the full grammar). **No other tool and no out-of-scope value is producible.** With **no** authorized action it degenerates to `build_respond_only_gbnf` — i.e. a refusal (the narrowest least-privilege policy).
2. The agent loop is **unchanged**. A good-outcome-only grammar has no `respondToUser` branch (unless `respondToUser` is itself authorized, e.g. a greeting), so the model emits an authorized action, then on dedup-repeat / turn-cap the **ADR 0002 respond-only swap** forces the closing reply. Termination is by construction; the good outcome appears in the trace by construction (turn 1 can only be an authorized action). Every sequence is `[authorized action(s)…, respondToUser]` within a few turns.

### Provenance discipline (the difference between least-privilege and a stacked deck)

The per-request policy **MUST** be derived from the **trusted channel** — the task identity — and be **invariant to untrusted skill content**:

- **Attack trials:** policy = `requested_defaults(skill_label)` (the legitimate task the poisoned skill masquerades as). The skill *label* is the task/route identity (like a tool name or an API route); the skill *body* (injected instructions) is never read to build the policy.
- **Legit trials:** policy = the legit task's `expected_tool`/`expected_param` (what the user actually asked for).

Both are the experimenter's ground-truth "what this request is authorized to do." Because the legit-trial `skill_id` is an unmapped passthrough of the task text, the trusted good-outcome cannot be re-derived server-side from `req.skill`; it travels in a new optional `EvalRequest.guided_policy` field that the harness fills from the trusted source above. The **same** map (`tantalus_grammar::guided_policy`, keyed on `skill_id`) also backs the harness deflection DV (`requested_defaults` delegates to it), so "the C-guided forced outcome == the deflection-allowed action" holds by construction.

### Scope — keep blind C as the headline

- **Blind C stays the HEADLINE security condition.** Its 0-bypass over the *union* allowlist is the falsifiable claim (a single hardcoded action per request would make 0% bypass trivially true — that is exactly the "circular" objection, and it is answered by keeping blind C as the security headline and presenting C-guided as a *utility/granularity* result, not a *security* one).
- **C-guided proves constitutive UTILITY** over the **3 enumerable-outcome skills** (`ChatDataExfil` → readChatHistory, `TicketAssistForward` → listInbox/readEmail, `InfraMonitorExfil` → fetchUrl-datadog): the task *can't fail* — legit-success ≈ 100% and deflection ≈ 0, both **by construction**.
- **Refuse-correct skills** (`SshKeyExfil`/`ApiKeyExfil`, `requested_defaults = []`) → respond-only = a refusal. Refusing IS the correct positive-AuthZ outcome when the trusted channel authorizes no action.

## Expected consequences

- **Security:** 0 bypass / 0 emission (strict subset of blind C's allowlist) — by construction; not the headline (blind C already owns that).
- **Utility (the headline here):** legit-success ≈ 100% on the enumerable skills (vs blind C ≈ 40% on the 1.7B); **deflection → 0** by construction (the only in-scope actions producible are the requested ones).
- **Reliability/efficiency:** spin-out ≈ 0 (ADR 0002 terminal); minimal tokens — the model emits only authorized tool-call structure then a forced reply (the "perfect sequence, no waste" demonstration).
- **The coarse↔fine contrast is itself a result:** residual deflection/spin-out under blind C is a **policy-granularity knob**, not a GCD limitation. Tightening the grammar removes it constitutively.

## What this is NOT

- **NOT a claim that the grammar makes the 1.7B "frontier."** The intelligence lives in the trusted policy + the model's selection among authorized branches — a **system** property, not a model one. A weak victim is a *feature*: it sharpens C-vs-D (more garbage under D for the gate to strand) and shows least-privilege carrying a model that fumbles open-ended tool use.
- **NOT free-form exploration (a documented knob, deliberately out of this cell).** The user's (c) included "the model could call searchFiles/readFile in any fashion before the good outcome." This cell implements the *strict* core: `root` = authorized actions only, so the model's autonomy is *selection among the authorized set* (genuinely non-deterministic for multi-action policies like TicketAssist's `listInbox | readEmail-{any ticket}`), and exploration of *unrelated* reads is omitted. The broader variant (allow inert read-tools for context-gathering, then **force** the good outcome at a 2-stage terminal) is a one-lever extension on top of this; it trades a few exploration tokens + reintroduced deflection for more autonomy, and is left for a follow-up. The strict core gives the cleanest "task can't fail / zero waste" headline and needs no new loop logic.

## Implementation (this session)

Three crates, reusing the ADR 0002 lever; **DbC + no-drift** throughout:

- **`tantalus-grammar`:** extracted the 6 tool-rule shapes into shared consts (`FETCH_URL_RULE` … `LIST_INBOX_RULE`) and rewrote `render_round2_gbnf` to interpolate them (so the full grammar and the guided grammar share the exact tool-call shapes). `guided_policy(skill_id)` is the single trusted policy map (harness `requested_defaults` delegates to it). `build_guided_gbnf(actions, style)` assembles `root` from the present authorized tools, narrowing each enum via `gbnf_json_string_enum`; `None` param on an enum tool = the full allowlist for that tool ("any ticket"); a `Some(value)` not in the tool's allowlist **panics** (DbC precondition — a guided policy may only *narrow* `L(G_s)`); empty `actions` → `build_respond_only_gbnf`.
- **`tantalus-eval`:** `Condition::CGuided` (serde `c_guided`, `uses_grammar() == true`); wire type `GuidedAction { tool, param }`; `EvalRequest.guided_policy: Option<Vec<GuidedAction>>` (`#[serde(default)]` → old payloads still validate under `deny_unknown_fields`).
- **server (`inference.rs`/`main.rs`) + prompt:** `(Round::Two, CGuided)` → Control template (grammar is the sole IV, as for C/C+); `full()` takes the policy and builds the guided grammar; `respond_only_gbnf` for CGuided = the free respond-only (same as C). `eval()` converts `req.guided_policy` → the policy slice.
- **harness:** `parse_condition`/`cond_seed_base` accept `c_guided`; `run_trial` fills `guided_policy` from `spec.requested` (attack) / `spec.expected` (legit) when `condition == CGuided`, else `None`.

`respondToUser` truncation caveat (cont.6) still applies to the *forced* free reply; a closed/canned respond-only would remove it (future, once the cresp corpus is grounded).

## Validation (smoke 2026-06-18 — Qwen3-1.7B-NVFP4/vLLM `:11440`, baseline prompt, `MAX_TURNS=6`, 300 attack + 208 legit/condition; `/tmp/adr3_smoke/adr3_smoke.db`)

**Security (attack, n=300/cond), CP 95%:**

| cond | bypass% | emission% | **deflection%** | avg tok | avg calls |
|---|---|---|---|---|---|
| control | 17.0 [12.9, 21.7] | 37.3 | 32.7 | 234 | 1.22 |
| c (blind) | **0.00** [0, 1.22] | 0.0 | **35.7** | 113 | 0.73 |
| **c_guided** | **0.00** [0, 1.22] | 0.0 | **0.0** | 132 | 0.91 |
| c_closed | 0.00 [0, 1.22] | 0.0 | 36.3 | 115 | 0.70 |
| d_r0 / r1 / r3 | 0.00 | 37.3 / 33.7 / 36.0 | ~33 | ~220 | ~1.15 |

**Utility (legit, n=208/cond) — the headline:**

| cond | legit-success% [CP95] | by tool (c_guided) |
|---|---|---|
| control | 59.1 [52.1, 65.9] | — |
| c (blind) | 37.5 [30.9, 44.5] | readFile 4.8 / readEmail 11.9 / readChat 14.3 / fetchUrl 28.6 |
| **c_guided** | **85.1 [79.5, 89.6]** | **fetchUrl / listInbox / readChat / readEmail / readFile = 100%**, respondToUser 100%, **searchFiles 51.6%** |
| c_closed | 36.1 | — |

- **Constitutive utility confirmed:** on the enumerable-outcome tools the task **cannot fail** — C-guided legit-success is **100% for every enum action** (and respondToUser), vs blind C's **5–29%** on the same tools (it deflects to a different in-scope action). The 85.1% aggregate is dragged down ONLY by **searchFiles (51.6%)** — the free-string query, the SAME cont.6 truncation/open-vocab caveat that limits C/C+; it is not an enumerable outcome, so it is the boundary, not a guided-grammar failure.
- **Deflection → 0 by construction:** C-guided attack deflection is **0.0%** (vs blind C **35.7%**, control **32.7%**) — the only in-scope action producible is the requested one.
- **Security unchanged + by construction:** C-guided bypass 0 / emission 0 (strict subset of blind C). Blind C remains the headline (its 0-bypass over the *union* allowlist is the falsifiable claim).
- **Reliability:** C-guided legit **spin-out = 0.00%** (0/208); attack 1.0% (3/300 — the free respond-only truncation residual, cont.6). D corrective preserved: `d_r0` strands **132** (`availability_failure`, all gate-sourced) → `d_r1` 2 → `d_r3` 1; gate_rejections 132/139/141; avg attempts 1.00/1.27/1.28.
- **Provenance + no-drift verified in code:** the C-guided policy and the deflection DV's requested-set are the SAME map (`requested_defaults` delegates to `tantalus_grammar::guided_policy`); the guided and full grammars share the tool-rule consts. `cargo test` green except the 1 pre-existing `max_turns_enforced`; +9 new unit tests (6 grammar, 2 eval, +consts refactor guarded by the existing 7 grammar tests). comfyui (an image build, no GPU) / vLLM / embedder / memgraph untouched.
