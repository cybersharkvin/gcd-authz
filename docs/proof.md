# Soundness of Grammar-Constrained Decoding as a Positive Authorization Control

**Companion artifact to the paper's §"Formal Core"** (`paper/sections/formal.tex`) and to
`docs/research/RESEARCH_DESIGN.md` §3. This document promotes the paper's *sketch* to a full
argument: it makes the for-all-logit mask-soundness lemma first-class, gives the tokenizer-lift a
precise statement and discharge, and turns the three §3.5 implementation caveats into explicit,
named obligations with the conditions under which each is met. It is a careful hand proof, not a
machine-checked one; the boundary between *what is proven* and *what is assumed/discharged
operationally* is stated explicitly throughout.

The whole point of the theorem is a **class-level** guarantee — a statement about *every*
producible output of the mechanism — which no finite sample, however large, can establish. It is
the one asset that licenses an "out-of-scope actions are *ungenerable*" claim rather than merely a
"not-yet-observed" claim. We are correspondingly strict about its scope and its trusted computing
base (TCB).

---

## 0. What is and is not claimed

- **Claimed (proven below, conditional on the named assumptions):** for an authenticated principal
  with scope `s`, *every* completed generation of the constrained decoder lies in the authorized
  action set `Authorized(s)`, **for any logit distributions the model produces and any of the
  standard samplers** — hence including a model whose logits have been fully driven by prompt
  injection.
- **Assumed (the TCB) and discharged operationally, not proven:** (A1) the compiler emits a
  grammar whose language is contained in the authorized set; (A2) the character→token lift is
  sound; (A3) the grammar is non-blocking (progress). Each is named, and the operational discharge
  (acceptance oracle, executor backstop, construction discipline) is described.
- **Explicitly *not* claimed:** semantic safety/wisdom of an authorized action; confidentiality
  through *unconstrained free-text* parameters; population-level universality across all agent
  architectures (the realization is single-subject — Tantalus — so this is a feasibility result for
  the covered class). These are stated in §6.

Proof and empirical evidence stay in **separate lanes** (§7): the theorem carries the
"eliminates-by-construction" claim; the experiments show that behavioral controls *leak* at scale
and that the *implementation* matches the theory.

---

## 1. Setup and definitions

Fix a tokenizer with finite **vocabulary** `V` and a distinguished end-of-sequence token
`EOS ∉ V`. A **generation** is a finite token sequence `t₁ t₂ ⋯ t_n ∈ V*`, optionally terminated
by `EOS`.

**Spelling and decode.** Each token `t ∈ V` has a fixed character spelling `σ(t) ∈ Σ*` over a
character alphabet `Σ`. The **decode homomorphism** `δ : V* → Σ*` is concatenation of spellings,
`δ(t₁ ⋯ t_n) = σ(t₁) · σ(t₂) · ⋯ · σ(t_n)`. (BPE/byte-level tokenizers are of this form; `δ` is a
monoid homomorphism from `(V*, ·, ε)` to `(Σ*, ·, ε)`.)

**Authorization.** For principal scope `s`, let `Authorizedᶜ(s) ⊆ Σ*` be the set of **character
strings** whose decoded action is permitted for `s` (authorized accounts, endpoints, channels,
paths, identifiers; out-of-scope parameters absent). Lift to tokens:
`Authorized(s) = { w ∈ V* : δ(w) ∈ Authorizedᶜ(s) }`.

**The compiled grammar.** The `G_s` compiler (the novel artifact; `crates/tantalus-grammar`,
RESEARCH_DESIGN §3.4) turns the runtime authorization context of `s` into a context-free grammar
`G_s` whose terminals are tokenizer tokens. Its language is `L(G_s) ⊆ V*`. Per-request compilation
is what lets a *static* CFG express *runtime-state* authorization (`§5`).

**Valid prefixes and the admissible set.** Write
`Pref(L) = { p ∈ V* : ∃ z ∈ V*, p·z ∈ L }` for the set of prefixes of strings in `L`. For a prefix
`p`, the **admissible (extension) set** is

```
Ext_{G_s}(p) = { t ∈ V : p·t ∈ Pref(L(G_s)) }.
```

**The constrained decoder.** At decode step `i` (prefix `p = t₁ ⋯ t_{i-1}` already emitted) the
decoder computes the **grammar mask** and, *before sampling*, drives to probability zero every
token outside `Ext_{G_s}(p)`. It admits `EOS` at step `i` **iff** `p ∈ L(G_s)` (the prefix is
itself a complete string). The transformer still computes a full logit vector over `V`; the mask is
applied to that vector. This is the standard pushdown-automaton mask realized by xgrammar, llama.cpp
GBNF, and the guidance/llguidance backend (all three validated here as engines; §8).

The **enforcement locus is the sampler, not the model.** This is the load-bearing structural fact:
the model may, under injection, assign arbitrarily high logit to a forbidden token; that token is
removed from the support before any sampling decision is made.

---

## 2. Mask soundness (the for-all-logit lemma)

> **Lemma 1 (Mask soundness).** Fix `G_s` with `L(G_s) ≠ ∅` and run the constrained decoder of §1.
> For **any** sequence of logit vectors over `V` produced by the model, and **any** sampler in
> {greedy argmax, top-`k`, top-`p` (nucleus), temperature sampling at any `T > 0`, and their
> compositions}, every token drawn at every step `i` lies in `Ext_{G_s}(t₁ ⋯ t_{i-1})`.
> Consequently every sequence the decoder reports as **complete** is a member of `L(G_s)`.

**Proof.** We first record a property of the samplers, then induct.

*Sampler support property.* Let `m ∈ {0,1}^V` be the post-mask indicator (`m_t = 1` iff
`t ∈ Ext_{G_s}(p)`), and let the post-mask distribution be `q_t ∝ m_t · f(ℓ_t)` where `ℓ` is the
logit vector and `f` is the sampler's (nonnegative, monotone) reweighting — `f(ℓ_t)=exp(ℓ_t/T)` for
temperature/top-`p`/top-`k`, with top-`k`/top-`p` additionally zeroing all but a high-probability
subset, and argmax selecting a maximizer. In every case the support of `q` satisfies
`supp(q) ⊆ { t : m_t = 1 } = Ext_{G_s}(p)`: multiplying by `m_t` sends every masked token to
probability zero, and none of the reweightings (truncation to a top set, temperature scaling,
renormalization, argmax over the surviving support) can move probability *onto* a token that is
already at zero. A token drawn from `q` therefore has `m_t = 1`, i.e. lies in `Ext_{G_s}(p)`. This
step **never inspects the logit values** `ℓ`, only the support after masking — which is precisely
why the conclusion is universal over logits, and so holds against an injection-compromised model.
(Edge case: if `Ext_{G_s}(p) = ∅` and `p ∉ L(G_s)`, the support is empty and no token is drawn;
this is the *progress* obligation, handled by Lemma 3, not a soundness failure — nothing
out-of-language is ever emitted.)

*Induction on the number of emitted tokens, invariant `I(i): t₁ ⋯ t_i ∈ Pref(L(G_s))`.*
- **Base (`i = 0`).** The empty prefix `ε ∈ Pref(L(G_s))` because `L(G_s) ≠ ∅`. `I(0)` holds.
- **Step.** Assume `I(i-1)`: `p = t₁ ⋯ t_{i-1} ∈ Pref(L(G_s))`. By the support property the drawn
  token `t_i ∈ Ext_{G_s}(p)`, i.e. `p·t_i ∈ Pref(L(G_s))` by definition of `Ext`. Thus
  `t₁ ⋯ t_i ∈ Pref(L(G_s))`, establishing `I(i)`.

*Completion.* The decoder reports completion only by emitting `EOS`, which is admitted at step `i`
**iff** the current prefix `p ∈ L(G_s)`. At that moment `I` gives `p ∈ Pref(L(G_s))`, and the EOS
admission condition gives `p ∈ L(G_s)` directly. Hence any completed generation is a member of
`L(G_s)`. ∎

**Remark (why "for any logits" is the whole game).** Logits encode *intent*; the lemma quantifies
over them universally and never reads them. Intent is uncontrolled — a successful injection can make
the model *want* a forbidden action — but the *emitted tokens* are confined to `L(G_s)` regardless.
This is the formal content of "GCD enforces in the sampler, not the weights," and the reason
abliteration of refusal directions (which edits the weights/logits) cannot defeat it (the steelman
exhibit, §7).

---

## 3. The tokenizer lift, made first-class (discharging caveat (i))

`G_s` is *authored* over intended **character-level** policy `Authorizedᶜ(s)` (URLs, paths, channel
ids), but the mask of §1 operates over the **token** language `L(G_s) ⊆ V*`. Soundness of the
end-to-end claim requires that token-level membership imply character-level authorization.

> **Definition (sound lift).** `G_s` is a **sound token lift** of `Authorizedᶜ(s)` iff
> `δ(L(G_s)) ⊆ Authorizedᶜ(s)` — every accepted token sequence *decodes* into the authorized
> character language.

Two distinct directions must be separated:
- **Soundness (security-critical):** `δ(L(G_s)) ⊆ Authorizedᶜ(s)`. If this fails, some accepted
  token path decodes to an out-of-scope string — a silent authorization violation one layer beneath
  Assumption A1. **This direction must hold.**
- **Completeness (utility, not security):** `δ(L(G_s)) ⊇ (intended reachable subset)`. If this
  fails, some authorized action is unreachable — a *liveness/utility* defect (it can only deny, never
  over-permit). It cannot cause an unauthorized emission and so is out of scope for the soundness
  theorem.

> **Lemma 2 (Lift soundness ⇒ character-level authorization).** If `G_s` is a sound token lift,
> then for every completed generation `w` of the constrained decoder, `δ(w) ∈ Authorizedᶜ(s)`.

**Proof.** By Lemma 1, `w ∈ L(G_s)`. Apply `δ` and the sound-lift inclusion:
`δ(w) ∈ δ(L(G_s)) ⊆ Authorizedᶜ(s)`. ∎

**The subtlety the lift hides.** `δ` is *not injective*: a character string can have several token
encodings, and a token boundary can straddle a grammar terminal (the "token-healing"/boundary
hazard). A naïvely character-authored grammar can therefore admit a token path that *re-spells* into
an out-of-scope string, or block the canonical encoding of an in-scope one. A sound lift must quotient
the grammar by `δ` correctly — typically by authoring terminals as **byte/character sequences the
engine itself re-tokenizes** under the same mask, so that `L(G_s)` is closed under the engine's
encoding of the intended character strings.

**Discharge (operational, per engine).** We do not assume A2; we *check* it. The **acceptance
oracle** (`crates/tantalus-grammar` validation, run before every experiment and re-run per engine)
asserts on probe inputs that (a) the engine actually constrains output to the intended language
(catching the silent-ignore footgun where a grammar field is accepted but ignored — e.g. vLLM's
top-level `guided_grammar` is silently dropped, only `structured_outputs.grammar` constrains), and
(b) the *decoded* constrained output lies in `Authorizedᶜ(s)` on adversarial probes (catching
boundary/over-approximation). This was validated independently on **three** mask implementations
(llama.cpp GBNF; vLLM xgrammar; vLLM guidance/llguidance) plus auxiliary corroboration on SGLang,
which is why a local, inspectable stack is required and cloud black boxes are not admissible
evidence. The H5 probe (`harness/h5_grammar_compile_results.md`) additionally bounds the cost of
the per-request lift+compile (one-time tens of ms; amortized ≈ 0 with grammar caching).

---

## 4. Progress / non-deadlock (discharging caveat (iii))

Lemma 1 establishes *safety* ("nothing out-of-language is emitted") but a vacuously safe decoder
that can never complete is useless and can be *coerced* into a degenerate state. We therefore make
the non-empty-reachability discipline a named obligation.

> **Lemma 3 (Progress).** Suppose `G_s` is constructed so that for every reachable valid prefix
> `p ∈ Pref(L(G_s))`, either `p ∈ L(G_s)` (so `EOS` is admissible) or `Ext_{G_s}(p) ≠ ∅` (some
> token extends `p`). Then the constrained decoder never deadlocks: at every step it has a legal
> move (extend or terminate), and on every path a member of `L(G_s)` is reachable.

**Proof.** Immediate from the hypothesis: at any reachable `p`, the admissible move set
`Ext_{G_s}(p) ∪ { EOS if p ∈ L(G_s) }` is non-empty, so the decoder is never wedged into masking
*all* tokens with no legal completion. Since `G_s` is a CFG with `L(G_s) ≠ ∅`, every valid prefix
has a finite continuation into `L(G_s)`. ∎

**Discharge.** The hypothesis is a grammar-construction discipline (no rule that can paint the
decoder into a corner with an empty admissible set and an incomplete prefix). Two backstops make it
robust in the implementation: (i) free-text fields are bounded/closed so the decoder cannot ramble
past the token budget without a legal completion (the `FreeStringStyle` and closed-response
mechanisms; ADR-0002/0003); (ii) the **structural agent-loop terminator** (ADR-0002) swaps to a
respond-only grammar that *forces* a valid terminal `respondToUser`, guaranteeing a completion in
`L(G_s)` exists on the path. Empirically, the degenerate residual is *truncation into "no action,"
never "wrong action"* — a fail-safe consistent with Lemma 1 (a truncated prefix is still a prefix of
`L(G_s)`; it simply never reaches `EOS`, so no out-of-scope action is emitted).

---

## 5. Per-request authorization and the soundness theorem

A static CFG cannot express authorization that depends on runtime state ("may read X *iff* owner").
Resolution (RESEARCH_DESIGN §3.4): compile a **per-request** grammar `G_s` from the authorization
context of session `s` (allowed URLs, permitted resource IDs, bounds, channel names). The
construction is monotone-narrowing: a per-request policy may only *restrict* `L(G_s)` to authorized
actions, never widen it (enforced in code — `build_l3_closed_gbnf` panics if a forced value is not
in the allowlist accessor).

> **Theorem (Action-integrity soundness).** Let `emitted` be any completed generation of the
> constrained decoder for principal scope `s`. Assume:
> - **(A1) Compiler/allowlist correctness (the TCB):** `δ(L(G_s)) ⊆ Authorizedᶜ(s)` (equivalently
>   `L(G_s) ⊆ Authorized(s)`).
> - **(A2) Sound tokenizer lift:** `G_s` is a sound token lift (§3).
> - **(A3) Progress:** the construction of Lemma 3 holds.
>
> Then
> ```
> emitted ∈ L(G_s) ⊆ Authorized(s),   i.e.   δ(emitted) ∈ Authorizedᶜ(s),
> ```
> **for any logit distributions and any of the §2 samplers** — hence against a fully
> injection-compromised model.

**Proof.** By Lemma 1 (using A3 for well-definedness/termination on the path), `emitted ∈ L(G_s)`
for any logits and sampler. By A2 and Lemma 2, `δ(emitted) ∈ δ(L(G_s))`; by A1,
`δ(L(G_s)) ⊆ Authorizedᶜ(s)`. Compose the inclusions. ∎

**Security corollary (the reduction).** No unauthorized action string is generable *for any input
whatsoever*; an attacker cannot, via any injected content, cause an output `∉ L(G_s)`. The residual
attack surface is exactly `{ a ∈ Authorized(s) : a is itself exploitable }` — i.e. the
**correctness of the allowlist** (A1), *not* the model's instruction-following. This is the precise
analogue of parameterized SQL queries: the vulnerability shifts from "can the attacker alter the
action" (eliminated by construction) to "does the allowlist contain something it shouldn't" (a
design/audit question, the TCB).

---

## 6. Honest scope (what the theorem does NOT give)

1. **Semantic safety.** The theorem gives *structural* membership in `Authorized(s)`, not that an
   authorized action is *wise*. Content judgment is out of scope by construction.
2. **Free-text confidentiality.** A parameter that must remain unconstrained (e.g.
   `searchFiles.query`, `respondToUser.message` in the blind/L1 grammar) is, by construction, not
   narrowed by `G_s`; the theorem makes **no** claim about what flows through it. Confidentiality
   through unconstrained free-text is Paper-2 scope (enumerable-response closure for the
   enumerable-response class — the L2/closed-response variant — and layered detection otherwise).
   The boundary is **enumerable vs open-vocabulary**, not structured vs free-text: any field whose
   authorized value set is an enumerable language is grammar-authorizable.
3. **Universality.** Single-subject realization (Tantalus). This is a *feasibility* result for
   action integrity over enumerable-sink tools, not a population claim over all agent
   architectures.
4. **TCB residue.** A1–A3 are *assumptions discharged operationally*, not theorems. A wrong
   allowlist is a wrong policy; a faulty lift violates A1 one layer down; a blocking grammar
   violates A3. We guard each with independent, defense-in-depth checks (acceptance oracle;
   executor re-validation backstop — itself a Condition-D-class post-parse `allowlist_verdict`,
   deployed as defense-in-depth that *complements* the constitutive control; construction
   discipline). C and D are policy-equivalent over `L(G_s)` and differ only in enforcement
   completeness, so using the corrective check to guard the constitutive control's TCB is
   consistent with the framing.

---

## 7. Proof vs evidence — separate lanes

The theorem is a statement about **every producible output**; it is what no finite sample can
establish, and it is the step beyond Galloway (2020), whose contribution was an empirical block rate
alone. The empirical program does **not** carry the "eliminates" claim; it establishes the two
things the theorem cannot:

- **Behavioral controls genuinely leak at scale** (the negative-control result): on a capable
  non-Qwen anchor (Mistral-Small-4-119B), the full behavioral stack A4 leaks at
  1.82 % [1.43, 2.29] (Clopper–Pearson 95 %), CI lower bound > 0.
- **The implementation matches the theory at scale:** GCD attack trials at **0 bypass** total
  across the program (≈ 868,000 GCD attack trials), spanning **three distinct pretraining
  lineages** — Qwen (1.7B / 35B-A3B / abliterated-27B), Mistral (119B), and Gemma (4-31B) — and
  three independent mask engines (llama.cpp GBNF, vLLM xgrammar, vLLM guidance). Of these, the 2,000
  abliterated-steelman trials are **partly true-by-construction** (the sink grammar makes exfil
  ungenerable) and are reported as an *engagement/upper-bound exhibit*, not as independent
  confirmation: they show the 97.85 % → 0 % contrast with the grammar as the sole independent
  variable on a weights-level-jailbroken model, illustrating Lemma 1's "for any logits."

The theorem covers the next, unseen input; the samples show the controls that *lack* the theorem
breaking, and the mechanism that *has* it holding wherever measured. Neither lane is asked to do the
other's job.

---

## 8. Mechanization status and trusted base summary

This is a hand proof. Lemma 1 (mask soundness) is elementary and engine-independent and would
mechanize directly given a formal model of the mask; Lemmas 2–3 reduce the end-to-end guarantee to
the three named obligations. The **trusted computing base** is exactly: the `G_s` compiler (A1), the
character→token lift (A2), and the grammar-construction discipline / incremental CFG parser (A3) —
each auditable in the local stack and guarded by the acceptance oracle and executor backstop. No
part of the guarantee rests on the model's instruction-following, on the prompt, or on the
benignity of the logits. That is the whole content of the claim: **positivity enforced all the way
down to the generative act, conditional on a correct allowlist and a sound lift — both checked, not
assumed.**

---

*Cross-references:* `paper/sections/formal.tex` (the sketch this expands);
`docs/research/RESEARCH_DESIGN.md` §3 (original setup + caveats); `harness/h5_grammar_compile_results.md`
(lift/compile cost); `harness/closeout_findings.md` (the three-lineage empirical program);
ADR-0002 (structural loop termination / progress backstop), ADR-0003 (per-request least-privilege
grammar), ADR-0005 (guidance backend).
