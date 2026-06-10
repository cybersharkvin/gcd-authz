# Related-Work Perimeter — GCD + `G_s` (Paper One)

Status: Draft v1 (2026-06-05) · Method: web survey, June 2026 · Gating task per the GCD-artifact plan
Done-test: *can I write the paragraph "X did A, Y did B, none made authorization a structural property of per-request generation," with citations?* — **Yes (see §1).**

---

## 0. VERDICT (read this first)

**The perimeter is crowded with *structured-output* and *post-hoc policy* work — but it is essentially empty at the point of true GBNF-GCD *as a security policy*.** The survey **confirms** the thesis's open lane rather than closing it. The critical distinction the literature blurs and we must not:

- **Structured outputs (format)** — JSON-Schema-shaped decoding for *reliability/parseability* (XGrammar, llguidance, Outlines, cloud structured-output APIs). Commodity. This is what "GCD" means in almost every paper found.
- **GBNF-GCD as security policy** — an *expressive CFG that encodes authorization*, compiled per request, enforced at the decoder as the *security boundary*. **Almost nobody does this.** The actual security-by-design work routes *around* GCD: Progent/AgentSpec *evaluate proposed actions post-hoc* (policy DSL, sometimes LLM-judged → itself injectable); CaMeL uses an *interpreter + capabilities*. None makes the unsafe parameter *ungenerable*.

### The axiom this rests on (state it up front in the paper)
> An LLM only emits text; it has no agency. **Every** real-world effect is a downstream interpreter executing that text. Therefore the security boundary is the *emittable set itself*: constrain what the model is *allowed to output* so the unsafe action is **ungenerable** — rather than filtering inputs or judging outputs after the fact. For *action integrity*, within the security scope, this is **complete and provable**, not heuristic.

### Framing discipline (corrected)
- **Don't lead with "GCD stops prompt injection"** — heard as *format* GCD (seen it). Lead with **GCD-as-authorization-policy**, which is open.
- **The SQLi/parameterized-query analogy is motivation, not contribution** — it's already in the literature (StruQ, Instruction Hierarchy, Cisco; NCSC argues it's *imperfect*). Claim the *output-side mechanism*, not the analogy.
- **"By design / provable" is contested** (CaMeL = interpreter/IFC; Progent = post-hoc gating). Yours is *provable generative impossibility of out-of-scope parameters* — a distinct mechanism.
- **The "GCD is an attack surface" result dissolves under mature practice** — it assumes the *attacker controls the grammar* (public structured-output APIs). Here the grammar is server-side, trusted, compiled from `AuthScope`. Immature-deployment artifact, not a property.

### The precision that keeps the novelty honest
**Do NOT rest novelty on "GBNF vs structured outputs" — same token-masking engine** (XGrammar compiles JSON Schema → a grammar/automaton; llguidance enforces arbitrary CFG). A reviewer collapses them at the mechanism level. Rest it on the two axes where the win is real:
1. **CFG expressiveness actually exploited** — context-dependent enums, integer ranges tied to authorization level, cross-field/business-logic constraints that JSON-Schema-shaped structured outputs (especially cloud APIs) *cannot* express.
2. **The grammar as a per-request authorization policy over tool-call parameters** (`G_s`) — *what the grammar encodes and where it comes from*, so out-of-scope identifiers are ungenerable regardless of injected content.

- **The defensible sliver, in one line:** *authorization is the generable token set, compiled per request from `AuthScope(s)`, enforced at the decoder over tool-call parameters.* The leading SoK names the parameter problem as **open** and does **not** propose this.
- **Residual risk:** two March-2026 papers (ATLAS-RTC, Chain-of-Authorization) sit close on *mechanism* and *topic* respectively and **must be read in full and differentiated before submission** (§9).

---

## 1. The novelty paragraph (the claim, with citations)

> Grammar-constrained decoding [XGrammar 2411.15100; llguidance; Outlines] enforces output *structure/format* and powers reliable tool-calling, but is positioned as a reliability/format mechanism at roughly JSON-Schema expressiveness, not as access control — leaving unused the full CFG power (context-dependent enums, authorization-tied ranges, cross-field constraints) that an authorization policy requires. CaMeL [2503.18813, SaTML'26] and the IFC line [Securing AI Agents with IFC 2505.23643; Fides] achieve *control- and data-flow* integrity via a trusted interpreter and capabilities — and the leading systematization [Beurer-Kellner et al. 2506.08837] explicitly leaves tool-call **parameter** constraints as an *open* limitation ("the parameters of these actions … could still be influenced by untrusted data"), recommending *more isolation* rather than constraining parameters directly. Progent [2504.11703] and AgentSpec [2503.18666] enforce least-privilege / runtime policies by **evaluating proposed actions post-generation** (DSL policy checks, sometimes LLM-judged), not by making out-of-scope outputs ungenerable. StruQ [2402.06363, USENIX'25] and the Instruction Hierarchy recreate the parameterized-query separation at the **input channel**, not the output. ATLAS-RTC [2603.27905] applies token-level runtime control for **format/contract** reliability, not authorization scoping; delegated-authorization work [2510.26702] issues scoped OAuth-style tokens at the **authorization server**, not the decoder. **None makes per-request, caller-authorization-scoped constraints on tool-call parameters a structural property of the decoder — i.e., compiling the caller's `AuthScope(s)` into the grammar so the model physically cannot emit out-of-scope resource identifiers, recipients, or URLs regardless of injected content.** That is the contribution of `G_s`.

---

## 2. Cluster map

### Cluster A — Constrained decoding / structured outputs (the *mechanism*, commoditized)
- XGrammar [2411.15100] (default backend for vLLM/SGLang/TensorRT-LLM); llguidance (~50µs/token, dynamic, near-zero startup); Outlines (automaton pre-compute); llama.cpp (what Tantalus/your fork use); JSONSchemaBench [2501.10868]; "Flexible and Efficient GCD" [2502.05111]; Earley pruning [2506.01151].
- **Did:** make token-masking to a grammar fast, reliable, production-default. The *engines* support full CFG (llguidance enforces arbitrary CFG; XGrammar compiles JSON Schema → automaton) — so "GBNF vs structured outputs" is **not** a mechanism difference.
- **Did NOT:** in *deployed practice and cloud APIs*, go beyond JSON-Schema-shaped format constraints; treat the grammar as a *security policy*; compile it *per request from authorization*; make parameters an *access-control* boundary. → Your mechanism is theirs; your **grammar's content, provenance, and exploited expressiveness** are not.

### Cluster B — Safe-by-design / parameterized-query analogy (already claimed, input-side)
- StruQ [2402.06363, USENIX'25]; OpenAI Instruction Hierarchy; Cisco & NCSC blogs.
- **Did:** separate instruction/data channels (the prepared-statement move) at the **prompt/input** level via training; articulate the SQLi analogy.
- **Did NOT:** enforce at the **output/decoder**; scope by authorization; address tool-call parameters. NCSC actively argues the analogy is *imperfect* — preempt this.

### Cluster C — "By design" defenses: control/data-flow & capabilities (the strong baselines)
- CaMeL [2503.18813] — interpreter + capabilities, IFC (Denning), "provable security" on AgentDojo (77% secure-task completion); code released. "CaMeLs Can Use Computers Too" [2601.09923].
- Securing AI Agents with IFC [2505.23643] (Costa, Köpf, Microsoft); Fides (planner with redacted/typed variables); ACE / plan-then-execute [2509.08646]; the SoK [2506.08837] (dual-LLM, plan-then-execute, map-reduce, action-selector).
- **Did:** make *control flow* injection-proof and protect *data flow* via capabilities/typing; own "by design" + "provable."
- **Did NOT:** constrain action **parameters** — **explicitly flagged as open** in the SoK and CaMeL's data-dependent-task limitation. ← *This is the gap `G_s` fills, and it's named in the literature.*

### Cluster D — Least-privilege / runtime policy enforcement (route *around* GCD; post-hoc gating, not generative)
*These are the actual "security-by-design" agent papers — and none uses constrained decoding. They evaluate proposed actions after the model has produced them, which is exactly the gap the axiom closes.*
- Progent [2504.11703] (Dawn Song et al.) — JSON DSL, least-privilege at tool-use level; ASR 41.2%→2.2% (AgentDojo), provably 0% with manual policies; LLM-generated/LLM-enforced policies. AgentSpec [2503.18666] — DSL, intercepts execution stages, *evaluates proposed actions prior to execution* (terminate/inspect/correct/reflect).
- **Did:** least-privilege for agents; "provably 0% ASR" with manual policies; strong utility.
- **Did NOT:** enforce at the **decoder** — they *gate already-proposed* actions (can be LLM-judged → itself injectable). `G_s` makes the out-of-scope token **ungenerable**, a different (stronger, narrower) guarantee than post-hoc evaluation. **Note:** Progent's "provably 0%" means you must contrast *generative impossibility* vs *policy gating*, not claim "provable" as uniquely yours.

### Cluster E — Authorization for agents (server-side scoping)
- Delegated Authorization / Semantic Task-to-Scope Matching [2510.26702] (TBAC); Authenticated Delegation & Authorized AI Agents [2501.09674]; industry "Decision Gateway" patterns; NL→policy compilation (ABAC/RBAC from text).
- **Did:** issue minimal-scope access tokens at the **authorization server**; intent→scope matching.
- **Did NOT:** push the scope into the **generation step**. `G_s` is the missing link: *the issued scope becomes the grammar*. (Strong framing — you compose with, not compete with, this line.)

### Cluster F — Token-level runtime control (nearest *mechanism*-neighbor — RESIDUAL RISK)
- ATLAS-RTC [2603.27905] — "monitors generation each step, detects drift from output contracts, applies biasing/masking/rollback." Same *layer* as `G_s` (token-level intervention) but **purpose is format/contract reliability**, not authorization (no authz/permission/per-user content found in abstract or extract).
- **Did:** token-level masking/rollback for structured-output & tool-call **reliability**.
- **Did NOT (as far as extracted):** authorization-scoped parameter allowlists. **Action:** read in full; differentiate on *purpose* (reliability vs access control) and *source of the constraint* (output contract vs caller `AuthScope`).

### Cluster G — Benchmarks & the benchmark-weakness problem (shapes your eval)
- AgentDojo, InjecAgent, Agent Security Bench (ASB, ICLR'25), WASP [2504.18575], tau-Bench; taxonomy [2602.10453]; large-scale public competition [2603.15714].
- "Indirect Prompt Injections: Are Firewalls All You Need" [2510.05244] — claims **perfect security** with tool-input/output firewalls across AgentDojo/ASB/InjecAgent/tau-Bench, AND shows benchmarks are **easily saturated by weak attacks**; proposes a 3-stage cascade (standard → second-order → adaptive).
- **Implication for your experiment:** default benchmark attacks are *not enough*. You must run **strong adaptive attacks** (incl. encoding/second-order) or the 0-result is dismissed. A competing "perfect security" firewall claim exists — differentiate (firewalls = filtering at the tool interface = negative/probabilistic; `G_s` = positive + provable at the decoder).

### Cluster H — Constrained decoding as an ATTACK surface (threat-model boundary)
- Constrained Decoding Attack / "When Grammar Guides the Attack" / "Beyond Prompts: Space-Time Decoupling Control-Plane Jailbreaks" [2503.24191] — if the **attacker controls the grammar/schema** (public structured-output APIs), GCD becomes a jailbreak vector (DictAttack 75–99% ASR).
- **Implication:** this is an **immature-deployment artifact, not a property of GCD.** The attack only exists because public APIs let the *caller* (attacker) supply the schema. In `G_s` the grammar is **server-side, trusted, compiled from `AuthScope`**, never attacker-supplied — so the attack does not apply. State this threat-model boundary explicitly (if an attacker can influence the grammar, the guarantee is void) or a reviewer weaponizes it.

---

## 3. Positioning recommendation

0. **Open on the axiom** (§0): the LLM only emits text; all effects are downstream execution; therefore constrain the emittable set. This is the spine that makes "constrain the output, not the input" obvious and reframes the whole defense landscape as solving the wrong problem (filtering/judging) on the wrong substrate.
1. **Headline = `G_s`**: *authorization as the generable token set* — per-request, parameter-level, decoder-enforced. Not GCD-general, not the analogy. **Do not rest novelty on "GBNF vs structured outputs"** (same engine); rest it on (a) CFG expressiveness *actually exploited* for authorization and (b) the grammar as a per-request authorization policy.
2. **Motivate from the gap in the SoK** [2506.08837]: the action-*parameter* problem is named as open by the field's own systematization → you answer it structurally.
3. **Compose, don't compete**, with Cluster E (server-side scope → becomes the grammar) and Cluster C (CaMeL/IFC handle control/data flow; `G_s` handles the parameter sub-problem they leave open).
4. **Concede "provable" is contested** (CaMeL, Progent) — your provability is specifically *generative impossibility of out-of-scope parameters*, distinct from interpreter capabilities (CaMeL) and post-hoc policy gating (Progent/AgentSpec).
5. **The boundary is the pitch**: `G_s` provably closes action integrity at the parameter level; free-text confidentiality remains (→ the embedding gate, paper 3) and control/data-flow remains (CaMeL-class, paper 2). That's the dissertation arc.

---

## 4. Threats to preempt in the paper

- **Grammar-as-attack-surface** [2503.24191] → trusted, server-side grammar; threat-model boundary stated.
- **Analogy is imperfect** (NCSC) → claim the *mechanism*, treat the analogy as motivation only.
- **Weak-benchmark dismissal** [2510.05244] → strong adaptive + encoding attacks, not default suites.
- **"Provable" already claimed** (CaMeL/Progent) → scope your provability precisely.

---

## 9. Must-read-in-full before submission (residual novelty risk)

1. **ATLAS-RTC** [2603.27905] — nearest *mechanism*-neighbor (token-level masking/rollback). Confirm it does **not** do authorization-scoped per-request parameter allowlists. *Most important read.*
2. **Chain-of-Authorization: Embedding authorization into LLMs** [2603.22869] — nearest *topic*-neighbor. PDF was compressed/unextractable; from the title it likely embeds authz **into the model** (training/prompt → probabilistic), vs `G_s`'s **external decoder constraint** (structural). **Verify the mechanism** — if it already does decoder-level per-request authz, the novelty narrows further.
3. **CaMeL** [2503.18813] full read — confirm its parameter/data-dependent limitation precisely (your wedge).
4. **Progent** [2504.11703] full read — confirm enforcement is post-hoc/LLM-judged, not decoder-level.

---

## Appendix — citation list (arXiv IDs from June-2026 search; ⚠ = verify before citing)

| Work | ID | Cluster |
|---|---|---|
| XGrammar | 2411.15100 | A |
| JSONSchemaBench | 2501.10868 | A |
| Flexible & Efficient GCD | 2502.05111 | A |
| Earley-Driven Dynamic Pruning | 2506.01151 | A |
| llguidance | (GitHub: guidance-ai/llguidance) | A |
| StruQ | 2402.06363 | B |
| Instruction Hierarchy (OpenAI) | ⚠ verify (Wallace et al. 2024) | B |
| CaMeL — Defeating Prompt Injections by Design | 2503.18813 (SaTML'26) | C |
| CaMeLs Can Use Computers Too | 2601.09923 | C |
| Securing AI Agents with IFC (Costa, Köpf) | 2505.23643 | C |
| Design Patterns for Securing LLM Agents (SoK) | 2506.08837 | C |
| Architecting Resilient LLM Agents / Plan-then-Execute | 2509.08646 | C |
| Progent | 2504.11703 | D |
| AgentSpec | 2503.18666 | D |
| Delegated Authorization / Task-to-Scope | 2510.26702 | E |
| Authenticated Delegation & Authorized AI Agents | 2501.09674 | E |
| ATLAS-RTC | 2603.27905 | F |
| Chain-of-Authorization | 2603.22869 | F/E |
| AgentDojo | ⚠ verify (Debenedetti et al., NeurIPS'24) | G |
| InjecAgent | ⚠ verify | G |
| Agent Security Bench (ASB) | ⚠ verify (ICLR'25) | G |
| WASP | 2504.18575 | G |
| Indirect PI: Are Firewalls All You Need | 2510.05244 | G |
| Landscape of Prompt Injection Threats (taxonomy) | 2602.10453 | G |
| Large-scale public competition (indirect PI) | 2603.15714 | G |
| Melon (provable defense) | 2502.05174 | G |
| PIShield | 2510.14005 | G |
| Constrained Decoding Attack / Control-Plane Jailbreaks | 2503.24191 | H |
| Galloway — Application Whitelisting (positive security) | (local PDF, 2020) | framing |
