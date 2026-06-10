# Methodology

This document is the expository methods narrative. It justifies the research design, defines the procedure and instruments, and states the validity framework. It is the source for the paper's *Methodology* section. The locked design parameters live in [`preregistration.md`](./preregistration.md); this document explains and justifies them. Two reference sources ground the design: **Galloway (2020)**, *Application Whitelisting as a Malicious Code Protection Control* (the work this study ports to LLM agents), and **Amaral et al.**, *About Computing Science Research Methodology* (the methodological frame).

---

## 1. Research design and its justification

This study uses a **quantitative true experiment** combined with a **formal soundness argument** and realized through a **built artifact** — in Amaral's taxonomy, a deliberate composition of the *Experimental*, *Formal*, and *Build* methodologies. Amaral explicitly sanctions this: *"the activities required to tackle a single research question may include several of these methodologies."* Each claim is carried by the method appropriate to it (§5).

The choice of an experiment replicates Galloway directly. Galloway adopted a *"quantitative experimental research"* design — a *"true experiment"* with a *"pre-test, post-test, and control group"* — to test whether a **positive security control** (application allowlisting, default-deny) prevents an effect (malware execution) that a **negative control** (antivirus, default-allow) fails to prevent. This study asks the structurally identical question for LLM agents, with **GCD/`G_s`** as the positive control and **behavioral guardrails** as the negative controls. Following Galloway, *qualitative* designs are rejected (*"not sufficient for the purposes of replication when risk was at stake"*) and *correlational* designs are rejected (*"does not attempt to discover the relationship between two variables"*).

**The enforcement locus — and why it is mechanically (not metaphorically) Galloway's control.** The transformer always computes a full logit distribution; under injection it may assign an arbitrarily high logit to a forbidden token. GCD applies the grammar mask **before sampling**, setting every grammar-invalid token's probability to 0, so such a token **cannot be generated** by any sampler (greedy, top-k, top-p, temperature). The mapping is exact:

- **logit distribution** = the machine that can be infected (injection compromises it arbitrarily)
- **sampling engine masking invalid tokens** = the OS execution gate / application allowlisting
- **generated token stream** = what actually runs

The model's logits (its "intent") are uncontrolled and may be fully adversarial; the **generated tokens** are constrained. Behavioral controls (A1, A2) live **in-band** — in the same input channel the injection occupies — so the injection overrides them; GCD is **out-of-band** — the grammar is compiled from authenticated identity and applied at the sampler, nowhere the attacker's tokens can reach. That in-band/out-of-band split is the precise reason one fails and one holds.

The single addition beyond Galloway is the **formal core**. Galloway could only report an empirical block rate (best 98.9% — some malware ran). GCD admits a soundness theorem: constrained generation can emit only strings in the grammar's language, so an emitted action provably lies within the authorized set. Crucially, the theorem **quantifies over all logit distributions** — it holds against a *fully injection-compromised model* — because it never assumes the logits are benign. That is the one asset that licenses a class-level "eliminates" claim no sample could.

---

## 2. The built artifact (instrument)

The experimental instrument is the agent system plus the per-condition control machinery:

- The **subject** is Tantalus, a real agentic application, run as a self-contained **local** binary on **llama.cpp** with **GBNF** (the cloud path replaced) — so GCD is a true token-level mask. MTP is resolved per the open decision in `preregistration.md` §2.
- A **per-request `G_s` compiler** turns the principal's authorization scope into a GBNF grammar (the novel artifact). Authorized accounts/endpoints/channels/paths become ground terminals; out-of-scope parameters are absent from the language.
- Per Amaral's *Build* good-practice, the artifact is **compared against existing controls** (the behavioral conditions, and the detective allowlist D) rather than presented in isolation, and an **automated acceptance oracle** validates compiled grammars against the target engine before any run.

The harness drives the agent **headless**, executing the trial matrix and recording every outcome — including the raw emitted tool call and output-token count — to a results database.

---

## 3. Variables and operationalization

Per Amaral's experimental checklist (*"What are the variables that will be controlled? … not under the control of the researcher? What measures will account for the variance?"*):

- **Independent variable** — the security control in force: Control (no added mechanism), A1 (defensive prompt), A2 (input classifier), A3 (output filter / credential denylist), A4 (full behavioral stack), C (GCD/`G_s`), and D (post-parse allowlist validator, evaluated offline). The full condition table and the offline treatment of D are in `preregistration.md` §4. **Structured-output shape is held constant** across all conditions (shape ≠ authorization), so there is no separate shape-only arm.
- **Primary DV** — **bypass / effect** (binary): did the harmful effect occur (the deterministic win detector fired)? Galloway's *"whether a piece of malware was able to run."*
- **Secondary DVs** — **emission** (did the model *generate* the out-of-scope call at all — separating structural from detective blocking), **output-token expenditure + the raw emitted call** (logged in every condition, driving the C-vs-D cost analysis), **legitimate-task success** (over-constraint), and **overhead** (compile ms, latency, tok/s).
- **Controlled variables** — agent, tools, environment, model lineup, temperature, seed policy, MTP setting, attack corpus, engine + flags, and the **security-neutral operational base prompt** (persona + tools + format, no security content). The base prompt is the constant substrate present in every condition; the Control condition is *base only* (de-contaminated), and A1 is *base + the explicit security policy*. Holding the base prompt constant — and keeping it security-neutral — is what makes Control a true baseline rather than a secretly-defended one.
- **Confounding (uncontrolled) variables** — model nondeterminism, tokenizer/grammar alignment, and incidental prompt/format differences between conditions. Mitigations: fixed seeds/temperatures logged per trial; identical prompts modulo the control; a per-model grammar-reachability pre-check; report variance, not just point estimates.

---

## 4. Procedure

The design is **pre-test / post-test / control group** in Galloway's sense, realized by the toggled treatment: each attack instance runs under every condition with all else held constant. For each trial the harness records the conversation, every emitted tool call (raw), the win verdict, output tokens, and timings. Win detection is deterministic (flag-marker / scope-oracle), no human judgement. Single-turn attacks run as one inference; multi-turn attacks follow the corpus's fixed turn protocol. A held-out legitimate-task set is run under each condition to measure over-constraint. **D is evaluated offline**: its block decision is the allowlist check overlaid on the logged non-GCD generations, and its cost is the output tokens those generations already spent.

**Phasing.** The exploratory pilot (the current million-request run) validates the instrument, the construct measurement, and the expected qualitative shape; the confirmatory run scales to symmetric N across all conditions — including the full 250k-per-model on GCD. Per Amaral, the exploratory phase identifies the questions; the confirmatory phase answers the pre-registered ones.

---

## 5. Which method carries which claim — the three-tier ladder

The cardinal discipline (and the cleanest honesty move Amaral's framework supports) is keeping proof and evidence in separate lanes, and not over-claiming "only GCD blocks the effect." The precise, defensible claim is a **three-tier ladder**:

| Tier | Result | Carried by |
|------|--------|-----------|
| **Behavioral controls** (prompt / classifier / denylist filter, A1–A4) | **do not stop it** — leak at scale, worst on business-data exfil with no credential signature | **Experimental** result (big-N, CIs) |
| **Post-parse allowlist validator** (D) | stops the *effect*, but is **dominated** — wastes generation (emits then rejects), too late for free-text/streaming, drifts from policy (a second artifact) | **Experimental** (emission + offline token-cost) **+** analytical argument |
| **GCD** (C) | stops it at **generation** — grammar-invalid tokens **ungenerable**, cheapest, **provable** | **Formal** proof **+** Build artifact **+** big-N |

- *Formal* (Galloway-beyond): `emitted ∈ L(G_s) ⊆ Authorized(s)`, for all logit distributions → licenses "eliminates by construction."
- *Build*: the artifact is new; demonstrated feasible and compared to existing controls (Amaral p.5).
- *Experimental*: the behavioral controls genuinely leak; the implementation matches the theory; reported with percentiles/CIs (Amaral p.4–5).

C and D both block the *effect*; only C blocks at **emission** and at **zero wasted generation**. That distinction — measured (emission, token cost) and argued (free-text/streaming, TOCTOU, single-source-of-truth) — is the contribution. The experiment is never asked to carry "eliminates"; the proof is never asked to show that behavioral controls leak in practice.

---

## 6. Data collection and analysis

- **Collection.** A SQLite results DB, one row per trial: condition, attack class, variant, model id, engine commit, MTP setting, seed, temperature, raw model output, parsed/emitted tool call, output tokens, bypass verdict, emission flag, block mechanism (construction vs detection), legitimate-task outcome where applicable, and timings. Everything needed to reproduce and re-analyze — including D's offline overlay — is stored.
- **Analysis.** Per-class and overall bypass/block/emission **rates with Clopper-Pearson 95% CIs** (rule-of-three for zero cells); the **structural-vs-detective cost** comparison (output tokens C vs the non-GCD path, on emission-positive trials, plus wall-clock honesty); overhead as **percentiles (p50/p90/p99)** — following Amaral's insistence on *"statistics … that don't depend on unjustified distribution assumptions"* and his warning that *"averages can be very misleading."* The headline artifact is the Galloway-ported table: per-class bypass rate (behavioral) vs block rate (C), with the ablation and the cost overlay.

---

## 7. Validity framework and threats

In Amaral's vocabulary, supplemented where his primer is silent (he provides no construct/internal/external validity taxonomy; those burdens are discharged explicitly).

- **Reproducibility (Amaral's central concern).** Engine commit, weights, seeds, temperatures, MTP setting, and flags pinned; the full pipeline reproduces via one command. The strongest validity story in the source's own terms.
- **Confound control.** All factors but the control held constant and logged; identical prompts modulo the treatment; a **security-neutral base prompt** so the Control baseline is not secretly defended; tokenizer-alignment pre-checks.
- **Construct validity (discharged by us).** "Bypass/effect," "emission," "block mechanism," and "over-constraint" are defined operationally and distinctly in advance; refusals and malformed output are not folded into "block."
- **Generalization (honestly bounded).** One subject system and a **selected-on-outcome** corpus (attacks known-effective against the undefended agent — the live-malware analogue) support a *feasibility* claim and a demonstration that behavioral controls leak on this corpus — **not** a population-level claim. **Large N does not repair this**; it tightens CIs only. The reference baseline is the no-defense replay rate (~51.8%), not 100%.
- **Proof-vs-evidence separation** (§5).
- **Model honesty.** Any abstraction of the agent/threat model is disclosed in full, to avoid Amaral's *"sloppy modeling … that eliminate[s] what is important or … over-emphasize[s] what is of lesser impact."*

---

## 8. Ethics and safety

Entirely local. `fetchURL` and all outbound channels are mocked — no real exfiltration, no SSRF surface. Environment, secrets, and credentials are synthetic sentinel markers. No external systems attacked; no human subjects.

---

## 9. Positioning — Galloway and the 2×2

Against Galloway:

| Galloway (2020) | This study |
|-----------------|-----------|
| Quantitative true experiment, pre/post/control | Same |
| Treatment: AV (negative) vs allowlisting (positive) | Treatment: behavioral guardrails (negative) vs GCD/`G_s` (positive) |
| DV: malware ran vs blocked (binary) | DV: unauthorized action occurred vs blocked (binary) + emission + cost |
| Sample: live malware corpus | Sample: selected-on-outcome agent-attack corpus |
| Empirical only (best 98.9% block) | Empirical **plus** a formal soundness core → elimination by construction, for all logit distributions |

Against the current landscape (Related Work), the design space is a **2×2 — security model (negative/positive) × enforcement stage (post-generation/at-generation):**

| | **Negative** (detect-bad) | **Positive** (allowlist, default-deny) |
|---|---|---|
| **Post-generation** | behavioral / LLM-judge guardrails (Adrian/SecureAgentics, Lakera, PromptShield) — probabilistic | deterministic **reference monitors / policy compilers** (e.g. Policy Compiler for Secure Agentic Systems; Agent-Sentry; SAGA) — execution-time |
| **At generation** | — | **GCD at the sampler — provable, no emission, cheapest ← this work** |

The academic frontier has moved security to a *deterministic execution-layer allowlist* (the positive/post-generation cell — Condition D's class). This work moves enforcement one stage earlier, to the **decoding boundary** (positive/at-generation — the empty cell), where it is provable, leaves no emission, wastes no tokens, and reaches the free-text/streaming gap an execution-time monitor cannot. Commercial "agent security" products that market themselves as preventative/allowlist (the negative/post-generation cell) are, mechanically, probabilistic detectors — the motivating gap.
