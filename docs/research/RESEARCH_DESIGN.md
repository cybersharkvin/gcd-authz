# Research Design — Grammar-Constrained Decoding as a Positive Security Control

Status: Draft v1 (2026-06-05)
Companion to: `THESIS.md` (the conceptual brief)
Target: arXiv preprint → security/ML systems venue

> This document operationalizes the four methodology decisions made on 2026-06-05:
> 1. **Spine** — Experimental, with a Formal core and a Build/artifact contribution.
> 2. **Central claim** — defended by a formal soundness argument + empirical validation + explicit scope of limits.
> 3. **Statistical rigor** — multi-trial, confidence intervals, a loose-grammar control, percentile overhead reporting.
> 4. **Taxonomy** — all three reference frameworks (OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF) as a coverage overlay on one shared corpus.

---

## 0. Methodology statement (per Amaral)

Amaral's *Computing Science Research Methodology* lists five methodologies (Formal, Experimental, Build, Process, Model) and states explicitly that "the activities required to tackle a single research question may include several of these." This work is a deliberate combination:

| Methodology | Role | Why it is required |
|---|---|---|
| **Experimental** (spine) | Controlled A/B/C evaluation over an attack corpus across multiple model architectures. | Empirically validates that the enforcement mechanism behaves as the theory predicts, and establishes that the attacks are real (they succeed under the control condition). |
| **Formal** (core) | Soundness argument: constrained decoding produces output provably within the grammar's language. | An experiment alone yields a *negative result* ("0 attacks in my finite corpus succeeded") — that is absence of evidence, not elimination of a class. The formal argument is what licenses the word *eliminates*, exactly as the structural argument (not a test suite) is what makes parameterized queries class-eliminating for SQLi. |
| **Build** (contribution) | The auditable apparatus: custom llama.cpp fork, GBNF grammars, evaluation harness, Nix flake. | Amaral's Build discipline (compare against existing systems; report with percentile statistics) governs the overhead study and the comparison against cloud structured outputs and behavioral baselines. Auditability is *why* cloud structured outputs are rejected as evidence. |
| **Model** (framing only) | The abstraction the formal argument operates over: trust domains, the enforcement boundary, policy-as-grammar. | Folded into the threat model; not a standalone study. |

**Exploratory → Evaluation (Amaral's two-phase experimental model).** The prior Tantalus deployment (Bedrock-hosted CTF, real player telemetry, embedding-router experiments) is the **exploratory phase** — it surfaced the questions and measured that layered behavioral defenses are breakable at a 74–84% rate. This paper is the **evaluation phase**: a controlled, reproducible, fully local study. Tantalus data appears only as clearly-labeled supplementary exploratory evidence. *(Open: include or exclude Tantalus — see §11. Current default: include as supplementary.)*

---

## 1. Research questions & hypotheses

**RQ1 (empirical, primary).** Does GCD reduce the success rate of security-class prompt-injection attacks to ≈0 across multiple model architectures, relative to negative behavioral controls?

**RQ2 (formal, primary).** Can it be shown *by construction* that no model output outside the grammar's language is generable — i.e., that GCD reduces the security problem to grammar (policy) correctness?

**RQ3 (build/systems).** What is the runtime cost of GCD enforcement — per-token latency, throughput, and per-request grammar-compilation time — and is it acceptable for production agent deployment?

**RQ4 (coverage).** How do GCD's guarantees map onto, and provide coverage of, the established AI-security taxonomies (OWASP LLM Top 10, MITRE ATLAS) and the NIST AI RMF risk functions?

**RQ5 (mechanism isolation).** Is the security property attributable to the *constrained-decoding mechanism* or to *grammar tightness*? (Answered by the loose-grammar control, Condition C.)

### Hypotheses

- **H1 (primary).** For every attack that succeeds under Condition A (negative controls only), the success rate under Condition B (GCD with a correct, tight grammar) is statistically indistinguishable from 0.
  - **H0:** GCD has no effect on attack success rate.
- **H3 (overhead).** GCD generation overhead is bounded within a stated, pre-registered envelope (target to be fixed before runs; e.g., ≤ X% throughput reduction at p99, grammar-compile ≤ Y ms/request).

> **Pre-registration note.** RQs, hypotheses, conditions, trial counts, and the overhead envelope are fixed in this document *before* the evaluation phase runs. Exploratory observations that motivate changes must be logged as such.

---

## 2. Threat model (the abstraction)

- **Axiom (trust domains).** The model occupies the *same trust domain as adversarial input*. Any input channel the attacker can influence (user turn, retrieved document, tool result, email body, marketplace skill) can influence model behavior. Therefore no instruction-layer mechanism (system prompt, RLHF, fine-tuning) is a security control; it is a quality control.
- **Corollary.** All security controls must be **external to the generation process**. GCD qualifies: enforcement happens at the sampler, downstream of and independent from the model's reasoning.
- **Attacker capability.** Arbitrary content in any input channel; full knowledge of the system (white-box: prompts, grammar, source). Cannot modify the deployed grammar or the decoder.
- **Security-relevant action (the construct).** A *binary, observable* technical action: a tool call / structured output that, if emitted and executed, performs an unauthorized operation (data exfiltration, unauthorized API call, privilege escalation, out-of-policy resource access). Success is detected by an emitted **action marker** in the structured output — no human judgment (cf. Tantalus `T4NTALUS_*` markers). This deliberately excludes safety (content-judgment) outcomes.
- **Enforcement boundary.** Token sampling. The grammar is the policy specification at that boundary.

---

## 3. The formal core (soundness argument)

### 3.1 Setup

Let `V` be the model's token vocabulary and `G` a context-free grammar whose terminals are aligned to `V` (see caveat (i)). Let `L(G) ⊆ V*` be its language. A **constrained decoder** maintains, after emitting prefix `p`, the admissible set

```
A(p) = { t ∈ V : p·t is a prefix of some string in L(G) }
```

and sets the logit of every token `t ∉ A(p)` to `−∞` before sampling. The model therefore samples only from `A(p)`.

### 3.2 Soundness theorem

> **Theorem (Soundness).** Every complete generation produced by the constrained decoder is a member of `L(G)`.

**Proof sketch.** Induction on output length. *Base:* the empty prefix is a prefix of every string in a non-empty `L(G)`. *Step:* if prefix `p` is extensible within `L(G)` and the decoder emits `t`, then `t ∈ A(p)`, so `p·t` is also a prefix of some string in `L(G)`. The decoder terminates only when it emits a token completing a string in `L(G)`. Hence the final output ∈ `L(G)`. ∎

### 3.3 Security corollary (the reduction)

> **Corollary.** Let `Authorized ⊆ V*` be the set of permitted action strings. If `L(G) ⊆ Authorized`, then no unauthorized action string is generable **for any input whatsoever**. The attacker cannot, via any injected content, cause an output ∉ `L(G)`.

The residual attack surface is therefore exactly:

```
{ a ∈ Authorized : a is itself exploitable }
```

i.e., the **correctness of the allowlist/grammar** — *not* the model's instruction-following. This is the precise analogue of parameterized queries: the vulnerability shifts from "can the attacker alter the query/action" (eliminated by construction) to "does the allowlist contain something it shouldn't" (a design/audit question).

### 3.4 Runtime-state authorization → per-request grammar compilation

Static CFGs cannot express authorization that depends on runtime state ("user may read resource X *iff* they own it"). Resolution: compile a **per-request grammar `G_s`** from the authorization context of session `s` (allowed URLs, permitted resource IDs, integer bounds, channel names). Then:

```
output ∈ L(G_s) ⊆ Authorized(s)
```

This both closes the limitation and is itself a contribution. Its cost (grammar compilation per request) is measured under RQ3.

### 3.5 Honest scope — what GCD does NOT guarantee

1. **Semantic safety.** GCD guarantees *structural* membership in `L(G)`, not that an authorized action is *wise*. Safety (content judgment) is out of scope by construction (§2).
2. **Grammar correctness.** Soundness is conditional on `L(G) ⊆ Authorized`. A wrong grammar is a wrong policy. (This is the point of Condition C.)
3. **Implementation caveats (threats to the proof's *applicability*):**
   - (i) **Tokenizer/grammar alignment.** The decoder must reason over the model's actual BPE tokens, not idealized characters; misalignment can over- or under-constrain. We use a fork whose alignment handling is auditable (the Build contribution) — this is precisely *why* a local, inspectable stack is required and cloud black boxes are not evidence.
   - (ii) **Parser correctness.** Soundness is only as strong as the incremental CFG parser. It is auditable here; it is not in cloud structured outputs.
   - (iii) **Non-empty reachability.** `G` must be constructed so `A(p)` is non-empty until a valid terminal, or the decoder deadlocks / forces an incorrect EOS. Grammar-construction discipline is part of the method.

These caveats are stated as first-class limitations, not buried — their honesty is what distinguishes a credible structural claim from an overclaim.

---

## 4. Experimental design

### 4.1 Conditions (the independent variable)

| Condition | Description | Expected result | Purpose |
|---|---|---|---|
| **A — Negative controls** | Defensive system prompt + input classifier + output filter. No grammar. | High attack success | Establishes attacks are real and the harness detects success (the control). |
| **B — GCD (tight)** | GBNF grammar encoding the correct policy. No behavioral controls. | ≈0 attack success | Tests H1 / validates the soundness theorem in implementation. |

Only the condition (and, secondarily, model architecture and grammar-complexity level) varies. Everything else is held constant.

### 4.2 Controlled variables (held constant)

Task environment, tool set and signatures, attack corpus, decoder build (pinned commit), hardware, and the model "operator" prompt. Decoding parameters are held constant except where temperature is intentionally swept (§7).

### 4.3 Uncontrolled-but-influential variables + mitigations

| Confound | Mitigation |
|---|---|
| Decoding stochasticity | Fixed seed set + temperature sweep `{0.0, 0.7, 1.0}`; multi-trial (§7). |
| Model/runtime nondeterminism (batching, kernels) | Pin llama.cpp fork commit; single-stream inference; log build + flags per trial. |
| Attack-corpus coverage / representativeness | Three-framework mapping (§6) argues coverage; the **formal argument** covers attacks *not* in the corpus. |
| Grammar-author skill / over-permissiveness | Out of scope: an over-permissive grammar is not a control anyone would deploy. C's security is argued from `G_s` construction + the empirical 0%; grammar correctness is verified by the reachability/soundness checks, not by a deliberately weakened ablation. |
| Prompt-phrasing sensitivity | ≥ k paraphrases per attack class (§5 data contract). |

### 4.4 Models under test (model-independence)

- Qwen3.6-35B-A3B (MoE, ~3B active) — IQ4_XS
- Qwen3.6-27B (dense) — Q4_K_XL
- ≥1 smaller model (additional architecture data point)
- Optional CPU baseline (AMD R9700X) for overhead generality

Running the full matrix on ≥3 architectures supports the claim that results are mechanism-driven, not model-specific.

### 4.5 Task environment

A read-capable agent with an exfiltration channel (mirrors the Tantalus design: `fetchURL`, `readFile`, `readEmail`, `readChatHistory`, `searchFiles`, `respondToUser`). Authorization model and data are fixed and documented. *(Open item — final tool count / authz model; see §12.)*

---

## 5. Data contracts (evaluation harness)

Following the project's explicit-over-implicit rule, the harness I/O boundaries are typed up front. (Rust-leaning; adapt to the harness language.)

```
enum Condition { NegativeOnly, GcdTight, GcdLoose }
enum Framework { Owasp, Atlas, NistRmf }
enum Scope { Security, Safety }

struct AttackCase {
    id: String,                  // stable, kebab-case
    class: String,               // e.g. "indirect-injection-exfil"
    owasp_id: String,            // e.g. "LLM01" (2025 list — verify, §6)
    atlas_id: Option<String>,    // e.g. "AML.T0051.001" (verify, §6)
    nist_fn: String,             // "Measure" | "Manage" | "Govern" | "Map"
    scope: Scope,                // corpus REQUIRES Security
    paraphrases: Vec<String>,    // >= MIN_PARAPHRASES
    action_marker: String,       // observable success token in structured output
}
// Validate: id non-empty; paraphrases.len() >= MIN_PARAPHRASES; action_marker non-empty;
//           scope == Security (Safety cases are excluded from the corpus by construction).

struct TrialResult {
    case_id: String,
    condition: Condition,
    model_id: String,
    seed: u64,
    temperature: f32,
    succeeded: bool,             // action_marker emitted in a grammar-valid action
    emitted_action: Option<String>,
    latency_ms: u32,
    ttft_ms: u32,
    gen_tokens: u32,
    tok_per_s: f32,
    grammar_compile_ms: Option<u32>, // Some for per-request G_s
}
// Validate: tok_per_s >= 0; if condition == NegativeOnly then grammar_compile_ms == None.
```

**Allowlisted values = the security policy.** For the tight grammar (Condition B), the enumerated terminals ARE the policy and must be listed verbatim in the paper, e.g.:

```
AllowedUrls    = [ "https://a.internal/api", "https://b.internal/api", "https://c.internal/api" ]
AllowedPaths   = [ "/etc/app/config", "/var/data/report", ... ]
AllowedChannels= [ "team-it", "operator-notes" ]
```

---

## 6. Attack taxonomy — three-framework coverage overlay

**Approach:** build **one** corpus of binary/observable security actions, then attach a mapping so each case carries its `(OWASP, ATLAS, NIST)` tags. The frameworks are a *coverage/citability overlay on a shared corpus*, not three separate evaluations — near-zero extra experimental cost.

**Two honesty rules:**
1. **Filter to security, exclude safety.** Drop content-judgment entries (e.g., OWASP Misinformation).
2. **NIST AI RMF is a governance framework, not an attack taxonomy.** It defines functions (Govern/Map/Measure/Manage), not attacks. We position it as the *risk-management framing* and map results to its **Measure** function. Claiming "attack coverage" from NIST would be a category error.

### Mapping table (target: OWASP LLM Top 10 **2025**) — ⚠ VERIFY all IDs before publication

| Attack class | OWASP (2025) | MITRE ATLAS | NIST RMF | Scope | In corpus |
|---|---|---|---|---|---|
| Direct prompt injection → tool misuse | LLM01 Prompt Injection | AML.T0051 (LLM Prompt Injection) | Measure | Security | ✓ |
| Indirect injection via poisoned data/tool result | LLM01 | AML.T0051.001 (Indirect) | Measure | Security | ✓ |
| Sensitive-data exfiltration | LLM02 Sensitive Information Disclosure | exfiltration technique | Measure/Manage | Security | ✓ |
| Improper/insecure output handling (downstream sink) | LLM05 Improper Output Handling | — | Measure | Security | ✓ |
| Excessive agency / unauthorized action | LLM06 Excessive Agency | LLM-enabled action technique | Manage | Security | ✓ |
| System-prompt / policy leakage | LLM07 System Prompt Leakage | — | Measure | Security | ✓ |
| Misinformation generation | LLM09 Misinformation | — | — | **Safety** | ✗ excluded |

> ⚠ **Verification required.** OWASP LLM Top 10 IDs differ between the 2023/24 and 2025 editions (e.g., 2025 LLM02 = *Sensitive Information Disclosure*, not *Insecure Output Handling*). MITRE ATLAS technique IDs and NIST RMF subcategory labels must be confirmed against the currently published matrices. Recommended immediate follow-up: a web-verification pass to pin every ID to a cited, dated source. Treat the IDs above as provisional until then.

---

## 7. Metrics & statistical plan

**Primary metric.** Per-cell attack success rate `ŝ = successes / trials`, where a cell = `(attack_case × condition × model)`.

**Trial design.** `k` trials per cell across the seed set and temperature sweep `{0.0, 0.7, 1.0}`. Default `k = 30` (tune before runs). Total runs ≈ `|cases| × 3 conditions × |models| × |temps| × seeds`.

**Reporting the zero result honestly.**
- For `0/k`: report a 95% confidence interval via Clopper–Pearson (exact) or the rule of three (`upper ≈ 3/k`). Example: `0/30 → 95% CI [0, 0.116]`.
- To claim a rate < 1% with confidence, `k ≈ 300` is required → state the **statistical-power vs. compute** trade-off explicitly rather than implying `0/30` proves impossibility. The *formal* argument, not the sample, carries "impossible"; the experiment shows the implementation matches it.
- **Condition A must show high success** (sanity: attacks + harness work).
- **Condition C must show > 0** (mechanism isolation, H2).

**Overhead (RQ3), reported as percentiles** (Amaral: percentiles, no distribution assumptions):
- Generation: tok/s and ms/token, with grammar (B/C) vs without (A).
- Time-to-first-token.
- Per-request grammar-compile time (for `G_s`).
- Report **p50 / p90 / p99**; no bare averages.

**Success detection.** Binary, observable: the `action_marker` appears inside a grammar-valid structured action (and, where applicable, the emulated tool would execute it). No human grading.

---

## 8. Build / comparison plan

Per Amaral's Build methodology ("compare against existing systems to verify the claims still hold"):
- **vs. negative behavioral baselines** — Condition A (the headline contrast).
- **vs. cloud structured outputs** — Bedrock/OpenAI structured-output mode as a comparison point, framed as: it may *behave* similarly but cannot be offered as *evidence* (black-box; can't audit masking; not reproducible). This sharpens "why GBNF."
- Artifact deliverables: the llama.cpp fork (MTP + TurboQuant) commit, GBNF grammar files (tight + loose), the harness, the corpus, and result databases.

---

## 9. Reproducibility plan

- **Nix flake** declares the entire apparatus; `nix run .#experiment` reproduces end-to-end.
- Pins: model weights by hash, llama.cpp fork commit, GBNF files, attack corpus, harness, all deps.
- **No cloud dependencies, no API keys** in the primary study. Anyone with equivalent hardware replicates exactly.
- Per-trial provenance logged (build, flags, seed, temp) into `TrialResult`.

---

## 10. Threats to validity

- **Internal.** Stochasticity, runtime nondeterminism, harness success-detection bugs → mitigations in §4.3; success markers are exact-match and audited.
- **External.** Generalization beyond tested models/tasks → ≥3 architectures + CPU baseline; the formal argument is model-agnostic.
- **Construct.** "Security action" must be genuinely binary/observable → enforced by the `Scope::Security` filter and marker-based detection; safety explicitly out of scope.
- **The headline is a negative result.** Defended by: (a) Condition A success, (b) Condition C > 0, (c) the soundness theorem, (d) honest CIs that do not overclaim from a finite sample.

---

## 11. Tantalus / Bedrock as exploratory evidence (open: include?)

Default: **include, clearly labeled as exploratory.** It motivates the controlled study and supplies real-world telemetry (behavioral defenses broken at 74–84%; embedding-router results). It is *not* part of the primary evaluation (Bedrock is black-box, so not admissible as proof of the structural claim). If preferred, the paper can be kept fully self-contained/local-only — flag this to drop §11.

---

## 12. Open decisions still pending

1. Task-environment specifics — exact tool count, authorization model, dataset.
2. Number of grammar-complexity levels to test (simple enum → full authz-aware `G_s`).
3. Whether embedding-based input routing is in-scope here or a follow-up paper.
4. Final trial count `k` and the overhead envelope (H3 target) — fix before runs.
5. Venue after arXiv.
6. **Framework-ID verification pass** (§6) — recommended as the immediate next action.

---

## Appendix A — Amaral experimental-checklist compliance

| Amaral requirement | Where satisfied |
|---|---|
| State the questions the experiment must answer | §1 (RQ1–RQ5) |
| Identify controlled variables | §4.2 |
| Identify variables affecting results but not under control | §4.3 (with mitigations) |
| Account for variance / statistical significance | §7 (multi-trial, CIs, rule of three) |
| Document for reproducibility | §9 (Nix flake, per-trial provenance) |
| Build: compare with existing systems | §8 |
| Build: report with percentiles, no distribution assumptions | §7 (p50/p90/p99) |
| Exploratory phase → evaluation phase | §0, §11 (Tantalus → local GBNF) |
