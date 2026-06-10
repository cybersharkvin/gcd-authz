# Research Paper Brainstorm v2 — A Composable Positive-Security Architecture for Agents

Status: Brainstorming (2026-06-05)
Extends: `THESIS.md` (the GCD-as-positive-control thesis)
Target: arXiv preprint

> v1 (`THESIS.md`) argues GCD is to prompt injection what parameterized queries are to SQLi. That still holds — but it is necessary, not sufficient. v2 widens the claim: a production agent needs **three composable, structural controls**, each addressing a different failure mode, with GCD as the provable core that also reinforces the other two.

---

## 1. Two security properties (the distinction v1 elided)

- **Action integrity** — the agent only *performs* authorized actions (right tool, right recipient, in-scope resource id). GCD provides this **structurally**: `output ∈ L(G_s) ⊆ Authorized(s)`.
- **Data confidentiality** — the agent only *reveals* data the sink is cleared for. GCD **cannot** provide this for a free-text field, because a free-text field is by definition a content-unconstrained channel. This is an information-flow problem, not a syntax problem.

A complete architecture needs a control for *each* property. Conflating them is the mistake.

---

## 2. Two independent axes (keep these separate)

|                | **Negative** (default-allow, blacklist) | **Positive** (default-deny, allowlist) |
|----------------|------------------------------------------|-----------------------------------------|
| **Probabilistic** (learned threshold) | input classifier, output regex filter | **embedding allow/deny gate** |
| **Provable** (formal mechanism)       | —                                        | **GCD / grammar**, **judge context isolation** |

"Positive vs negative" (allowlist vs blacklist) and "provable vs probabilistic" (formal guarantee vs learned threshold) are **different axes**. A control can be positive-but-probabilistic. The strongest claim — *eliminates the class* — requires positive **and** provable. The paper must label each control by both axes and never claim probabilistic-grade controls as provable.

---

## 3. The three composable controls

### Control 1 — Grammar-Constrained Decoding (positive + provable)

The core, carried over from v1.

- **Mechanism**: invalid tokens masked to −∞ before sampling; output is provably ∈ `L(G)`. Inspectable in llama.cpp; GBNF (a CFG) is strictly more expressive than JSON Schema (enums, ranges, business-logic patterns). The grammar *is* the security policy.
- **Per-request grammar `G_s`**: compiled at request time from the authenticated caller's authorization context. Enums populated from `AuthScope(s)` (permitted resource ids, recipients, corpora, integer bounds). Guarantee becomes **identity-relative**: `output ∈ L(G_s) ⊆ Authorized(s)`. This makes authorization a *structural* property — not a runtime `if` the model can be talked out of, but the set of generable tokens. Solves the confused-deputy / cross-tenant problem.
- **Scope**: action integrity + the structured parts of output. Localizes (does not close) the free-text confidentiality hole — see Control 2.
- **Reinforces Control 3**: a schema-constrained planner artifact is what closes the judge's one defeat condition.

### Control 2 — Embedding allow/deny margin (positive-in-spirit + probabilistic, fail-closed)

A single primitive — `allow_score − deny_score > τ` against an allowlist corpus (approved semantic region) and a denylist corpus (forbidden region), which **coexist** — applied at *whichever boundaries you choose* (it **can** sit at every boundary; it doesn't have to):

- **Pre-model, on raw input** — drop obviously malicious / roleplay inputs before inference. Saves the inference call; a denylist (`"ignore your instructions"`, known attack shapes) filters injection *before it reaches the model at all*.
- **On ingested untrusted content** — gate a poisoned email body / attachment before it enters context.
- **On tool invocation** — gate the action.
- **On tool return** — gate what a backend hands back before it re-enters context.
- **On output / the user-facing message** — and because `respondToUser` *is* a tool call, that field is a **known enum**, so the check is against a fixed, known-in-advance set rather than open space.
- **Streaming output gate**: as tokens stream, embed the running output; kill generation the instant it leaves the allowlist region or enters the denylist region. **Fail-closed by construction**: the free-text body is the *argument* to a tool; a killed generation never completes the argument, so the tool never fires — nothing leaves. (Backend tool-call setting: partial generation = no action = no leak.)
- **Per-request denylist** (enhancement): seed it from embeddings of the *exact* sensitive records retrieved this turn, so it kills on drift toward *this request's* secrets — a per-request artifact, like `G_s`.

**Primary purpose: confidentiality** — prevent leakage of internal data, the system prompt itself, PII/PHI. **Secondary, parked:** the same mechanism doubles as a *safety* control (noted, out of the paper's security scope, but real).

**Honest residual (a research question, not a dismissal):** the boundary is a learned threshold, so its guarantee is **empirical**, not formal. An attacker who controls the injected instruction can try to emit a secret in a form that stays inside the allowed region — encoding (base64, acrostic, "spell it as a story"), or splitting across the body. So the gate's confidentiality strength is an **adversarial-robustness rate you measure**, not 0-by-construction. Still strictly stronger than a classic output filter: default-deny allowlist (not enumerate-bad), streaming (not post-hoc), fail-closed (not log-after-send).

### Control 3 — Adversarial Judge (structural context isolation)

A two-model planner/judge split between the user and execution.

- **Planner**: sees the user request; decomposes it into a *structured plan* (goal, required tools, steps, success criteria). Executes nothing; produces an artifact.
- **Judge**: sees *only* the plan + the system rules. **Never** the user input, chat history, or other context. Rules solely on whether the plan's steps are policy-compliant — indifferent to user intent. Approve → execute; reject → nothing happens.
- **Security property = causal severance, not detection.** Injection works because attacker text gains semantic weight inside the model's context and competes with the rules. The judge's context **contains no user text — there is nothing to inject into.** The attacker's payload is severed at the context boundary. The attacker's problem mutates from "convince the model to ignore its rules" into "craft an input that makes the *planner* emit a plan that reads clean when judged in isolation" — dramatically harder.
- **The one real defeat condition**: the planner faithfully *replays* the attacker's payload into the plan as free text, smuggling it across into the judge's context.
- **Counter (ties to Control 1)**: constrain the planner's output with a **schema/grammar**. Atomized steps with fixed fields can't carry arbitrary adversarial strings; a replay must be *both* expressible in the schema *and* survive the policy check — two independent layers to defeat simultaneously.

---

## 4. How they compose

- **GCD** gives provable action integrity and structures the planner artifact.
- **The judge** removes the attacker from the decision context entirely (defense by causality, not detection); GCD on the planner output closes its only weakness.
- **The embedding gate** handles the deliberately-unconstrained free-text channels GCD leaves open, fail-closed, wherever you choose to place it.

No single control is the whole answer. The thesis sharpens to: **prompt injection is eliminated as a vulnerability class by a composition of structural controls — provable where the output is discrete (GCD, judge isolation), measured-and-fail-closed where the output must be free text (embedding gate) — with GCD reinforcing the others.** Each control is labeled honestly on the positive/negative and provable/probabilistic axes.

---

## 5. The realistic task environment (not a chatbot)

A **single shared customer-operations agent, same tools, two authorization tiers** — the production-grade descendant of Tantalus:

- **External (customer) path**: ingests untrusted email + attachments, queries a customer-scoped backend / RAG, replies via an email tool (returns data to the verified customer).
- **Internal (employee) path**: same agent, same tools, *different* DB / RAG scope; used for busywork and responding to customer inquiries.
- The only difference is the **authorization context** → per-request `G_s` is where it shines, and where cross-tier / cross-tenant confidentiality is at stake (the internal agent reads internal data the customer LLM never sees, yet can email customers — the free-text-body leak the embedding gate guards).

Most agentic token consumption in the world is exactly this kind of backend, multi-agent, non-coding system whose work is never seen by the user. That is the right setting to prove the architecture.

---

## 6. Carried-over commitments from v1

- Local GBNF (llama.cpp), not cloud structured outputs — the enforcement stack must be auditable, inspectable, reproducible, provable.
- Security ≠ Safety: scoped to unauthorized *technical actions* (binary, observable). Safety overlaps noted but out of scope.
- The model is never a security control; all controls external to generation.
- Reproducibility via Nix flake; multi-model to show model-independence.

---

## 7. Open questions (updated)

- Which controls are *headline* (proven) vs *supporting* (measured) — esp. the epistemic positioning of the embedding gate (provable-for-integrity / measured-for-confidentiality vs other framings).
- Attack taxonomy scope (OWASP / MITRE ATLAS / NIST — IDs to verify per edition).
- How far to push the judge (single judge vs panel; planner schema complexity).
- Whether per-request denylist + compartmentalization (IFC) are in-scope or follow-up.
- Task-environment specifics: tool count, authZ model, datasets.
- Paper structure / venue after arXiv.
