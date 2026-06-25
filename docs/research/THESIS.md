# Research Paper Brainstorm — Grammar-Constrained Decoding as a Positive Security Control

Status: Brainstorming (2026-06-05)
Target: arXiv preprint

---

## Thesis

Grammar-Constrained Decoding (GCD) is to prompt injection what parameterized queries are to SQL injection and what application allowlisting is to antivirus — a positive security control that structurally eliminates the vulnerability class, not a mitigation that reduces its likelihood.

---

## Core Delineation: AI Security vs. AI Safety

- **AI Security**: Unauthorized *technical actions* — data exfiltration, unauthorized API calls, privilege escalation, tool misuse. Binary, observable, requires no human interpretation to classify. If the system performed an unauthorized action, it's a security failure.
- **AI Safety**: Output that requires human interpretation to be considered harmful — bias, toxicity, misinformation, social engineering content. A content/judgment problem.

This paper focuses exclusively on AI security. Many of the same controls happen to help with safety, but the framing and claims are scoped to security.

---

## The Axiom: The Model Is Never a Security Control

Prompting, RLHF, system instructions, and fine-tuning can improve output quality under normal operation, but they cannot be relied upon as security controls. The model operates in the same trust domain as adversarial input — if an attacker can influence the model's behavior via injection, they can influence it past any instruction-based defense.

Therefore: **all security controls must be external to the model's reasoning/generation process.**

Prompting and training improve quality. They are not security controls. This distinction is the foundation of the paper.

---

## Positive vs. Negative Security Controls

### Negative Security (Blacklist / Default-Allow)

Define what's bad, try to detect and block it, allow everything else. The defender is permanently behind the attacker. Every novel attack is a gap until someone writes a detection rule.

AI examples:
- Input classifiers (detect "injection-like" patterns)
- Output filters (regex for sensitive data in responses)
- Defensive system prompts ("never reveal credentials")
- Content moderation layers

### Positive Security (Whitelist / Default-Deny)

Define what's good, allow only that, deny everything else by default. Novel attacks are irrelevant — they're not on the allowlist. The attacker's only option is to find exploitation paths *within* the approved set.

AI examples:
- GCD via GBNF grammars (constrain model output to only valid actions)
- Embedding-based allowlists (route inputs only to known-good execution paths)

### Historical Parallels

| Era | Negative Control | Positive Control | Result |
|-----|-----------------|-----------------|--------|
| SQL | Input sanitization / escaping | Parameterized queries | SQL injection eliminated as a class |
| Malware | Antivirus signatures | Application allowlisting | Unauthorized execution eliminated |
| AI Agents | Prompt engineering / classifiers / output filters | GCD + embedding allowlists | Prompt injection eliminated as a class |

### Prior Work

- Galloway, G.R. (2020). "Application Whitelisting as a Malicious Code Protection Control." Capitol Technology University. — Argues application allowlisting completely replaces antivirus for critical systems. Same paradigm shift, different domain.

---

## Why Not Cloud Structured Outputs (Bedrock, OpenAI)

- **Black box** — can't verify if it's actually GCD, rejection sampling, or post-hoc validation
- **Limited expressiveness** — JSON Schema gives you types and enums, not arbitrary authorization logic
- **Not reproducible** — requires cloud account, specific model access, vendor pricing
- **Not inspectable** — can't audit the grammar compilation or token masking code
- **Not provable** — can't demonstrate the enforcement mechanism operates at the sampler level

For a paper claiming "GCD eliminates prompt injection," the entire enforcement stack must be auditable and reproducible.

---

## Why GBNF Grammars (llama.cpp)

A GBNF grammar is a Context-Free Grammar (CFG). Strictly more expressive than JSON Schema:

- Enum literals for URLs, file paths, channel names (equivalent to Structured Outputs)
- Integer ranges dependent on authorization context
- Arbitrary structural patterns (character classes, repetition, alternation)
- Business logic encoded as grammar rules, not just data types
- Semantic constraints expressible within CFG formalism

**The grammar IS the security policy** — human-readable, auditable, formally analyzable.

**Enforcement point**: Invalid tokens get masked to -inf log-probability before sampling. The constraint is applied at the token generation level — the model physically cannot produce tokens that violate the grammar. This is inspectable in llama.cpp source code.

### Expressiveness Advantage Over JSON Schema

JSON Schema: "this field is an integer"
GBNF: "this field is an integer between 1 and max_for_this_user's_authorization_level"

JSON Schema: "this field is a string enum"
GBNF: "this field matches this regex pattern encoding valid resource identifiers for this session's permissions"

---

## GCD Is Not the Only Control

GCD constrains *outputs*. Complex systems also need input-side controls:

- **Embedding-based allowlists** — positive security for input routing (does this prompt semantically match a known-good execution path?)
- **Embedding-based denylists** — reject inputs semantically close to known attack patterns (defense-in-depth; a positive model when used as margin with allowlist)
- Other external controls TBD

The paper may scope to GCD alone or include the full positive security stack. TBD.

---

## Experimental Design

### Methodology

Per Amaral et al.'s CS research methodologies (Computing Science Research Methodology, U of Alberta):

**Experimental methodology** — clear hypothesis, controlled variables, measurable outcomes, reproducible setup.

- **Hypothesis**: GCD eliminates prompt injection (and related OWASP/MITRE/NIST AI attack classes) as a vulnerability class
- **Controlled variables**: Same environment, same attack prompts, same tools — only grammar presence changes between conditions
- **Measurable outcomes**: Binary — did the unauthorized technical action occur?
- **Reproducibility**: Nix flake pins everything (model weights by hash, llama.cpp commit, grammar files, attack corpus, evaluation harness)

### Conditions

- **Condition A (Negative controls only)**: System prompt defenses, input classifier, output filter. No grammar.
- **Condition B (Positive control)**: GCD via GBNF grammar. Grammar encodes the security policy.

Same attack corpus run against both conditions. Measure attack success rate.

### Attack Taxonomy (TBD — scope one or more of)

- OWASP LLM Top 10
- MITRE ATLAS
- NIST AI Risk Management Framework

### Models Under Test

Multiple architectures to show results are model-independent:
- Qwen3.6-35B-A3B (MoE, 3B active params)
- Qwen3.6-27B (dense, all params)
- Potentially smaller models for additional data points

---

## Hardware

| GPU | Card | VRAM | Models | Performance |
|-----|------|------|--------|-------------|
| 0 | RTX 5090 | 32 GB | Qwen3.6-35B-A3B MoE (IQ4_XS) + Embedding 0.6B | ~93 tok/s gen, ~438 tok/s prompt |
| 1 | RTX 5090 | 32 GB | Qwen3.6-35B-A3B MoE (IQ4_XS) + Embedding 0.6B | ~93 tok/s gen, ~438 tok/s prompt |
| 2 | RTX 5090 | 32 GB | Qwen3.6-27B Dense (Q4_K_XL) + Embedding 0.6B | ~66 tok/s gen, ~160 tok/s prompt |
| 3 | RTX 5090 | 32 GB | Qwen3.6-27B Dense (Q4_K_XL) + Embedding 0.6B | ~66 tok/s gen, ~160 tok/s prompt |
| 4 | RTX 4090 | 24 GB | Qwen3-Reranker-4B + Embedding 0.6B | Reranking + embeddings |
| — | AMD R9700X | CPU | Qwen3.6-27B + Embedding 0.6B | CPU inference baseline |

All via custom llama.cpp fork with Multi-Token Prediction (MTP) + TurboQuant KV cache compression. Full 256k context on single GPUs.

---

## Reproducibility

- **Nix flake** declares entire experimental apparatus
- Pins: model weight files (by nix hash), llama.cpp fork commit, GBNF grammar files, attack corpus, evaluation harness, all dependencies
- `nix run .#experiment` reproduces the full experiment _(not yet wired — `apps.experiment` is stubbed in `flake.nix`; use the manual path in `README.md` today)_
- No cloud dependencies, no API keys, no vendor accounts
- Anyone with equivalent hardware can replicate

---

## Open Questions

- Exact attack taxonomy scope (OWASP? MITRE? NIST? All three?)
- Task environment design — how many tools, what authorization model, what data
- Whether to test multiple grammar complexity levels (simple enum → full authz-aware grammars)
- Whether embedding-based routing is in-scope or a follow-up paper
- Paper structure / target venue (arXiv preprint first, then which conference?)
- How to handle CFG limitations honestly (constraints requiring runtime state that can't be expressed statically in a grammar)
- Whether to include Tantalus (Bedrock) data as supplementary evidence alongside the primary local experiment
