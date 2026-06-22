# ADR 0005 — vLLM `guidance`/llguidance grammar backend for the Mistral-119B anchor (xgrammar LARK incompatibility)

- **Status:** Accepted (apparatus decision, already executed for the Mistral-119B anchor run `harness/mistral119_anchor.db`, 2026-06-22).
- **Date:** 2026-06-22
- **Deciders:** Vince (researcher), Claude (Opus 4.8)
- **Supersedes / relates to:** ADR 0001 (SGLang+xgrammar throughput engine). Records a forced, dataset-local change from the project's default **vLLM + xgrammar** grammar path. Does **NOT** change the experiment design (conditions, win semantics, DVs, analysis plan) — see "Why this is not a pre-registration deviation of substance." Cross-referenced from `preregistration.md` §12.

## Context and problem statement

The confirmatory plan and every prior result DB use **vLLM + xgrammar** as the grammar-constrained-decoding (Condition C) path (`blast_1p7b_5m.db`, `steelman_abliterated.db`, the `confirm_1p7b_*` series). The remaining headline gap was a **capable, non-Qwen anchor** to carry RQ1 (behavioral leak on a capable model) plus a second pretraining lineage — delivered by running the full matrix on **`mistralai/Mistral-Small-4-119B-2603-NVFP4`** (hybrid MLA + MoE, ~6B active), TP=4 on Host B's 4×5090, engine image `mistralllm/vllm-ms4` (a from-source vLLM v1 build for sm120).

On that build, the experiment could not run on xgrammar:

- The victim sends `tool_choice: "auto"` for the native-tool arms (Control / A1–A4 / D). On this vLLM build, auto-tool-choice compiles the tool schema into a **LARK** grammar internally.
- The **default `xgrammar` structured-output backend rejects LARK**: `ValueError: grammar is not of valid supported types (StructuredOutputOptions.LARK)` → `EngineDeadError` → **the engine dies on the first tool call.**
- This crash is on the *native-tool* path, not C's path. Engine coherence (free-gen probe) and C's GBNF grammar door (a `root ::= "PURPLE" | "ORANGE"` probe forced `PURPLE`) **both passed before the crash** — i.e., the grammar mechanism itself was fine; only the auto-tool-choice→LARK→xgrammar interaction was fatal.

Inspecting the in-container source (`vllm/config/structured_outputs.py`, `vllm/.../backend_guidance.py:255–256`): valid backends are `auto | xgrammar | guidance | outlines | lm-format-enforcer`, and **`guidance` (llguidance) maps LARK → its `lark` path** and also accepts our GBNF.

## Decision

**Launch the Mistral-119B anchor with `--structured-outputs-config '{"backend":"guidance"}'`** so a single backend serves both (a) the auto-tool-choice LARK grammar the native arms emit and (b) Condition C's GBNF — on the same engine (vLLM). `Backend::Vllm` in `tantalus-llm` is unchanged (it still sends `structured_outputs.grammar`); only the server launch flag changed.

Companion launch facts for the same run (recorded so the recipe reproduces):
- **Drop `--reasoning-parser mistral`** (it free-texts / hangs the grammar path — same class of footgun as the Qwen `--reasoning-parser qwen3` regression).
- **Keep NCCL P2P/SHM enabled** (the stock compose's `NCCL_P2P_DISABLE=1`/`NCCL_SHM_DISABLE=1` throttle PCIe TP ~8×).
- `LLM_THINKING_KWARG=off` (the Mistral tokenizer 400s on `chat_template_kwargs`).
- Recipe: `--tensor-parallel-size 4 --max-model-len 8192 --gpu-memory-utilization 0.90 --attention-backend TRITON_MLA --max-num-batched-tokens 2048 --enable-auto-tool-choice --tool-call-parser mistral --structured-outputs-config '{"backend":"guidance"}'`, gpus device=0,1,2,3, `--ipc host`, `-p 11435`.

## Evidence (measured 2026-06-22, Host B 4×5090, `mistralllm/vllm-ms4`)

- **Grammar door under guidance:** the PURPLE/ORANGE probe constrains output (forced `PURPLE`); `guided_grammar` (top-level) still silently ignored — identical to the xgrammar footgun, so `Backend::Vllm`'s `structured_outputs.grammar` is correct unchanged.
- **Tool-call path no longer crashes** — the auto-tool-choice LARK grammar is accepted; the engine survives the full native-tool matrix.
- **C de-risk (30-trial C-only check):** real grammar-constrained tool calls (e.g. the malicious skill drives `searchFiles{query:"id_rsa"}`) but the exfil sink is ungenerable → **0 emission / 0 win / terminal `respondToUser`**.
- **Full matrix:** `harness/mistral119_anchor.db`, 37,872 rows (9 cond × 4,000 attack + 208 legit, cycles ×4), **0 errors**, ~2.6 h. **C bypass 0.00% [0, 0.09], 0 emission, 99.8% valid_output** — the same structural invariant the xgrammar runs produce.

## Considered options

1. **Stay on xgrammar (default).** Impossible on this build — the engine dies on the first tool call (LARK rejection). Rejected by force.
2. **Disable auto-tool-choice / route the native arms around the LARK path so xgrammar serves only C.** Plausible (C uses `structured_outputs.grammar`, not auto-tool-choice), but fiddly on a from-source build that already crashed once, and it would change how the *behavioral* arms emit tool calls — a worse confound than a grammar-backend swap on the C-only cells. Rejected for this run; available if backend-uniformity is ever demanded.
3. **`guidance` backend (chosen).** One backend serves both grammar surfaces, accepts LARK + our GBNF, validated grammar door + 0-emission C. Accepted.
4. **`outlines` / `lm-format-enforcer`.** Untested here; no reason to prefer over guidance once guidance was confirmed working.

## Consequences

### Positive
- The Mistral-119B anchor run completed → RQ1 (capable non-Qwen leak), the formal H2 contrast, RQ3, and blind-C utility are now demonstrated on a capable, second-lineage model.
- **Reinforces engine-independence:** C = 0 bypass / 0 emission now holds under a *third* grammar library (llguidance), on a from-source vLLM build — on top of xgrammar (vLLM) and the auxiliary llama.cpp-GBNF / SGLang-xgrammar corroborations. The structural claim does not depend on a single grammar implementation.

### Why this is not a pre-registration deviation of substance
- The grammar **backend is apparatus, not a hypothesis-bearing variable.** The prereg states C is engine-independent **by construction** (§6, §12). No hypothesis can turn on xgrammar-vs-guidance.
- The swap touches the **least hypothesis-sensitive cells**: Control / A1–A4 / D do **not** use a grammar backend (free generation / native tool-calls), so RQ1 and the entire behavioral-leak headline are untouched. Only the C-family cells use the grammar path.
- The change was **forced and directionally neutral** — the engine crashed on the first tool call, so the switch was decided *to make the engine run at all*, before any bypass data existed; both backends enforce the grammar, so C = 0 either way. It cannot favor the hypothesis.
- Recorded here (ADR) + cross-referenced in `preregistration.md` §12 per the prereg's cardinal change-log rule. The locked §3/§5/§8 machinery is unchanged.

### Negative / constraints (read before reproducing)
- **This is the one confirmatory dataset NOT on xgrammar.** For cross-dataset claims, state it: 1.7B blast + steelman = vLLM/xgrammar; Mistral anchor = vLLM/guidance. (It is still vLLM — a backend swap on one engine, not a new engine.)
- **The LARK crash is specific to this combination** — a from-source vLLM v1 build's xgrammar default *and* auto-tool-choice. The packaged vLLM 0.23.0 / 0.17.1 builds ran our path on xgrammar without it. Don't generalize "xgrammar rejects LARK" beyond this build.
- **Provenance gap:** `mistral119_anchor.db` logged `engine_commit = unknown` and `model_id = mistral-119b` (a served alias). The image digest + resolved checkpoint hash must be recorded out-of-band before the DB is paper-grade (a general §10 gap shared by the blast and steelman DBs — tracked in `findings_report.md` §4).

### Follow-up work
1. If a reviewer demands backend-uniformity, re-run only the Mistral **C / C-guided / C+** cells on xgrammar via option 2 (route the native arms off the auto-tool-choice LARK path); the A-arms need no re-run.
2. Capture real provenance (image digest + checkpoint hash) for this DB.
3. C-guided + C+ cells were **not** in this anchor run (blind C only) — a separate tracked gap (`findings_report.md` §5 "Open").

## Notes
- Backend enum + LARK mapping confirmed in-container: `vllm/config/structured_outputs.py`, `vllm/model_executor/.../backend_guidance.py:255–256`.
- This ADR documents an apparatus decision; it makes no formal-proof or new-finding claim.
