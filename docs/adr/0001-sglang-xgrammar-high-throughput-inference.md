# ADR 0001 — SGLang + xgrammar for high-throughput grammar-constrained inference

- **Status:** Accepted (throughput architecture). llama.cpp/GBNF retained as the correctness anchor; full per-condition migration is a tracked follow-up, not yet done.
- **Date:** 2026-06-10
- **Deciders:** Vince (researcher), Claude (Opus 4.8)
- **Supersedes / relates to:** the "multi-server llama.cpp per GPU" throughput approach (techContext.md). Does **not** change the experiment design (7 conditions, win semantics, corpus).

## Context and problem statement

The experiment needs ~1,008,000 inference requests (7 conditions × 4 model families × 36k), each a multi-turn agent trial. Throughput is the gating constraint on finishing the paper.

Measured facts on llama.cpp (our original engine):

- **One llama.cpp server caps a GPU at ~40% util.** Root cause (confirmed via maintainers, llama.cpp discussion #18308): sampling runs on the **CPU, once per sequence, every decode tick**. At `-np 16` the server serializes 16 CPU sampling ops while the GPU idles.
- **Condition C (GBNF grammar) is worse — ~6% util, fully CPU-bound** on the grammar mask (a per-token, per-sequence, ~150k-vocab intersection on CPU). `--backend-sampling` (`-bs`, GPU sampling) gives ~2.08× for the non-grammar conditions but **does nothing for C** (the grammar mask stays on CPU).
- Workaround was **4 llama.cpp server processes per GPU** (one CPU sampler each) → ~95% util, ~96 req/min/GPU for the 2B; 16 servers / 4 GPUs ≈ 359 req/min (validated 10,152-trial run in 28.8 min).

The multi-server hack is operationally clunky and does not fix C's grammar-mask cliff. We needed an engine where (a) one instance saturates the GPU via real continuous batching, and (b) grammar-constrained decoding is not a throughput cliff.

## Decision

**Adopt SGLang + xgrammar as the high-throughput inference path, one instance per GPU, with continuous batching at high `--max-running-requests` (multi-slot) and thinking disabled.** Keep llama.cpp/GBNF as a cross-engine 0-bypass correctness anchor.

Rationale — SGLang fixes both bottlenecks structurally:

- **GPU-side sampling + continuous batching** → one instance saturates the card. Measured: a single instance held **256 concurrent streams at 85% GPU util** (see Evidence).
- **xgrammar** (SGLang's default grammar backend) precomputes that ~99% of vocab tokens are context-independent per grammar → mask drops to <40µs, plus **jump-forward decoding** emits the deterministic JSON scaffolding of our R2 grammar in single steps. Grammar is **no longer CPU-bound** — the exact cliff `-bs` couldn't touch.
- Our R2 GBNF ports to SGLang's `ebnf` field nearly as-is (xgrammar uses GGML-BNF-style grammar).

## Evidence (measured 2026-06-10, 1× RTX 5090)

**256-stream throughput proof — Qwen3-1.7B, thinking off, `--max-running-requests 256`, no token cap:**

| metric | value |
|---|---|
| requests | 10,000 (0 errors) |
| peak concurrent streams | **256** (sustained 255–256) |
| GPU util | 85% mean / 100% max |
| wall | 2,802 s (46.7 min) |
| tokens generated | 20,474,039 (every request hit the 2048 cap → token worst-case) |
| steady-state | ~12,900 tok/s/GPU (avg 7,300 incl. ramp + drain) |

The 46.7 min was **token volume, not a concurrency limit** — the GPU was saturated the whole run; the benchmark prompt ("be thorough") plus the uncapped 2048 tokens/request produced ~20M tokens (5–20× a real agent turn). Throughput is **token-bound**: `wall ≈ total_output_tokens / aggregate_decode_rate`.

**1M-request projection (4× 5090, ~48k tok/s aggregate):**

| tokens/request | 1M on 4 GPUs |
|---|---|
| ~400 (realistic short agent turn) | **~2–3 hours** |
| 2048 (this worst case) | **~12 hours** |

**Grammar (Condition C) on xgrammar — Qwen3.6-35B-A3B NVFP4:** 48 grammar requests in 5.5 s, **not grammar-bound** (vs llama.cpp's 6%-util CPU cliff), and **0 bypass preserved**: 128 adversarial exfil prompts → 45/45 `fetchURL` calls to safe URLs, 0 to attacker sinks. Same structural guarantee as GBNF.

## Considered options

1. **llama.cpp, 4 servers/GPU (status quo).** Works (~359 req/min, 2B) but clunky and leaves Condition C on the CPU grammar-mask cliff. Rejected as the bulk engine; retained as correctness anchor.
2. **llama.cpp + `--backend-sampling`.** ~2× for Control/A1–A4, **zero** for C. Insufficient — C is the headline condition. Rejected as a standalone fix.
3. **SGLang + xgrammar (chosen).** Saturates one instance, fixes the grammar cliff, preserves 0-bypass.
4. **vLLM + xgrammar.** Comparable engine; better GGUF loading. Viable fallback, not chosen (SGLang's compressed-FSM/jump-forward + RadixAttention is the closest fit and loaded our target checkpoint).

## Consequences

### Positive
- One instance/GPU saturates the card; the multi-server hack is retired for SGLang runs.
- Condition C is no longer a throughput cliff — grammar runs at batch speed.
- 1M requests is reachable in hours-to-half-a-day on 4 GPUs, dominated only by tokens/request.
- Reinforces the thesis: 0-bypass holds on a *second* engine/grammar mechanism (xgrammar compiled FSM, not just llama.cpp's token-stack mask) → strengthens the "structural, engine-independent" claim.

### Negative / constraints (the gotchas — read before reproducing)
- **256 slots is a small-model capability.** It requires a small model (e.g. 1.7B: ~3.5 GB weights → ~26 GB KV). The capable **Qwen3.6-35B-A3B is a hybrid mamba model and caps ~25–50 slots/GPU** (each slot carries an SSM state, not just cheap KV; 22.4 GB weights leave only ~6 GB for caches). So: **small model = bulk/throughput engine; the 35B-A3B anchor runs a confirmatory subset at lower concurrency.**
- **Model loading is the fragile part, not the grammar.** Local Qwen3.5/3.6 **GGUFs do NOT load in SGLang** (nonstandard arch string `qwen35`/`qwen36` rejected by transformers' GGUF loader). Use HF **safetensors**. For Qwen3.6 NVFP4: the **`nvidia/...-NVFP4` checkpoint is the vLLM one and crashes SGLang** on the hybrid `ba_proj` layer (size-32 ÷ block-128); use the **SGLang-targeted `mmangkad/Qwen3.6-35B-A3B-NVFP4`** (its `hf_quant_config.json` excludes `*.linear_attn*`/`*.shared_expert*` from quantization). Hybrid models also need `--mem-fraction-static ~0.90 --max-running-requests <small> --context-length <small>` or the mamba state cache is too small to serve.
- **Image freshness matters.** Qwen3.6 needs `sglang >= 0.5.10` / current `lmsysorg/sglang:dev-cu13`. The stale `dev-cu13-mistral-medium-3.5` (built 2026-04-29) is too old.
- **Wire-format change for Condition C (I/O boundary).** `tantalus-llm` currently sends the GBNF in the llama.cpp `grammar` field (`crates/tantalus-llm/src/lib.rs:152`). SGLang needs it as `ebnf` inside `sampling_params` (or `extra_body` for the OpenAI route). This is a gated patch (e.g. `LLM_BACKEND=sglang` → `body["ebnf"]` instead of `body["grammar"]`). The R2 GBNF transfers near-verbatim.
- **Free-text params remain unconstrained.** xgrammar (like GBNF) locks structure + enum params (`fetchURL.url`, paths, channels, email ids) but **not** free strings (`searchFiles.query`, `respondToUser.message`). Attacker strings can appear there — that is **not** an action-integrity bypass (Paper-2/confidentiality scope). Win = attacker URL in the `fetchURL` sink, which stayed at 0. Naive "attacker substring anywhere" detection FALSE-FAILS.

### Follow-up work
1. ~~Wire `tantalus-local` → SGLang and run the **agentic** 10k to get real experiment turns/min.~~ **DONE 2026-06-10.** Gated `tantalus-llm` on `LLM_BACKEND=sglang` (grammar→`ebnf` top-level, `chat_template_kwargs.enable_thinking=false`; `crates/tantalus-llm/src/lib.rs`). Tool-call parser `qwen25` + reasoning parser `qwen3`. Ran the full **agentic** red-team harness (6 live conditions × 1667 attack + 25 legit, corpus_full.json) against **4× SGLang Qwen3-1.7B** (one instance/5090, 256 slots each, ports 30000–30003; 4 victims on 3360–3363). **10,152 trials in 4:57 (297 s), ~2,050/min blended (Control/A1 ~4,000/min), 0 errors.** vs the 2B llama.cpp run's 28.8 min ≈ **5.8× faster on the real agentic loop** (multi-turn, not raw flood). Result reproduces the thesis on a **second engine + grammar mechanism**: Control 13.4% / A1 13.2% / A2 11.1% / A3 5.0% / A4 5.6% / **C(GCD) 0.0% bypass, 0 emission, 0 d_blocked_calls** (D==C invariant holds on xgrammar too). Low absolute potency is the 1.7B (weaker than the 2B's 53%); apparatus/throughput validation, not a headline victim. DB: `harness/sglang_agentic_10k.db`.
2. Acquire a SGLang-loadable small Qwen for the bulk victim — our 2B is GGUF-locked; this run used public Qwen3-1.7B.
3. Per-family Control-potency floor check still applies before trusting any new victim's leak numbers.

## Notes
- Bench artifacts: `/tmp/bsbench/` (`flood_sglang.py`, `bypass_probe2.py`, `r2.gbnf`). Models in `/REDACTED/sglang_models/`.
- Infra: borrow a 5090 with `docker stop <live-container>` (transient; restart:always does NOT recreate a manually-stopped container — confirmed no supervisor), `docker start` to restore. Map the **live** container via `nvidia-smi --query-compute-apps` → PID → cgroup, not a stale id. Never `docker update` configs (user boundary).
