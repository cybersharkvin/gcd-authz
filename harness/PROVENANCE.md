# Provenance — confirmatory result DBs

Out-of-band provenance for the result DBs cited in `docs/findings_report.md`. **Required because all three DBs have `engine_commit = unknown` and `model_id = served-alias` in the trial rows** (the `ENGINE_COMMIT` env was not set on those victim launches). Prereg §10 names reproducibility "the primary validity concern," so this file records the engine image digests (verified from `docker images --digests`) and launch facts from operator notes until the DBs themselves can be re-stamped or the runs reproduced.

**Confidence:** image digests below are **verified** (read from the live/cached image on the host that ran the cell). Launch flags are from operator notes (this session's memory) and should be treated as **high-confidence-but-not-cryptographically-tied** to the rows. HF checkpoint revision hashes are **still TODO** (see bottom).

**Backfill applied 2026-06-22:** the `engine_commit` column in all three DBs (which logged `unknown` at runtime — the `ENGINE_COMMIT` env was unset on those launches) has been set out-of-band from the verified digests below: blast NVFP4 rows → `vllm-openai-0.23.0-oob`, blast BF16 rows → `vllm-therock-0.22.1rc1-oob`, mistral → `vllm-ms4-fromsrc-oob`, steelman → `vllm-openai-0.17.1-oob`. The **`-oob` suffix marks an out-of-band backfill, not a runtime capture**; this file is the authoritative full-digest record. (Result DBs are gitignored, so this backfill is a local-artifact change.) Native runtime stamping is still required for future runs (checklist at bottom).

---

## `harness/blast_1p7b_5m.db` — 1.7B generator×gate factorial (2,370,741 trials)

| field | value |
|---|---|
| host | Host A — **two engines** (see below); 1 instance/card |
| engine — NVFP4 rows (2,070,912 trials, 5090s, all cycles) | `vllm/vllm-openai:latest` (v0.23.0) — `sha256:6d8429e38e3747723ca07ee1b17972e09bb9c51c4032b266f24fb1cc3b22ed8f`; backfill tag `vllm-openai-0.23.0-oob` |
| engine — BF16 rows (299,829 trials, **R9700 / ROCm**, early cycles ≤ 2026-06-19 23:01) | `kyuz0/vllm-therock-gfx1201:latest` (v0.22.1rc1) — `sha256:55fa7796374a281e4b77a05cc2f26391d4100a5abb738f77c580ebc3951761e9`; backfill tag `vllm-therock-0.22.1rc1-oob` |
| grammar backend | xgrammar (both), via `structured_outputs.grammar` |
| victim model(s) | `kaitchup/Qwen3-1.7B-NVFP4` (alias `qwen3-1p7b-nvfp4`, NVFP4 engine); `Qwen/Qwen3-1.7B` BF16 (alias `qwen3-1p7b-bf16`, ROCm engine) |
| key flags | `--enable-auto-tool-choice --tool-call-parser hermes` (NO `--reasoning-parser`), `--enable-prefix-caching` |
| victim env | `LLM_BACKEND=vllm LLM_THINKING_KWARG=on MAX_TURNS=6`, temp 0.6 |
| containers (exited) | `vllm-g0`, `vllm-g1` |

## `harness/mistral119_anchor.db` — capable non-Qwen anchor (37,872 trials)

| field | value |
|---|---|
| host | Host B (`vg` = internal-host), 4× RTX 5090, TP=4 |
| engine image | `mistralllm/vllm-ms4:latest` (from-source vLLM v1, sm120) |
| **image digest** | `sha256:47b98aa31f2e201dfb57f3c1bf140f03e4ef0298d0cd0a77b62e101d034149bb` |
| grammar backend | **guidance / llguidance** via `--structured-outputs-config '{"backend":"guidance"}'` (xgrammar rejects the auto-tool-choice LARK grammar — see ADR 0005) |
| victim model | `mistralai/Mistral-Small-4-119B-2603-NVFP4` (alias `mistral-119b`) |
| key flags | `--tensor-parallel-size 4 --max-model-len 8192 --gpu-memory-utilization 0.90 --attention-backend TRITON_MLA --max-num-batched-tokens 2048 --enable-auto-tool-choice --tool-call-parser mistral` (NO `--reasoning-parser`); NCCL P2P/SHM **enabled** |
| victim env | `LLM_BACKEND=vllm LLM_THINKING_KWARG=off`, temp 0.6 |
| harness link | Host A harness → `SSH tunnel` → engine `:11435` |

## `harness/steelman_abliterated.db` — abliterated steelman (4,000 trials)

| field | value |
|---|---|
| host | Host A, 2× RTX 5090, TP=2 |
| engine image | `vllm/vllm-openai:v0.17.1` (container `vllm-ablit`, still up as of this writing) |
| **image digest** | `sha256:0dc46f74eb0e630675d83101dc66c6441c4475cceedcf9235ee42b87c3affd23` |
| grammar backend | xgrammar, via `structured_outputs.grammar` |
| victim model | `lyf/Huihui-Qwen3.5-27B-abliterated-NVFP4` (alias `q35`) |
| key flags | `--tensor-parallel-size 2 --enforce-eager --gpu-memory-utilization 0.55 --enable-auto-tool-choice --tool-call-parser qwen3_coder` |
| victim env | `LLM_BACKEND=vllm LLM_THINKING_KWARG=on MAX_TURNS=6`; `CONTROL_TEMPLATE`+`ROUND1_TEMPLATE`=`harness/prompts/malicious-control.tmpl` |

---

## MTP setting (prereg §10/§6 require it logged)

**Not applicable / off for all three runs.** MTP (multi-token prediction / speculative) was a *llama.cpp*-era setting; none of these vLLM launches enabled speculative decoding. The prereg's open "MTP on vs off" decision (§12) pertained to the llama.cpp anchor era and is moot for the vLLM confirmatory runs (recorded here so the §6/§10 MTP-logging requirement is satisfied: MTP = off/N-A).

## Still TODO (before any of these is paper-grade)

1. **HF checkpoint revision hashes** — record the exact resolved snapshot commit for each model repo (`huggingface-cli download <repo> --revision <hash>` or read the cache snapshot dir), not just the repo ID. Repos: `kaitchup/Qwen3-1.7B-NVFP4`, `Qwen/Qwen3-1.7B`, `mistralai/Mistral-Small-4-119B-2603-NVFP4`, `lyf/Huihui-Qwen3.5-27B-abliterated-NVFP4`.
2. **Re-stamp future runs at the source** — set `ENGINE_COMMIT` (image digest) and a real `LLM_MODEL` (repo@revision, not a bare alias) on the victim env so the trial rows carry provenance natively. Launch checklist:
   - `ENGINE_COMMIT=$(docker inspect --format '{{index .RepoDigests 0}}' <engine-image>)`
   - `LLM_MODEL=<repo>@<resolved-revision>`
   - verify post-run: `sqlite3 <db> "SELECT DISTINCT engine_commit, model_id FROM trials;"` ≠ `unknown`.
