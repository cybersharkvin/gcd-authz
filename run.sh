#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ -f .env ]; then set -a; source .env; set +a; fi

cargo build -q 2>&1 | tail -5
echo "tantalus-local → http://localhost:${PORT:-3333}"
echo "LLM: ${LLM_ENDPOINT:-http://localhost:11450} (${LLM_MODEL:-qwen3.6-35b})"
exec ./target/debug/tantalus-local
