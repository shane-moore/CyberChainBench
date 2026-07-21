#!/bin/bash
set -euo pipefail

# CyberChainBench entry point.
#
# Usage:
#   ./run.sh <command> [options]
#
# Commands:
#   eval -s <setting> [options]   Run evaluation via Harbor (detect/exploit/patch)
#   results [--rescore] [--csv]   Aggregate and display results
#   docker                        Build the cyberchainbench:latest Docker image
#   help                          Show this message
#
# Examples:
#   ./run.sh eval -s codex/gpt-5.4 --task detect -l 5
#   ./run.sh eval -s claude-code/opus-4-6 --task exploit -n 4
#   ./run.sh results --rescore
#   ./run.sh results --rescore --csv results.csv
#   ./run.sh docker
#
# Prerequisites:
#   - .env file with API keys / RPC URLs (see .env.example)
#   - Docker running, cyberchainbench:latest image built (./run.sh docker)
#   - Python deps installed: pip install -e '.[dev]'  (Python 3.12+)

cd "$(dirname "$0")"

# Activate a local virtualenv if present (optional — falls back to system python3).
if [ -f .venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi
export PYTHONPATH=src

# Load .env into the shell environment (harbor/eval read os.environ).
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi
export OPENAI_BASE_URL="${LLM_API_BASE_URL:-http://api.example.com/v1}"
export OPENAI_API_KEY="${LLM_API_KEY:-${OPENAI_API_KEY:-}}"
export CODEX_FORCE_API_KEY=1

usage() {
    sed -n '4,24p' "$0" | sed 's/^# \{0,1\}//'
}

cmd="${1:-help}"
shift || true

case "$cmd" in
    eval)
        exec python3 src/scripts/2_eval/eval.py "$@"
        ;;
    results)
        exec python3 src/scripts/3_results/results.py "$@"
        ;;
    docker)
        exec docker build -t cyberchainbench:latest "$@" .
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        echo "Unknown command: $cmd" >&2
        echo >&2
        usage >&2
        exit 1
        ;;
esac
