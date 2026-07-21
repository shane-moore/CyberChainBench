#!/bin/bash
# Resume evaluation — only run cases that haven't completed yet.
#
# Usage:
#   ./run_resume.sh -s codex/gpt-5.4 --task detect -n 8
#   ./run_resume.sh -s codex/gpt-5.5 --task patch -n 4
#   ./run_resume.sh -s codex/gpt-5.2 --task exploit -n 16 --subset
#
# Options:
#   --subset    Use exploit_subset200 instead of full exploit set
#
# This script:
#   1. Finds the latest result dir for the given setting+task
#   2. Identifies completed case IDs (has result.json)
#   3. Creates a temp dir with symlinks to only unfinished cases
#   4. Runs harbor on the remaining cases

set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate
export PYTHONPATH=src

# Load .env
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# Parse arguments
SETTING=""
TASKS=()
CONCURRENCY=8
USE_SUBSET=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s) SETTING="$2"; shift 2 ;;
        --task|-t) TASKS+=("$2"); shift 2 ;;
        -n) CONCURRENCY="$2"; shift 2 ;;
        --subset) USE_SUBSET=true; shift ;;
        *) EXTRA_ARGS+=("$1"); shift ;;
    esac
done

if [ -z "$SETTING" ]; then
    echo "Usage: ./run_resume.sh -s <setting> --task <task> [-n <concurrency>] [--subset]"
    exit 1
fi

# Extract agent and model from setting
IFS='/' read -r AGENT MODEL <<< "$SETTING"

# Map to harbor agent import path
declare -A AGENT_IMPORTS=(
    ["codex"]="harbor.agents.installed.codex:Codex"
    ["claude-code"]="harbor.agents.installed.claude_code:ClaudeCode"
    ["gemini-cli"]="harbor.agents.installed.gemini_cli:GeminiCli"
    ["aider"]="harbor.agents.installed.aider:Aider"
    ["swe-agent"]="harbor.agents.installed.swe_agent:SweAgent"
    ["openhands"]="harbor.agents.installed.openhands:OpenHands"
    ["opencode"]="harbor.agents.installed.opencode:OpenCode"
    ["hermes"]="harbor.agents.installed.hermes:Hermes"
)

AGENT_IMPORT="${AGENT_IMPORTS[$AGENT]:-}"
if [ -z "$AGENT_IMPORT" ]; then
    echo "Unknown agent: $AGENT"
    exit 1
fi

# Get model in harbor format (agent/model -> provider/model)
HARBOR_MODEL="openai/$MODEL"

# Setup env vars
export OPENAI_API_KEY="${LLM_API_KEY:-$ANTHROPIC_API_KEY}"
export OPENAI_BASE_URL="${LLM_API_BASE_URL:-http://api.example.com/v1}"
export CODEX_FORCE_API_KEY=1

if [ ${#TASKS[@]} -eq 0 ]; then
    TASKS=("detect" "exploit" "patch")
fi

for TASK in "${TASKS[@]}"; do
    echo ""
    echo "=== Resuming: $SETTING / $TASK (concurrency=$CONCURRENCY) ==="

    # Determine source task dir
    if [ "$TASK" = "exploit" ] && [ "$USE_SUBSET" = true ]; then
        TASK_DIR="data/benchmark/harbor_tasks/exploit_subset200"
    else
        TASK_DIR="data/benchmark/harbor_tasks/$TASK"
    fi

    if [ ! -d "$TASK_DIR" ]; then
        echo "  [SKIP] $TASK_DIR does not exist"
        continue
    fi

    # Find ALL result dirs and collect VALID completed case IDs
    # Only count as completed if agent actually responded (not timeout/no_response)
    RESULT_BASE="data/eval/$TASK/$AGENT/$MODEL"

    COMPLETED=()
    if [ -d "$RESULT_BASE" ]; then
        while IFS= read -r f; do
            # Check if this is a real result (not timeout/no_response)
            details_file="$(dirname "$f")/details.json"
            if [ -f "$details_file" ]; then
                is_timeout=$(python3 -c "
import json
d = json.loads(open('$details_file').read())
det = d.get('details', {})
# Skip if no_agent_response or if agent_response is null/empty
if det.get('error') == 'no_agent_response':
    print('yes')
elif det.get('agent_response') is None and det.get('best_score') is None and det.get('best_profit_usd') is None:
    print('yes')
else:
    print('no')
" 2>/dev/null)
                if [ "$is_timeout" = "yes" ]; then
                    continue
                fi
            fi
            # Extract case ID from dir name like "detect_bench-234__ABC123"
            dirname=$(basename "$(dirname "$(dirname "$f")")")
            case_id=$(echo "$dirname" | sed 's/^[a-z]*_//' | sed 's/__.*$//')
            COMPLETED+=("$case_id")
        done < <(find "$RESULT_BASE" -path "*/verifier/reward.json" 2>/dev/null)
    fi

    TOTAL=$(ls -d "$TASK_DIR"/${TASK}_* 2>/dev/null | wc -l)
    DONE=${#COMPLETED[@]}
    REMAINING=$((TOTAL - DONE))

    echo "  Total: $TOTAL, Completed: $DONE, Remaining: $REMAINING"

    if [ "$REMAINING" -le 0 ]; then
        echo "  All cases completed!"
        continue
    fi

    # Create temp dir with only unfinished cases
    RESUME_DIR="/tmp/harbor_resume_${TASK}_${MODEL}"
    rm -rf "$RESUME_DIR"
    mkdir -p "$RESUME_DIR"

    for case_dir in "$TASK_DIR"/${TASK}_*; do
        case_name=$(basename "$case_dir")
        # Extract case ID: e.g., "detect_bench-234" -> "bench-234"
        case_id=$(echo "$case_name" | sed "s/^${TASK}_//")

        # Skip if already completed
        skip=false
        for done_id in "${COMPLETED[@]}"; do
            if [ "$case_id" = "$done_id" ]; then
                skip=true
                break
            fi
        done

        if [ "$skip" = false ]; then
            ln -sf "$(realpath "$case_dir")" "$RESUME_DIR/$case_name"
        fi
    done

    LINKED=$(ls "$RESUME_DIR" | wc -l)
    echo "  Symlinked $LINKED remaining cases to $RESUME_DIR"

    # Write .env.runtime to remaining tasks
    ENV_RUNTIME=""
    for key in $(env | grep -E "_RPC_URL=|ETHERSCAN" | cut -d= -f1); do
        val="${!key}"
        if [ -n "$val" ]; then
            ENV_RUNTIME="${ENV_RUNTIME}${key}=${val}\n"
        fi
    done
    for dir in "$RESUME_DIR"/${TASK}_*/environment; do
        # .env.runtime holds real RPC URLs and the Etherscan key; keep it
        # owner-only (0600) so it is not world-readable, matching eval.py.
        printf "$ENV_RUNTIME" > "$dir/.env.runtime" 2>/dev/null && \
            chmod 600 "$dir/.env.runtime" 2>/dev/null
    done

    # Run harbor
    echo "  Running harbor ($LINKED cases, $CONCURRENCY concurrent)..."
    harbor run --yes \
        --path "$RESUME_DIR" \
        --agent-import-path "$AGENT_IMPORT" \
        --model "$HARBOR_MODEL" \
        -n "$CONCURRENCY" \
        -o "$RESULT_BASE" \
        --artifact /app/workspace \
        --ae "OPENAI_API_KEY=$OPENAI_API_KEY" \
        --ae "OPENAI_BASE_URL=$OPENAI_BASE_URL" \
        --ae "CODEX_FORCE_API_KEY=1" \
        --ae "NO_PROXY=api.example.com,localhost,127.0.0.1" \
        --ae "ETHERSCAN_API_KEYS=${ETHERSCAN_API_KEYS:-}" \
        $(env | grep "_RPC_URL=" | sed 's/^/--ae /' | tr '\n' ' ') \
        "${EXTRA_ARGS[@]}"

    # Cleanup
    rm -rf "$RESUME_DIR"
done

echo ""
echo "=== Resume complete ==="
