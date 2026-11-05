#!/usr/bin/env bash
# Run one AgentDojo cell (one suite x one backbone) of the paper's breadth grid with the paper's settings:
# suite v1.2.2, the important_instructions attack, the full user x injection task grid, the defense switches
# --auto --access-grant --chatml-guard --exfil-provenance, and the SPW_* environment the runner sets
# (reproduce/README.md lists every setting).
#
#   reproduce/run_cell.sh <suite> <backbone> [extra spillway-agentdojo arguments]
#
#   suite      banking | slack | travel | workspace
#   backbone   qwen3:8b | qwen3-coder:30b | gpt-4o-mini-2024-07-18   (any Ollama tag or OpenAI model id)
#
# Examples
#   reproduce/run_cell.sh banking qwen3:8b                      # under attack: UAU and ASR of the cell
#   reproduce/run_cell.sh banking qwen3:8b --attack none        # benign run: BU of the cell
#   reproduce/run_cell.sh workspace qwen3:8b --user-tasks user_task_0 --injection-tasks injection_task_0
#
# Environment (all optional)
#   SPW_OLLAMA_URL   judge server, and the agent server for a local backbone   (default http://127.0.0.1:11434)
#   SPW_VOTERS       judge model tag(s), comma separated                        (default gemma4:31b)
#   SPW_OUT_DIR      where summaries and per-pair logs go                       (default ./spillway_runs)
#   SPW_RUN_ID       run id; also the summary tag, so reruns never overwrite    (default: timestamp)
#   OPENAI_API_KEY   needed for a gpt-* backbone (OPENAI_BASE_URL must be unset)
#   SPW_SKIP_PREFLIGHT=1   skip the judge-server check below
set -euo pipefail

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

if [[ $# -lt 2 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage; exit 2
fi
suite="$1"; backbone="$2"; shift 2
case "$suite" in
  banking|slack|travel|workspace) ;;
  *) echo "run_cell.sh: unknown suite '$suite' (banking | slack | travel | workspace)" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SPW_OLLAMA_URL="${SPW_OLLAMA_URL:-http://127.0.0.1:11434}"
export SPW_VOTERS="${SPW_VOTERS:-gemma4:31b}"
export SPW_OUT_DIR="${SPW_OUT_DIR:-$PWD/spillway_runs}"
run_id="${SPW_RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
backbone_safe="$(printf '%s' "$backbone" | tr ':/' '__')"
logdir="$SPW_OUT_DIR/cells/${suite}_${backbone_safe}"

is_openai_api=0
case "$backbone" in
  gpt-oss*) ;;
  gpt-*|o1*|o3*|o4*) is_openai_api=1 ;;
esac
if [[ $is_openai_api -eq 1 ]]; then
  [[ -n "${OPENAI_API_KEY:-}" ]] || { echo "run_cell.sh: OPENAI_API_KEY is unset (needed for $backbone)" >&2; exit 2; }
  [[ -z "${OPENAI_BASE_URL:-}" ]] || { echo "run_cell.sh: unset OPENAI_BASE_URL; the OpenAI backbone must reach api.openai.com" >&2; exit 2; }
fi

# With the judge unreachable, every judge request counts as a no, which changes utility, so the server and the
# judge model are checked first. A local backbone is served by the same server.
if [[ "${SPW_SKIP_PREFLIGHT:-0}" != "1" ]]; then
  if ! tags="$(curl -sS --max-time 10 "$SPW_OLLAMA_URL/api/tags" 2>/dev/null)"; then
    echo "run_cell.sh: no Ollama server at $SPW_OLLAMA_URL (set SPW_OLLAMA_URL, or SPW_SKIP_PREFLIGHT=1)" >&2; exit 1
  fi
  IFS=',' read -r -a wanted <<< "$SPW_VOTERS"
  [[ $is_openai_api -eq 1 ]] || wanted+=("$backbone")
  for model in "${wanted[@]}"; do
    model="${model// /}"
    if ! printf '%s' "$tags" | python3 -c '
import json, sys
want = sys.argv[1]
names = {m.get("name", "") for m in json.load(sys.stdin).get("models", [])}
sys.exit(0 if want in names or want + ":latest" in names else 1)' "$model"; then
      echo "run_cell.sh: model '$model' is not on the server at $SPW_OLLAMA_URL (ollama pull $model)" >&2; exit 1
    fi
  done
fi

if command -v spillway-agentdojo >/dev/null 2>&1; then
  runner=(spillway-agentdojo)
else
  export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
  runner=(python3 -m spillway_guard.agentdojo.runner)
fi

mkdir -p "$logdir"
echo "run_cell.sh: suite=$suite backbone=$backbone judge=$SPW_VOTERS server=$SPW_OLLAMA_URL run_id=$run_id" >&2
echo "run_cell.sh: logs -> $logdir ; summary -> $SPW_OUT_DIR/summary_${suite}_${backbone_safe}_*_${run_id}.json" >&2
# Later arguments win in argparse, so "$@" can override any of the defaults below (for example --attack none).
exec "${runner[@]}" \
  --suite "$suite" --agent-model "$backbone" --attack important_instructions \
  --auto --access-grant --chatml-guard --exfil-provenance \
  --logdir "$logdir" --run-id "$run_id" --summary-tag "$run_id" \
  "$@"
