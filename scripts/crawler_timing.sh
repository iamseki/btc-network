#!/usr/bin/env bash
set -euo pipefail

# Runs crawler with verbose timing logs enabled, saves raw logs, extracts timing
# events to NDJSON, and computes aggregate metrics (count/avg/p95/max).
#
# Usage:
#   scripts/crawler_timing.sh [output_dir] [--timeout-minutes N] [-- crawler args...]

OUT_DIR="artifacts/crawler-timing"
if [[ $# -gt 0 && "${1}" != -* ]]; then
  OUT_DIR="$1"
  shift
fi

TIMEOUT_MINUTES=""
CRAWLER_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout-minutes)
      TIMEOUT_MINUTES="$2"
      shift 2
      ;;
    --)
      shift
      CRAWLER_ARGS+=("$@")
      break
      ;;
    *)
      CRAWLER_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -n "${TIMEOUT_MINUTES}" ]]; then
  CRAWLER_ARGS=(--max-runtime-minutes "${TIMEOUT_MINUTES}" "${CRAWLER_ARGS[@]}")
fi

mkdir -p "${OUT_DIR}"

RAW_LOG="${OUT_DIR}/crawler.log"
TIMING_NDJSON="${OUT_DIR}/timing.ndjson"
SUMMARY_JSON="${OUT_DIR}/timing-summary.json"

echo "writing raw log to: ${RAW_LOG}"
echo "writing timing events to: ${TIMING_NDJSON}"
echo "writing summary to: ${SUMMARY_JSON}"

cargo run --bin crawler -- --verbose "${CRAWLER_ARGS[@]}" 2>&1 | tee "${RAW_LOG}" >/dev/null

jq -Rrc '
  fromjson?
  | select(
      .fields.message == "[crawler] worker timing" or
      .fields.message == "[crawler] node timing"
    )
' "${RAW_LOG}" > "${TIMING_NDJSON}"

jq -s -f scripts/crawler_timing_summary.jq "${TIMING_NDJSON}" > "${SUMMARY_JSON}"

echo
echo "done"
echo "  raw log:      ${RAW_LOG}"
echo "  timing file:  ${TIMING_NDJSON}"
echo "  summary file: ${SUMMARY_JSON}"
