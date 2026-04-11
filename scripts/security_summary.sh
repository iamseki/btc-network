#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_LINES="${SECURITY_LOG_LINES:-40}"
VERBOSE="${SECURITY_VERBOSE:-0}"
KEEP_LOGS="${SECURITY_KEEP_LOGS:-0}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_ROOT="${ROOT_DIR}/.dev-data/security-logs"
RUN_LOG_DIR="${LOG_ROOT}/${RUN_ID}"

STEP_NAMES=()
STEP_STATUSES=()
STEP_LOGS=()
FAILED_STEPS=0

mkdir -p "${RUN_LOG_DIR}"

append_result() {
  STEP_NAMES+=("$1")
  STEP_STATUSES+=("$2")
  STEP_LOGS+=("$3")

  if [[ "$2" != "PASS" && "$2" != "SKIP" ]]; then
    FAILED_STEPS=$((FAILED_STEPS + 1))
  fi
}

print_failure_excerpt() {
  local log_file="$1"

  printf 'Last %s log lines:\n' "${LOG_LINES}"
  tail -n "${LOG_LINES}" "${log_file}"
}

run_step() {
  local label="$1"
  shift

  local log_file="${RUN_LOG_DIR}/$(printf '%s' "${label}" | tr '[:upper:]' '[:lower:]' | tr ' /' '__').log"

  printf '\n== %s ==\n' "${label}"

  if [[ "${VERBOSE}" == "1" ]]; then
    if (
      cd "${ROOT_DIR}" &&
        "$@"
    ) 2>&1 | tee "${log_file}"; then
      printf '[PASS] %s\n' "${label}"
      append_result "${label}" "PASS" "${log_file}"
      return 0
    fi
  else
    if (
      cd "${ROOT_DIR}" &&
        "$@"
    ) >"${log_file}" 2>&1; then
      printf '[PASS] %s\n' "${label}"
      append_result "${label}" "PASS" "${log_file}"
      return 0
    fi
  fi

  printf '[FAIL] %s\n' "${label}"
  print_failure_excerpt "${log_file}"
  printf 'Full log: %s\n' "${log_file}"
  append_result "${label}" "FAIL" "${log_file}"
  return 1
}

skip_step() {
  local label="$1"
  local reason="$2"
  local log_file="${RUN_LOG_DIR}/$(printf '%s' "${label}" | tr '[:upper:]' '[:lower:]' | tr ' /' '__').log"

  printf '\n== %s ==\n' "${label}"
  printf '[SKIP] %s: %s\n' "${label}" "${reason}"
  printf '%s\n' "${reason}" >"${log_file}"
  append_result "${label}" "SKIP" "${log_file}"
}

print_summary() {
  local i

  printf '\n== Security Summary ==\n'
  printf '%-28s %-6s\n' "step" "status"
  printf '%-28s %-6s\n' "----------------------------" "------"

  for i in "${!STEP_NAMES[@]}"; do
    printf '%-28s %-6s\n' "${STEP_NAMES[$i]}" "${STEP_STATUSES[$i]}"
  done
}

maybe_cleanup_logs() {
  if (( FAILED_STEPS > 0 )) || [[ "${KEEP_LOGS}" == "1" ]]; then
    printf '\nLogs kept under %s\n' "${RUN_LOG_DIR}"
    return
  fi

  rm -rf "${RUN_LOG_DIR}"
}

main() {
  local exit_code=0

  run_step "Rust audit" make --no-print-directory security-rust-audit || exit_code=1
  run_step "Rust deny" make --no-print-directory security-rust-deny || exit_code=1

  if getent ahosts registry.npmjs.org >/dev/null 2>&1; then
    run_step "Web audit" make --no-print-directory security-web-audit || exit_code=1
    run_step "Web signatures" make --no-print-directory security-web-signatures || exit_code=1
  else
    skip_step "Web audit" "npm registry is unreachable"
    skip_step "Web signatures" "npm registry is unreachable"
  fi

  print_summary
  maybe_cleanup_logs
  exit "${exit_code}"
}

main "$@"
