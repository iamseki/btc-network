#!/usr/bin/env bash

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_POSTGRES_ADMIN_URL="${BTC_NETWORK_TEST_POSTGRES_ADMIN_URL:-postgresql://btc_network_dev:btc_network_dev@localhost:5432/postgres}"

COMPONENT_NAMES=()
COMPONENT_TYPES=()
COMPONENT_STATUSES=()
COMPONENT_PASSED=()
COMPONENT_FAILED=()
TOTAL_COMPONENTS_PASSED=0
TOTAL_COMPONENTS_FAILED=0
TOTAL_TESTS_PASSED=0
TOTAL_TESTS_FAILED=0

print_header() {
  printf '\n== %s ==\n' "$1"
}

append_result() {
  local name="$1"
  local kind="$2"
  local status="$3"
  local passed="$4"
  local failed="$5"

  COMPONENT_NAMES+=("$name")
  COMPONENT_TYPES+=("$kind")
  COMPONENT_STATUSES+=("$status")
  COMPONENT_PASSED+=("$passed")
  COMPONENT_FAILED+=("$failed")

  TOTAL_TESTS_PASSED=$((TOTAL_TESTS_PASSED + passed))
  TOTAL_TESTS_FAILED=$((TOTAL_TESTS_FAILED + failed))

  if [[ "$status" == "PASS" ]]; then
    TOTAL_COMPONENTS_PASSED=$((TOTAL_COMPONENTS_PASSED + 1))
  else
    TOTAL_COMPONENTS_FAILED=$((TOTAL_COMPONENTS_FAILED + 1))
  fi
}

extract_default_members() {
  awk '
    /^\[workspace\]/ { in_workspace=1; next }
    /^\[/ && !/^\[workspace\]/ && in_workspace { in_workspace=0 }
    in_workspace && /^default-members = \[/ { in_default=1; next }
    in_default {
      if ($0 ~ /\]/) { in_default=0; next }
      gsub(/"/, "")
      gsub(/,/, "")
      gsub(/^[[:space:]]+/, "")
      gsub(/[[:space:]]+$/, "")
      if (length($0) > 0) print $0
    }
  ' "$ROOT_DIR/Cargo.toml"
}

manifest_value() {
  local manifest="$1"
  local key="$2"
  sed -n "s/^${key} = \"\\([^\"]*\\)\"/\\1/p" "$manifest" | head -n 1
}

run_rust_package() {
  local member_path="$1"
  local manifest_path="$ROOT_DIR/$member_path/Cargo.toml"
  local package_name
  local kind
  local label
  local status="PASS"
  local passed=0
  local failed=0
  local log_file

  package_name="$(manifest_value "$manifest_path" "name")"
  if [[ "$member_path" == crates/* ]]; then
    kind="crate"
  else
    kind="app"
  fi

  label="Rust $kind: $package_name"
  print_header "$label"

  log_file="$(mktemp)"
  if ! (
    cd "$ROOT_DIR"
    if [[ "$package_name" == "btc-network-api" ]]; then
      BTC_NETWORK_TEST_POSTGRES_ADMIN_URL="$TEST_POSTGRES_ADMIN_URL" cargo test -p "$package_name" --locked
    else
      cargo test -p "$package_name" --locked
    fi
  ) 2>&1 | tee "$log_file"; then
    status="FAIL"
  fi

  while IFS= read -r line; do
    if [[ "$line" =~ test\ result:\ (ok|FAILED)\.\ ([0-9]+)\ passed\;\ ([0-9]+)\ failed\;\ ([0-9]+)\ ignored\;\ ([0-9]+)\ measured\;\ ([0-9]+)\ filtered\ out ]]; then
      passed=$((passed + ${BASH_REMATCH[2]}))
      failed=$((failed + ${BASH_REMATCH[3]}))
    fi
  done < "$log_file"

  rm -f "$log_file"
  append_result "$package_name" "$kind" "$status" "$passed" "$failed"
}

run_web_tests() {
  local status="PASS"
  local passed=0
  local failed=0
  local log_file

  print_header "Web app: @btc-network/web"

  log_file="$(mktemp)"
  if ! (
    cd "$ROOT_DIR" &&
      npm run test --prefix apps/web
  ) 2>&1 | tee "$log_file"; then
    status="FAIL"
  fi

  while IFS= read -r line; do
    if [[ "$line" =~ Tests[[:space:]]+([0-9]+)[[:space:]]+passed ]]; then
      passed="${BASH_REMATCH[1]}"
      if [[ "$line" =~ \|[[:space:]]+([0-9]+)[[:space:]]+failed ]]; then
        failed="${BASH_REMATCH[1]}"
      fi
    fi
  done < "$log_file"

  rm -f "$log_file"
  append_result "@btc-network/web" "app" "$status" "$passed" "$failed"
}

print_summary() {
  local index

  print_header "Project Test Summary"
  printf '%-26s %-6s %-6s %6s %6s\n' "component" "type" "status" "passed" "failed"
  printf '%-26s %-6s %-6s %6s %6s\n' "--------------------------" "------" "------" "------" "------"

  for index in "${!COMPONENT_NAMES[@]}"; do
    printf '%-26s %-6s %-6s %6s %6s\n' \
      "${COMPONENT_NAMES[$index]}" \
      "${COMPONENT_TYPES[$index]}" \
      "${COMPONENT_STATUSES[$index]}" \
      "${COMPONENT_PASSED[$index]}" \
      "${COMPONENT_FAILED[$index]}"
  done

  printf '\ncomponents: %s passed, %s failed\n' "$TOTAL_COMPONENTS_PASSED" "$TOTAL_COMPONENTS_FAILED"
  printf 'tests:      %s passed, %s failed\n' "$TOTAL_TESTS_PASSED" "$TOTAL_TESTS_FAILED"
}

main() {
  local member_path
  local exit_code=0

  while IFS= read -r member_path; do
    run_rust_package "$member_path"
  done < <(extract_default_members)

  run_web_tests
  print_summary

  if (( TOTAL_COMPONENTS_FAILED > 0 )); then
    exit_code=1
  fi

  exit "$exit_code"
}

main "$@"
