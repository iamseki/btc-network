#!/usr/bin/env bash

set -euo pipefail

label="${1:-subject}"
subject="${2:-}"
pattern='^(feat|fix|docs|chore|refactor|test|ci|build)(\([A-Za-z0-9._/-]+\))?: .+'

if [[ -z "$subject" ]]; then
  echo "usage: $0 <label> <subject>" >&2
  exit 2
fi

if [[ ! "$subject" =~ $pattern ]]; then
  echo "::error title=Invalid ${label}::${label^} must match '<type>(<scope>): <summary>' or '<type>: <summary>'."
  echo "Allowed types: feat, fix, docs, chore, refactor, test, ci, build."
  echo "Scope is recommended in this monorepo but optional."
  echo "Example: feat(crawler): add startup recovery guard"
  exit 1
fi
