#!/usr/bin/env bash
set -euo pipefail

active=$(jq -r '.stop_hook_active // false')
[[ "$active" == "true" ]] && exit 0

cd "${CLAUDE_PROJECT_DIR:-.}"
if ! out=$(go test ./... 2>&1); then
  echo "go test failed, fix it before finishing:" >&2
  echo "$out" | tail -n 40 >&2
  exit 2
fi
