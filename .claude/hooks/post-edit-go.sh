#!/usr/bin/env bash
set -euo pipefail

file=$(jq -r '.tool_input.file_path // empty')
[[ "$file" == *.go ]] || exit 0
[[ -f "$file" ]] || exit 0

gofmt -w "$file"

cd "${CLAUDE_PROJECT_DIR:-.}"
if ! out=$(go vet "./$(dirname "${file#"$PWD"/}")/..." 2>&1); then
  echo "go vet failed after editing $file:" >&2
  echo "$out" >&2
  exit 2
fi
