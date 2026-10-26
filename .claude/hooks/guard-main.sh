#!/usr/bin/env bash
set -euo pipefail

cmd=$(jq -r '.tool_input.command // empty')
cd "${CLAUDE_PROJECT_DIR:-.}"
branch=$(git branch --show-current 2>/dev/null || true)

if [[ "$cmd" =~ git[[:space:]]+push ]]; then
  if [[ "$cmd" =~ (^|[[:space:]:])(main|master)([[:space:]]|$) ]] || [[ "$branch" == "main" && ! "$cmd" =~ [[:space:]]-u[[:space:]]|--set-upstream ]]; then
    echo "Pushing to main is blocked. Create a feat/* branch and open a PR with /ship." >&2
    exit 2
  fi
fi

if [[ "$cmd" =~ git[[:space:]]+commit && "$branch" == "main" ]]; then
  echo "Committing directly on main is blocked. Switch branch: git switch -c feat/<name>." >&2
  exit 2
fi
