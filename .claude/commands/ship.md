---
description: Verify the branch, push, and open a PR to main
allowed-tools: Bash(git status), Bash(git log:*), Bash(git push:*), Bash(gofmt:*), Bash(go vet:*), Bash(go test:*), Bash(gh pr create:*), Bash(gh pr view:*), Read
---
Ship the current branch as a PR.

1. Refuse if the current branch is `main` or the working tree is dirty.
2. Run `gofmt -l .`, `go vet ./...`, `go test -race ./...`. If anything fails, stop and report.
3. `git push -u origin HEAD`.
4. Create a PR to `main` with `gh pr create`:
   - Title: a Conventional Commit summarizing the slice.
   - Body: summary, link to `tasks/NNN-*.md`, commit list (`git log main..HEAD --oneline`), contents of `tasks/NNN-*.review.md` (code and security review) if present, and manual verification steps.
5. Print the PR URL. Do not merge; the user reviews and merges with a merge commit.
