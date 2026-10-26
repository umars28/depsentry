---
description: Write a new ADR in docs/adr from the template
argument-hint: <decision title>
allowed-tools: Read, Write, Glob, Bash(git add:*), Bash(git commit:*)
---
Create a new ADR for the decision: $ARGUMENTS

1. Look at `docs/adr/` and take the next number (4 digits, e.g. `0005`).
2. Copy the structure of `docs/adr/template.md` to `docs/adr/NNNN-<kebab-case-title>.md`.
3. Fill in Context, Decision, Alternatives, and Consequences from the discussion in this conversation. If anything is unclear, ask before writing.
4. Status is `Accepted` if the user has agreed, otherwise `Proposed`.
5. Commit: `docs(adr): NNNN <title>`.
