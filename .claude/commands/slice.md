---
description: Deliver one vertical slice - task file, tests first, implementation, code and security review
argument-hint: <slice-name> <short description>
---
Deliver the slice: $ARGUMENTS

1. Make sure the working tree is clean and you are on an up-to-date `main`, then `git switch -c feat/<slice-name>`. Record `git rev-parse HEAD` as BASE.
2. Write `tasks/NNN-<slice-name>.md` (next number) containing: Goal, Related ADRs, Acceptance criteria numbered `AC<slice>.<n>`, Out of scope.
   Show the ACs to the user and wait for approval. Commit: `docs(tasks): NNN <slice-name>`.
3. Write tests for every AC, with test names containing the AC ID. Run `go test ./...` and confirm the new tests are red.
   Commit: `test(<pkg>): <summary>`. Record this commit hash as BASE_TEST.
4. Implement until `go test -race ./...` is green. Commit in small, sensible chunks, e.g. `feat(<pkg>): ...`.
   If a test turns out to be wrong, fix it in its own commit `test(<pkg>): ...` and note why in the task file.
5. Invoke the `reviewer` agent (task path, BASE_TEST, test files) and the `security-reviewer` agent (task path, BASE) in parallel.
   On `CHANGES`, fix the Required items, commit as `fix(<pkg>): ...`, and rerun the agent that asked for changes. At most 3 rounds.
6. Save both final outputs to `tasks/NNN-<slice-name>.review.md` and commit `docs(tasks): review NNN`.
7. Summarize for the user: commits created, both verdicts, and suggest `/ship`.
