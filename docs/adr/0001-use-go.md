# 0001. Use Go for the CLI

- Status: Accepted
- Date: 2026-10-26

## Context

`depsentry` is a CLI run on developer laptops and in CI. Its users may not have any particular runtime installed, and the tool only needs an HTTP client, JSON parsing, and simple concurrency for many requests to OSV.

## Decision

Write it in Go, using the standard library as the base (`net/http`, `encoding/json`, `flag`). Distribute via `go install github.com/umars28/depsentry/cmd/depsentry@latest` or a binary built with `go build`.

## Alternatives

| Option | Why not chosen |
|---|---|
| Node.js/TypeScript | Same domain as the target, but a CLI that audits the npm supply chain should not depend on its own `node_modules` tree |
| Python | CLI distribution (venv, pipx) is clumsier for CI users |

## Consequences

- One static binary, easy to use in CI with no extra runtime.
- Concurrent OSV requests are simple with goroutines + a semaphore.
- npm semver parsing is not in the stdlib; it is handled only as far as ADR 0003 requires.
