# depsentry

Go CLI that reads the dependencies of a Node.js project and checks them for known CVEs against OSV (https://osv.dev).
It is not an `npm audit` wrapper: data is fetched directly from the OSV API.

## Commands

| Purpose | Command |
|---|---|
| Test | `go test ./...` |
| Test + race | `go test -race ./...` |
| Lint | `gofmt -l . && go vet ./...` |
| Build | `go build -o bin/depsentry ./cmd/depsentry` |
| Run | `go run ./cmd/depsentry <project-path>` |

## Layout

| Path | Contents |
|---|---|
| `cmd/depsentry` | entrypoint: argument parsing, wiring, exit code |
| `internal/deps` | reads `package.json` + `package-lock.json` (v1/v2/v3) → list of package@version |
| `internal/osv` | OSV client: `POST /v1/querybatch`, `GET /v1/vulns/{id}` |
| `internal/report` | renders results, CVSS severity, fixed version, summary |
| `testdata/` | Node.js project fixtures for tests and e2e |
| `docs/adr/` | architecture decisions; read before changing any behavior they cover |
| `tasks/` | one file per slice, containing acceptance criteria (AC) |

## Conventions

- Standard Go: `gofmt`, wrap errors with `fmt.Errorf("...: %w", err)`, no `panic` on normal paths.
- No comments in code.
- Unit tests must not touch the network. The OSV client is tested with `httptest.Server`; its base URL is injectable.
- Table-driven tests, test names include the AC ID: `TestResolve_AC1_2_LockV1`.
- External dependencies only if listed in an ADR.
- Exit codes: `0` clean, `1` vulnerabilities found, `2` error.
- All code, docs, commit messages, and PR text are written in English.

## Workflow

1. `/slice <name>`: create branch `feat/<name>` and `tasks/NNN-<name>.md`, write tests first, implement, then run the `reviewer` and `security-reviewer` agents.
2. Small commits, one step per commit, Conventional Commits format (`feat:`, `test:`, `fix:`, `docs:`, `chore:`, `ci:`).
3. `/ship`: test, push, open a PR. PRs are merged with a merge commit, not squash.
4. New decisions that change the design → `/adr <title>` first.
5. Never commit or push directly to `main`; the `guard-main.sh` hook blocks it.
