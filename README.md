# depsentry

A CLI that checks whether the dependencies of a Node.js project have known CVEs. Data is fetched directly from the [OSV API](https://osv.dev), not from `npm audit`.

## Installation

Requires Go 1.27.3 or newer.

```sh
go install github.com/umars28/depsentry/cmd/depsentry@latest
```

Or build from source:

```sh
git clone https://github.com/umars28/depsentry
cd depsentry
go build -o bin/depsentry ./cmd/depsentry
```

## Usage

```sh
depsentry [--timeout <duration>] <project-path>
```

```sh
depsentry ./my-project
depsentry --timeout 30s ./my-project
```

| Flag | Default | Meaning |
|---|---|---|
| `--timeout` | `2m` | Overall deadline for all OSV requests |

| Exit code | Meaning |
|---|---|
| `0` | Every dependency was checked and none has a known vulnerability |
| `1` | At least one vulnerability was found |
| `2` | Error: missing or malformed `package.json` / `package-lock.json`, OSV unreachable or failing, timeout, Ctrl-C, or invalid arguments |

Try it on the bundled fixtures:

```sh
depsentry testdata/vulnerable
depsentry testdata/clean
```

## Example output

Real run against OSV on `testdata/vulnerable`:

```
$ depsentry testdata/vulnerable
lodash@4.17.15
  CVE-2026-4800  8.1 HIGH  fixed: 4.18.0
    lodash vulnerable to Code Injection via `_.template` imports key names
    https://nvd.nist.gov/vuln/detail/CVE-2026-4800
    https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc
  CVE-2020-8203  7.4 HIGH  fixed: 4.17.19
    Prototype Pollution in lodash
    https://nvd.nist.gov/vuln/detail/CVE-2020-8203
    https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw
  CVE-2021-23337  7.2 HIGH  fixed: 4.17.21
    Command Injection in lodash
    https://nvd.nist.gov/vuln/detail/CVE-2021-23337
    https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
  CVE-2025-13465  6.9 MEDIUM  fixed: 4.17.23
    Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions
    https://nvd.nist.gov/vuln/detail/CVE-2025-13465
    https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg
  CVE-2026-2950  6.5 MEDIUM  fixed: 4.18.0
    lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`
    https://nvd.nist.gov/vuln/detail/CVE-2026-2950
    https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh
  CVE-2020-28500  5.3 MEDIUM  fixed: 4.17.21
    Regular Expression Denial of Service (ReDoS) in lodash
    https://nvd.nist.gov/vuln/detail/CVE-2020-28500
    https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9

Skipped:
  mylib  git dependency

Checked 2 packages: 1 vulnerable, 6 vulnerabilities (3 HIGH, 3 MEDIUM), 1 skipped.
$ echo $?
1
```

Each vulnerable package shows its name and version, then one entry per advisory: CVE ID (or the GHSA ID when no CVE exists), CVSS score and severity, fixed versions, summary, and reference links. The last line is the summary.

## How it works

1. **Dependencies.** Reads `dependencies` and `devDependencies` from `package.json`. The version of each package comes from `package-lock.json` (v1, v2 and v3). Without a lockfile, the base version of the range is used (`^4.17.0` → `4.17.0`) and marked `(from range)`. Git, file, link, workspace, URL and `npm:` alias dependencies cannot be checked and are listed under `Skipped`. Transitive dependencies are not checked. See [ADR 0003](docs/adr/0003-version-resolution-from-lockfile.md).
2. **OSV lookup.** One `POST /v1/querybatch` for all packages, then `GET /v1/vulns/{id}` for each unique advisory (at most 8 at a time). Transient failures (`429`, `5xx`, network errors) are retried up to 3 times with backoff. See [ADR 0002](docs/adr/0002-use-osv-as-data-source.md) and [ADR 0005](docs/adr/0005-osv-client-resilience.md).
3. **Severity.** The CVSS v4 or v3 base score is computed from the advisory's vector with [go-cvss](https://github.com/pandatix/go-cvss). Without a usable vector, the GHSA severity label is shown, otherwise `UNKNOWN`. See [ADR 0004](docs/adr/0004-cvss-scoring.md).

`package.json`, the lockfile and OSV responses are treated as untrusted. File and response sizes are limited, and all printed text is stripped of terminal escape sequences and control characters.

## Development

| Purpose | Command |
|---|---|
| Test | `go test ./...` |
| Test with race detector | `go test -race ./...` |
| Lint | `gofmt -l . && go vet ./...` |
| Build | `go build -o bin/depsentry ./cmd/depsentry` |

Unit tests never touch the network; the OSV client and the CLI are tested against `httptest.Server`.

| Path | Contents |
|---|---|
| `cmd/depsentry` | Entrypoint: arguments, wiring, exit codes |
| `internal/deps` | Reads `package.json` and `package-lock.json` |
| `internal/osv` | OSV API client |
| `internal/report` | CVE ID, CVSS severity, fixed versions, output |
| `testdata/` | Node.js project fixtures |
| `docs/adr/` | Architecture decision records |
| `tasks/` | One file per slice with acceptance criteria, plus its review notes |

## AI tools used

Only **Claude Code** was used.

What I did myself:

- Wrote the architecture decisions in `docs/adr/`.
- Set up the project workflow: `CLAUDE.md`, the `/slice`, `/ship` and `/adr` commands, the `reviewer` and `security-reviewer` agents, and the hooks that block pushes to `main`, run `gofmt -w` and `go vet` after every Go edit, and run `go test ./...` before Claude Code may finish a turn.
- Approved or changed the acceptance criteria of every slice. For example, I corrected the lockfile precedence rule in slice 001, and asked for retries and ADR 0005 in slice 002.
- Decided which review findings to fix, and reviewed and merged every PR.

What Claude Code did, one slice at a time through the `/slice` workflow (task → failing tests → implementation → review):

- Drafted the acceptance criteria in `tasks/`.
- Wrote the tests first, then the implementation, for `deps`, `osv`, `report` and the CLI.
- Ran the `reviewer` and `security-reviewer` subagents on each slice and fixed their findings. The review notes are in `tasks/*.review.md`.
- Opened the PRs via `/ship` and drafted this README.

The tool itself does not use an LLM at runtime.
