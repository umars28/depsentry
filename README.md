# depsentry

A CLI that checks whether the dependencies of a Node.js project have known CVEs. Data is fetched directly from [OSV](https://osv.dev), not from `npm audit`.

> Status: work in progress.

## Installation

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
depsentry ./my-project
```

| Exit code | Meaning |
|---|---|
| `0` | no CVEs found |
| `1` | vulnerable packages found |
| `2` | error (unreadable file, network, etc.) |

## Design

Architecture decisions live in [`docs/adr/`](docs/adr/).

## AI tools used

To be completed at the end of the project.
