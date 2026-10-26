# 0003. Version resolution from package-lock.json

- Status: Accepted
- Date: 2026-10-26

## Context

Assignment: the dependency list is read from `package.json`; if `package-lock.json` exists, use the versions recorded there. `package.json` only holds ranges (`^4.17.0`), while OSV needs exact versions.

## Decision

Package list = keys of `dependencies` and `devDependencies` in `package.json`. Dev packages are marked in the output. Transitive dependencies are not checked.

Version per package:

| Source | Rule |
|---|---|
| lockfile v2/v3 (`lockfileVersion` ≥ 2) | `packages["node_modules/<name>"].version` |
| lockfile v1 | `dependencies["<name>"].version` |
| package missing from the lockfile, or no lockfile | base version of the range: strip `^ ~ >= > = v` prefixes and whitespace, take the first token; marked `from range` |
| non-registry spec (`git+`, `github:`, `file:`, `link:`, `workspace:`, URL, `*`, `latest`, `npm:` alias) | skipped, reported as `skipped` with a reason |

A missing or malformed `package.json` produces exit code 2. A malformed lockfile also produces exit code 2, because silently falling back to ranges could hide the wrong version.

## Alternatives

| Option | Why not chosen |
|---|---|
| Check every package in the lockfile (transitive) | Beyond what the assignment asks; could become a flag later |
| Resolve ranges to the latest version via the npm registry | Not what is installed, and needs extra requests |

## Consequences

- Without a lockfile, results may include false positives because a range's base version is usually older than the installed one; the output marks these `from range`.
- CVEs in transitive dependencies are not detected.
