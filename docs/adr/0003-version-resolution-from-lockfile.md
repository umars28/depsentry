# 0003. Version resolution from package-lock.json

- Status: Accepted
- Date: 2026-10-26

## Context

Assignment: the dependency list is read from `package.json`; if `package-lock.json` exists, use the versions recorded there. `package.json` only holds ranges (`^4.17.0`), while OSV needs exact versions.

## Decision

Package list = keys of `dependencies` and `devDependencies` in `package.json`. Dev packages are marked in the output. Transitive dependencies are not checked.

Version per package, in order of precedence:

| # | Case | Rule |
|---|---|---|
| 1 | non-registry spec (`git+`, `git://`, `github:`, `file:`, `link:`, `workspace:`, `http(s)://`, `npm:` alias, `user/repo` shorthand) | always skipped, reported as `skipped` with a reason, even when the lockfile has an entry |
| 2 | registry spec with a lock entry: lockfile v2/v3 (`lockfileVersion` ≥ 2) | `packages["node_modules/<name>"].version` |
| 3 | registry spec with a lock entry: lockfile v1 | `dependencies["<name>"].version` |
| 4 | registry spec missing from the lockfile, lock entry without `version`, or no lockfile | base version of the range: strip `^ ~ >= > = v` prefixes and whitespace, take the first token; marked `from range` |
| 5 | case 4 where the base version is not `MAJOR.MINOR.PATCH` (optionally `-prerelease`/`+build`), e.g. `*`, `latest`, `1.x`, `>=1`, empty | skipped with a reason, never sent to OSV as a guess |

Registry specs include `*`, `latest`, dist-tags, and empty strings: when the lockfile records a version for them, that version is checked. `npm:` aliases are skipped for now because the real package name differs from the dependency key.

A missing or malformed `package.json` produces exit code 2. A malformed lockfile also produces exit code 2, because silently falling back to ranges could hide the wrong version.

## Alternatives

| Option | Why not chosen |
|---|---|
| Check every package in the lockfile (transitive) | Beyond what the assignment asks; could become a flag later |
| Resolve ranges to the latest version via the npm registry | Not what is installed, and needs extra requests |

## Consequences

- Without a lockfile, results may include false positives because a range's base version is usually older than the installed one; the output marks these `from range`.
- CVEs in transitive dependencies are not detected.
- Aliased packages (`npm:`) and non-registry dependencies are not checked; they are listed as skipped so the gap is visible.
