# 001 deps-parser

## Goal

Given a Node.js project directory, produce the list of direct dependencies with the exact version to check against OSV, following ADR 0003.

API: `deps.Resolve(projectDir string) ([]deps.Dependency, error)`, where `Dependency` has `Name`, `Version`, `Dev bool`, `Source` (`lockfile`, `range`, `skipped`), and `SkipReason`.

## Related ADRs

- [0001 Use Go](../docs/adr/0001-use-go.md): standard library only, semver handled only as far as ADR 0003 needs.
- [0003 Version resolution from package-lock.json](../docs/adr/0003-version-resolution-from-lockfile.md)

## Acceptance criteria

Rule precedence: non-registry specs are always skipped. Registry specs (including `*`, `latest`, `1.x`, empty) use the lockfile version when present, and only fall back to the range base version, or skip, when it is not.

| ID | Criterion |
|---|---|
| AC1.1 | Every key of `dependencies` and `devDependencies` in `package.json` is returned once, sorted by name. Packages from `devDependencies` have `Dev = true`. A package listed in both is returned once with `Dev = false`. |
| AC1.2 | Lockfile v1 (`lockfileVersion: 1`): version is `dependencies["<name>"].version`, `Source = lockfile`. |
| AC1.3 | Lockfile v2: version is `packages["node_modules/<name>"].version`, `Source = lockfile`. Scoped names (`@scope/name`) work. |
| AC1.4 | Lockfile v3: same rule as AC1.3. |
| AC1.5 | A registry package missing from the lockfile, or whose lock entry has no `version`, gets the base version of its range: strip `^ ~ >= > = v` prefixes and whitespace, take the first token. `Source = range`. Examples: `^4.17.0` → `4.17.0`, `>= 1.2.3 < 2` → `1.2.3`, `~v2.0.1` → `2.0.1`, `1.0.0 \|\| 2.0.0` → `1.0.0`. |
| AC1.6 | With no `package-lock.json`, every registry package is resolved per AC1.5. |
| AC1.7 | Non-registry specs are always `Source = skipped` with a non-empty `SkipReason`, even when the lockfile has an entry: `git+…`, `git://…`, `github:…`, `file:…`, `link:…`, `workspace:…`, `http(s)://…`, `npm:…` aliases, and `user/repo` shorthand. |
| AC1.8 | Registry specs whose range has no exact base version (`*`, `latest`, `1.x`, `>=1`, empty) use the lockfile version when present (`Source = lockfile`). Without a lock entry, a base version that is not `MAJOR.MINOR.PATCH` (optionally `-prerelease`/`+build`) is `Source = skipped` with a reason. |
| AC1.9 | Missing `package.json`, malformed `package.json`, or a `dependencies`/`devDependencies` field that is not an object of strings returns an error. |
| AC1.10 | Malformed `package-lock.json`, or a `lockfileVersion` other than 1, 2, 3, returns an error (no silent fallback to ranges). |
| AC1.11 | `package.json` larger than 10 MiB or `package-lock.json` larger than 256 MiB returns an error instead of being read fully. |
| AC1.12 | `package.json` or `package-lock.json` that is not a regular file after following symlinks (FIFO, device, directory) returns an error without blocking. A symlink to a regular file is read normally. Added from review 001, security finding 1. |
| AC1.13 | A lockfile version that is not an exact version (`MAJOR.MINOR.PATCH`, optional `-prerelease`/`+build`) for a registry spec is `Source = skipped` with a reason; it is neither sent to OSV nor silently replaced by the range. Added from review 001, reviewer finding 2. |

## Out of scope

- Transitive dependencies (ADR 0003).
- Resolving `npm:` aliases to the real package; skipped with a clear reason for now.
- Symlink containment for `package.json`/lockfile: the tool only reads, and the user chooses the directory.
- CLI wiring, exit codes, output formatting (later slices).
- OSV queries.
- `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`.
- e2e fixtures under `testdata/`; unit tests build projects in `t.TempDir()`.
