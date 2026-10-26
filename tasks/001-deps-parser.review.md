# 001 deps-parser review

- BASE: `269aab4`
- BASE_TEST: `b0fe408`
- Reviewed HEAD: `bf60b4c`
- Rounds: 1

## reviewer

VERDICT: APPROVE

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/deps/deps.go:154 | `baseVersion` splits only on whitespace, so `1.0.0\|\|2.0.0` without spaces is skipped instead of resolving to `1.0.0`. Safe, but AC1.5 "first token" could be read to cover it. | Suggestion |
| 2 | internal/deps/deps.go:105 | Lockfile version is used as-is, not validated against the exact-version pattern. | Suggestion |
| 3 | internal/deps/deps.go:126-129 | `gitlab:`, `bitbucket:`, `gist:` are skipped beyond the ADR 0003 list; consider listing them in the ADR. | Suggestion |
| 4 | internal/deps/deps.go:167 | `package.json` containing `null` is treated as an empty project, not an error. | Suggestion |

Checked: tests unchanged since BASE_TEST; `gofmt`, `go vet`, `go test -race` clean; ADR 0003 precedence and lookup rules; AC1.1–AC1.11 implemented without test-targeted values; errors wrapped, no comments; no extra abstractions.

## security-reviewer

VERDICT: APPROVE

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/deps/deps.go:195 | `os.Open` does not require a regular file; a FIFO or a symlink to `/dev/stdin`/`/dev/tty` makes `io.ReadAll` block forever (CI hang). Check `Mode().IsRegular()` after open. | Low | Suggestion |
| 2 | internal/deps/deps.go:182 | `json.Unmarshal` on a buffer of up to 256 MiB keeps the raw copy in memory; `json.NewDecoder` over the `LimitReader` would lower peak memory. | Low | Suggestion |
| 3 | internal/deps/deps.go:99,106,111 | `Name` and lockfile `Version` are untrusted strings; the report slice must sanitize them before printing and the OSV slice must send them only in the JSON body. | Low | Suggestion (later slices) |
| 4 | go.mod | govulncheck: no reachable vulns; go1.27.1 stdlib has advisories fixed in 1.27.2/1.27.3. Bump the toolchain before the HTTP slice. | Low | Suggestion |

Checked: size-limited reads, malformed/deep JSON returns errors, read-only file access, no `os/exec`/env/writes, no new modules.
