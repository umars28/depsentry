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

## Follow-up

Addressed after review, at the user's request, as new ACs with tests first:

| Finding | AC | Commits |
|---|---|---|
| security-reviewer 1 (non-regular file hang) | AC1.12 | `2ada602` test, `846bd8d` fix |
| reviewer 2 (lockfile version not validated) | AC1.13 | `2ada602` test, `b9fd0f7` fix |

Remaining suggestions are left for later slices: reviewer 1, 3, 4; security-reviewer 2, 3, 4.

## Round 2 (fixes `846bd8d`, `b9fd0f7`)

### reviewer

VERDICT: APPROVE

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/deps/deps.go:200-218 | Race between `os.Stat` and `os.Open`: a file swapped for a FIFO in that window blocks `os.Open` before the post-open check. Low risk; `O_NONBLOCK` on unix would close it. | Suggestion |
| 2 | internal/deps/deps.go:224 | Size-limit error does not name the file; callers' wrapping already does. | Suggestion |

Checked: test files unchanged since `2ada602`; lint and `go test -race` clean; AC1.12/AC1.13 implemented with the shared `exactVersion` regex, not test-targeted values. Accepts AC1.13 skipping instead of erroring: no range fallback, nothing sent to OSV, `SkipReason` keeps it visible. The report slice must show skipped packages and reasons clearly.

### security-reviewer

VERDICT: APPROVE

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/deps/deps.go:207 | Same `Stat`/`Open` race: swap to a FIFO can hang `open(2)`; the post-open `f.Stat` still prevents reading any non-regular file. Needs a concurrent local attacker, outside the threat model. | Low | Suggestion |
| 2 | internal/deps/deps.go:99 | `Name` remains untrusted (round 1 finding 3) for the report and OSV slices. | Low | Suggestion (later slices) |
| 3 | go.mod | Toolchain still go1.27.1; no reachable vulns. | Low | Suggestion |

Checked: `Dependency.Version` is only set after passing the anchored `exactVersion` regex, so URLs, aliases and ANSI escapes cannot reach it; error text has no attacker-controlled data; tests have a watchdog against hangs; no new modules.

## Round 2 follow-up

The Stat/Open race (reviewer 1, security-reviewer 1) was closed at the user's request: `739c3cc` test, `c03007a` fix. On unix, files are opened with `O_NONBLOCK` and the type is checked only after opening, so a FIFO swapped in cannot block. Other platforms use a plain open and the same post-open check.

## Round 3 (fix `c03007a`)

### reviewer

VERDICT: APPROVE

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/deps/open_unix.go:11 | Opening a device node still runs the driver's open before the type check. Only relevant for a hostile project tree; an `O_NOFOLLOW`/`Lstat` check would break AC1.12's symlink rule. | Suggestion |
| 2 | internal/deps/deps.go:202,207 | `f.Close()` error ignored on error paths; acceptable for a read-only descriptor. | Suggestion |

Checked: tests unchanged since `739c3cc`; missing lockfile still detected via `fs.ErrNotExist`; descriptors closed on every path; Stat/Open race closed; `GOOS=windows` vet and build clean; lint and `go test -race` clean.

### security-reviewer

VERDICT: APPROVE

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/deps/open_unix.go:11 | Without the pre-open `os.Stat`, a symlink to a character device is always opened; the driver's open/close side effects run (e.g. DTR on `/dev/ttyUSB*`). Re-add a pre-open `os.Stat` as a fast path, keeping the post-open `f.Stat` as authoritative. | Low | Suggestion |
| 2 | internal/deps/open_unix.go:11 | No `O_NOCTTY`: on Linux a session leader without a controlling terminal could acquire a tty opened through a symlink. | Low | Suggestion |
| 3 | go.mod:3 | Toolchain go1.27.1; no reachable vulns. Bump to 1.27.3. | Low | Suggestion |

Checked: no remaining hang for FIFOs, devices or symlinks; `O_NONBLOCK` has no effect on regular-file reads; descriptors closed on every path; `!unix` path (Windows, plan9, wasip1) does not reintroduce a hang.

## Round 3 follow-up

Applied at the user's request, after the 3-round review limit, so not re-reviewed by the agents:

| Finding | Commit | Change |
|---|---|---|
| security-reviewer 1 (device open side effects) | `200c336` | `os.Stat` before opening rejects non-regular targets early; the post-open `f.Stat` stays authoritative, so the race stays closed. |
| security-reviewer 2 (controlling tty) | `2bb6f38` | `O_NOCTTY` added to the unix open flags. |

No new tests: the device-open side effect and controlling-tty acquisition cannot be observed reliably in a unit test. The existing AC1.12 tests still cover FIFOs, devices, directories and symlinks, and `TestOpenRegular_AC1_12_FIFODoesNotBlock` still exercises the open path without the pre-check.
