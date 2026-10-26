# 002 osv-client review

- BASE: `197217d`
- BASE_TEST: `aca232c`
- Reviewed HEAD: `b86d43e` (round 1), `29ee5eb` (round 2, security-reviewer only)
- Rounds: 2, plus a follow-up (`7c88840`, `a1867b1`) not re-reviewed

## reviewer (round 1)

VERDICT: APPROVE

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/osv/osv.go:332 | A timed-out attempt is retried, so one request can take ~3 × 30 s plus backoff; ADR 0005's "bounded by the HTTP timeout" was ambiguous. | Suggestion |
| 2 | internal/osv/osv.go:69-79 | Limits not overridden by tests could be `const`. | Suggestion |
| 3 | internal/osv/osv.go:180-183 | Page counter counts per 1000-package chunk, not per package; equivalent in effect. | Suggestion |

Checked: tests unchanged since BASE_TEST; lint and `go test -race` clean; ADR 0002/0005 conformance; AC2.1–AC2.11 implemented without test-targeted values; no partial results on error; no panics; bodies always closed; stdlib only.

## security-reviewer (round 1)

VERDICT: CHANGES

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/osv/osv.go:180-206, 237-283 | Vuln IDs from the server are unbounded; a hostile server can exhaust memory and trigger millions of detail requests. | Medium | Required |
| 2 | go.mod:3 | go1.27.1 has 9 stdlib vulns now reachable via the net/http client (GO-2026-6809, GO-2026-6605, GO-2026-6610, …). | Medium | Required |
| 3 | docs/adr/0005-osv-client-resilience.md:21 | "Bounded by the HTTP timeout" is false; the timeout is per request. | Low | Suggestion |
| 4 | internal/osv/osv.go:90 | Default redirect policy can resend the POST body (package names) to another host. | Low | Suggestion |
| 5 | internal/osv/osv.go:287 | `url.PathEscape` keeps `.`/`..`; currently harmless due to the id-match check. Validate IDs against a strict charset. | Low | Suggestion |
| 6 | internal/osv/osv.go:28-36 | OSV text fields are unsanitized; the report slice must strip control/ANSI characters. | Low | Suggestion |

### Fixes

| Finding | Commit | Change |
|---|---|---|
| 1 | `b462789` | AC2.12: at most 1000 unique IDs per package and 10000 per run, enforced before any detail request; ADR 0005 limits table updated; tests added. |
| 2 | `29ee5eb` | `go.mod` set to `go 1.27.3`; govulncheck reports no vulnerabilities. |
| 3 (and reviewer 1) | `b462789` | ADR 0005 "Bound" row corrected: per-attempt 30 s timeout, overall deadline is the caller's context. |

## security-reviewer (round 2)

VERDICT: APPROVE

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/osv/osv.go:201-214 | Round 1 item 1 fixed: unique IDs counted after dedupe, both limits error out before `fetchVulns`; memory bounded. | Low | Suggestion (no action) |
| 2 | go.mod:3 | Round 1 item 2 fixed; keep CI on `go-version-file: go.mod`. | Low | Suggestion |
| 3 | docs/adr/0005-osv-client-resilience.md:21,46 | The CLI slice must pass a context with a deadline, and its review should check it. | Medium | Suggestion (CLI slice) |
| 4 | internal/osv/osv.go | Round 1 suggestions 4 (redirects) and 5 (ID charset) remain open. | Low | Suggestion |
| 5 | report slice | Sanitize OSV text and package names before printing; make it a Required check in the report slice review. | Medium | Suggestion (report slice) |

## Follow-up after round 2

Applied at the user's request; not re-reviewed by the agents.

| Finding | AC | Commits |
|---|---|---|
| security round 1 #4 (redirects) | AC2.13 | `a1867b1` |
| security round 1 #5 (vuln ID charset) | AC2.14 | `7c88840` test change, `a1867b1` fix |

`7c88840` replaces the `ODD/ID?x` vuln ID in the AC2.4 test, because AC2.14 makes it invalid (reason recorded in the task file).

## Carried to later slices

- CLI slice: overall `context.WithTimeout` deadline for `Check`.
- Report slice: strip control characters and ANSI escapes from package names and OSV text before printing.
