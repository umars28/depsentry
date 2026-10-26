# 005 advisory-link review

- BASE: `8604647`
- BASE_TEST: `9b00160`
- Reviewed HEAD: `8994436` (round 1), `9419b7e` (reviewer round 2)
- Rounds: reviewer 2, security-reviewer 1, plus a follow-up (`409383f`) not re-reviewed

## reviewer (round 1)

VERDICT: CHANGES

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/report/report_test.go:131-146 | Under the new selection order the unsafe inputs in `TestLinks_AC3_5` (`javascript:`, `ftp:`, no host) are never reachable, so removing the scheme/host checks in `safeLink` leaves every test green. | Required |
| 2 | internal/report/report.go:145 | The ID pattern has no boundaries (`GHSA-aaaa-bbbb-cccc-dddd`, `XCVE-…`). | Suggestion |
| 3 | internal/report/report.go:147-151 | Own IDs other than CVE/GHSA (`PYSEC-…`, `MAL-…`) silently use the fallback; document it. | Suggestion |

Fixed in `9419b7e`: `TestLinks_AC3_5_UnsafeBeforeSafe` puts unsafe URLs before the safe choice on both paths (verified to fail when `safeLink` returns `true`); IDs glued to letters/digits or GHSA followed by another `-xxxx` group count as foreign (`TestLinks_AC5_4_Boundaries`); AC5.4 documents the PYSEC/MAL fallback.

## reviewer (round 2)

VERDICT: APPROVE

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/report/report.go:198 | An own GHSA followed by `-word` (`/GHSA-…-details`) now counts as foreign; safe direction, documented in AC5.4. | Suggestion |

Checked: the Required item is fixed and recorded in the task file; only additions to the tests since BASE_TEST; the boundary test fails without `glued()`; lint and `go test -race` clean; no comments or new dependencies.

## security-reviewer

VERDICT: APPROVE

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/report/report.go:145, 160-163 | The own-ID check looks at the whole URL, so `https://evil.example/?x=CVE-…` (or the ID in a fragment or subdomain) counts as a match. No new power over what OSV could already do. | Low | Suggestion |
| 2 | internal/report/report.go:145 | Percent-encoded foreign IDs (`CVE%2D2018%2D16487`) are not recognised, so such a URL can become the ID-free fallback. | Low | Suggestion |
| 3 | internal/report/report.go:145 | No boundaries on the ID pattern. | Low | Suggestion |
| 4 | internal/report/report.go:145 | No backtracking cost: Go regexp is linear and URL length is capped by the OSV response limit. | None | n/a |
| 5 | internal/report/report.go:306-307 | Sanitization still applies to the chosen link; `url.Parse` already rejects control bytes. | None | n/a |

Checked: `go test ./...` passes; govulncheck clean; `go.mod` unchanged; no exec, file writes or exit-code changes.

## Follow-up

Applied at the user's request after the reviews; not re-reviewed by the agents.

| Finding | AC | Commit | Change |
|---|---|---|---|
| security 1, 2 | AC5.6 | `409383f` | IDs are read from the decoded host, path, query and fragment. An own ID makes a match only in the path; a foreign ID anywhere rejects the URL, so it can never be the fallback. |
| security 3 | AC5.4 | `9419b7e` | Covered by the reviewer round 1 fix. |

## Verification against real OSV data

An independent script re-fetched every advisory from OSV and recomputed each CVSS score with the Python `cvss` library. It then compared ID, CVE existence, score, fixed versions, affected range and links for 165 findings across 12 playground projects.

| Build | Result |
|---|---|
| Before this slice | 3 wrong links (GHSA-898c-q2cr-xwhg linked CVE-2018-16487 in three projects) |
| After `8994436` | 0 wrong links; the only output difference is those three links |
| After `409383f` | Output identical to `8994436` for all 12 projects |

The one remaining note, CVE-2026-111181 having no standalone OSV record, is data lag: GHSA-27r3-jxmh-p828 was published on 2026-10-23 and already lists it as an alias.
