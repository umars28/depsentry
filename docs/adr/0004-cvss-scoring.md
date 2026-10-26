# 0004. Severity from CVSS score

- Status: Accepted
- Date: 2026-10-26

## Context

The `severity` field in OSV holds a CVSS vector (e.g. `CVSS:3.1/AV:N/AC:L/...`), not a numeric score. The output must show a severity or CVSS score.

## Decision

- Use `github.com/pandatix/go-cvss` to parse vectors and compute the base score: package `30` for CVSS v3.0/v3.1, `40` for CVSS v4.0.
- Priority: `CVSS_V4`, then `CVSS_V3`. Displayed as `9.8 CRITICAL`.
- Label from score: 0.0 NONE, 0.1–3.9 LOW, 4.0–6.9 MEDIUM, 7.0–8.9 HIGH, 9.0–10.0 CRITICAL.
- If there is no vector or it fails to parse, fall back to `database_specific.severity` (GHSA label, e.g. `HIGH`), then `UNKNOWN`.
- Fixed version: every `affected[].ranges[].events[].fixed` for the `affected[]` entries whose `package.name` and `ecosystem` match; empty is shown as `-`.
- Link: the first reference of type `ADVISORY`, plus `https://osv.dev/vulnerability/<id>`.

## Alternatives

| Option | Why not chosen |
|---|---|
| Implement the CVSS formula ourselves | Error-prone, especially v4.0 which uses lookup tables |
| Show only the GHSA label | Does not satisfy "CVSS score" and is not available for every advisory |

## Consequences

- One small external dependency with no transitive dependencies.
- The displayed score is the base score, not temporal/environmental.
