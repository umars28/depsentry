# 0002. OSV as the vulnerability data source

- Status: Accepted
- Date: 2026-10-26

## Context

The tool must not just wrap `npm audit`; data has to be fetched from a public source directly. We need an unauthenticated API that supports the npm ecosystem and maps advisories to CVEs.

## Decision

Use the OSV API (`https://api.osv.dev`):

1. One `POST /v1/querybatch` for all packages, each query `{"package":{"name":..., "ecosystem":"npm"},"version":...}`. The response only contains `id` and `modified` per vuln. If a `next_page_token` is returned, repeat the query for that package.
2. `GET /v1/vulns/{id}` for each unique ID, in parallel with a concurrency limit of 8, to fetch `aliases`, `severity`, `affected`, `references`, `database_specific`.
3. CVE ID: use `id` if it starts with `CVE-`, otherwise look in `aliases`. If there is no CVE at all (GHSA-only advisory), show the GHSA ID so the finding is not lost.
4. The base URL is injectable so the client can be tested with `httptest.Server`.
5. HTTP timeout of 30 seconds. Network errors or non-200 status produce exit code 2.

## Alternatives

| Option | Why not chosen |
|---|---|
| GitHub Advisory Database (GraphQL) | Requires a GitHub token, adding a setup step for users |
| NVD API | Does not know npm package names; needs fragile CPE mapping, strict rate limits without an API key |
| `npm audit` / registry audit endpoint | Forbidden by the assignment |

## Consequences

- Works out of the box, no token.
- OSV aggregates GHSA, so npm coverage matches the GitHub Advisory Database.
- Request count = 1 batch + N details; N can be large for very vulnerable projects, so concurrency is bounded and IDs are deduplicated.
