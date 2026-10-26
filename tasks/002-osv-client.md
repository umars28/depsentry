# 002 osv-client

## Goal

Given a list of package@version, fetch the matching OSV advisories with full details, following ADR 0002.

API:

```go
c := osv.New(baseURL)
results, err := c.Check(ctx, []osv.Package{{Name: "lodash", Version: "4.17.15"}})
```

`Check` returns one `Result{Package, Vulns []Vuln}` per input package, in input order. `Vuln` holds `ID`, `Aliases`, `Summary`, `Severity[]{Type, Score}`, `Affected[]{Package{Name, Ecosystem}, Ranges[]{Type, Events[]{Introduced, Fixed, LastAffected}}}`, `References[]{Type, URL}`, and `DatabaseSpecific` as raw JSON.

## Related ADRs

- [0001 Use Go](../docs/adr/0001-use-go.md): standard library only for this slice.
- [0002 OSV as the vulnerability data source](../docs/adr/0002-use-osv-as-data-source.md)
- [0005 OSV client resilience](../docs/adr/0005-osv-client-resilience.md): retries, response size and page limits.

## Acceptance criteria

| ID | Criterion |
|---|---|
| AC2.1 | `Check` sends `POST {base}/v1/querybatch` with `{"queries":[{"package":{"name":…,"ecosystem":"npm"},"version":…}]}` in input order, and returns one result per input package in the same order. Packages without vulns have an empty `Vulns`. Scoped names (`@scope/name`) are sent only in the JSON body. |
| AC2.2 | More than 1000 packages are split into several querybatch requests of at most 1000 queries each. Results keep input order. |
| AC2.3 | A result with `next_page_token` is queried again for that package with `page_token` until no token is returned; IDs from all pages are combined. More than 100 pages for one package returns an error. |
| AC2.4 | Each unique vuln ID is fetched once with `GET {base}/v1/vulns/{url.PathEscape(id)}`, even if several packages share it, and its details are attached to every package that has it. |
| AC2.5 | At most 8 vuln detail requests are in flight at once. |
| AC2.6 | An empty package list returns an empty result without any HTTP request. |
| AC2.7 | Each of these returns an error and no partial results: non-200 status from either endpoint, malformed JSON, a querybatch response whose `results` count differs from the queries sent, an empty vuln ID, a vuln detail whose `id` differs from the one requested. |
| AC2.8 | `New` sets a 30 s HTTP timeout. A request that exceeds the client's timeout, or a cancelled context, returns an error. |
| AC2.9 | Response bodies are read through a size limit (querybatch 32 MiB, vuln detail 4 MiB); a larger body returns an error. Every response body is closed. |
| AC2.10 | The base URL is injectable via `New(baseURL)`; a trailing `/` does not produce `//` in request paths. |
| AC2.11 | Network errors, `429` and `5xx` are retried up to 3 attempts per request with exponential backoff (base 500 ms, full jitter); `Retry-After` in seconds is honoured, capped at 10 s. Other `4xx`, malformed JSON and oversized bodies are not retried. After the last failed attempt `Check` returns an error. |
| AC2.12 | More than 1000 unique vuln IDs for one package (across pages), or more than 10000 unique vuln IDs in one run, returns an error before any detail request is sent. Added from review 002, security finding 1. |

## Out of scope

- Picking the CVE ID from `id`/`aliases`, CVSS scoring, fixed versions, links (report slice, ADR 0004).
- CLI wiring, exit codes, output (later slices).
- On-disk caching (ADR 0005).
- Converting `deps.Dependency` to `osv.Package`, and skipping `Source = skipped` packages (CLI slice).
