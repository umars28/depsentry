# 0005. OSV client resilience: retries and response limits

- Status: Accepted
- Date: 2026-10-26

## Context

ADR 0002 makes every network error or non-200 status exit with code 2. In CI a single transient `503` or `429` from OSV would then fail the pipeline even though nothing is wrong with the project. OSV responses are also untrusted (security-reviewer threat model), so a misbehaving or hostile server must not be able to exhaust memory or keep the CLI paginating forever.

## Decision

Retries, for both `POST /v1/querybatch` and `GET /v1/vulns/{id}` (the batch query is read-only, so repeating it is safe):

| Aspect | Rule |
|---|---|
| Retried | network errors, `429`, `5xx` |
| Not retried | other `4xx`, malformed JSON, oversized bodies, a cancelled or expired context |
| Attempts | at most 3 per request |
| Backoff | exponential with full jitter: base 500 ms, doubling per attempt |
| `Retry-After` | honoured when present (seconds form), capped at 10 s |
| Bound | the whole operation stays bounded by the HTTP timeout and the caller's context |

After the last attempt the error is returned, keeping ADR 0002's exit code 2.

Limits on untrusted responses:

| Limit | Value | On exceed |
|---|---|---|
| querybatch response body | 32 MiB | error |
| vuln detail response body | 4 MiB | error |
| `next_page_token` pages per package | 100 | error |

## Alternatives

| Option | Why not chosen |
|---|---|
| No retries | Transient OSV hiccups turn into red CI runs |
| Retry every error, including `4xx` | `400`/`404` will not change on retry and only slow the failure down |
| On-disk cache of advisories | Requires writing files, which the CLI must not do; a stale cache would hide new advisories; within a run IDs are already deduplicated |
| No size or page limits | A hostile or broken server could exhaust memory or loop forever |

## Consequences

- A run can take up to a few extra seconds when OSV is flaky, still bounded by the timeout.
- Very large legitimate responses above the limits fail with exit 2; the limits are far above real OSV responses.
- The backoff delay is injectable so tests do not sleep.
