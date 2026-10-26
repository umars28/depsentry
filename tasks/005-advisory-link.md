# 005 advisory-link

## Goal

The advisory link shown next to a vulnerability must be about that vulnerability. Until now, `links` took the first `ADVISORY` reference, but OSV does not order references. For GHSA-898c-q2cr-xwhg (axios, CVE-2026-44490) the first `ADVISORY` reference is `https://nvd.nist.gov/vuln/detail/CVE-2018-16487`, a related lodash CVE, so the report showed CVE-2026-44490 with a link to a different CVE. This was found by checking 165 real findings against OSV with an independent script. ID, CVSS score, fixed versions and affected range were all correct; only this link was wrong.

## Related ADRs

- [0004 Severity from CVSS score](../docs/adr/0004-cvss-scoring.md): the "Link" rule changes in this slice.

## Acceptance criteria

The "own IDs" of a vuln are its OSV `id` and its `aliases`. IDs in a URL are the `CVE-YYYY-NNNN…` and `GHSA-xxxx-xxxx-xxxx` patterns found anywhere in it, case-insensitive.

| ID | Criterion |
|---|---|
| AC5.1 | Among `ADVISORY` references that pass the existing checks (`http`/`https`, a host, no userinfo), the first one whose URL contains an own ID and no other ID is chosen. |
| AC5.2 | If none matches AC5.1, the first `ADVISORY` reference whose URL contains no ID at all is chosen (e.g. a vendor bulletin). |
| AC5.3 | A reference whose URL contains any ID that is not an own ID is never chosen, so when every `ADVISORY` reference is about another vulnerability only the osv.dev link is shown. |
| AC5.4 | ID matching is exact on both sides: `CVE-2021-1` does not match `CVE-2021-12`; an ID glued to a letter or digit (`XCVE-2021-1234`, `CVE-2021-1234x`) or a GHSA followed by another `-xxxx` group counts as a foreign ID. Matching is case-insensitive (`ghsa-…` equals `GHSA-…`). Own IDs in other formats (`PYSEC-…`, `MAL-…`) are not recognised in URLs, so such vulns use the AC5.2 fallback. |
| AC5.5 | Regression: the reference list of GHSA-898c-q2cr-xwhg (aliases `CVE-2026-44490`; `ADVISORY` CVE-2018-16487 first, CVE-2026-44490 second) yields `https://nvd.nist.gov/vuln/detail/CVE-2026-44490` and the osv.dev link. |

## Test changes

- `TestLinks_AC3_5` built a vuln `GHSA-35jh-r3h4-6jhm` without aliases but expected its NVD link for `CVE-2021-23337`. Real OSV data lists that CVE as an alias, and under AC5.3 a CVE that is not an own ID is never linked. The test now sets `Aliases: CVE-2021-23337`; the expected links are unchanged.

## Out of scope

- Showing more than one advisory link.
- Validating that the linked page exists.

## Review fixes

- Reviewer round 1 (Required): the new selection order made the unsafe-URL inputs in `TestLinks_AC3_5` unreachable, so removing the scheme/host checks in `safeLink` left every test green. `TestLinks_AC3_5_UnsafeBeforeSafe` puts unsafe URLs before the safe choice on both the own-ID and the ID-free path; disabling `safeLink` makes it fail.
