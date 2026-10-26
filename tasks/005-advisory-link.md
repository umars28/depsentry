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
| AC5.4 | ID matching is exact: `CVE-2021-1` does not match `CVE-2021-12`, and matching is case-insensitive (`ghsa-…` equals `GHSA-…`). |
| AC5.5 | Regression: the reference list of GHSA-898c-q2cr-xwhg (aliases `CVE-2026-44490`; `ADVISORY` CVE-2018-16487 first, CVE-2026-44490 second) yields `https://nvd.nist.gov/vuln/detail/CVE-2026-44490` and the osv.dev link. |

## Out of scope

- Showing more than one advisory link.
- Validating that the linked page exists.
