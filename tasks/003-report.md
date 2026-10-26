# 003 report

## Goal

Turn the resolved dependencies and the OSV results into a readable terminal report with CVE IDs, CVSS severity, fixed versions and links, plus a summary the CLI can use for its exit code. Follows ADR 0004.

API:

```go
sum, err := report.Write(w, dependencies, results)
```

`dependencies` is the full `[]deps.Dependency` list (including skipped ones). `results` is the `[]osv.Result` for the non-skipped ones. `Summary` holds `Checked`, `Skipped`, `VulnerablePackages`, `Vulns`, and a count per severity label.

## Related ADRs

- [0003 Version resolution](../docs/adr/0003-version-resolution-from-lockfile.md): dev, `from range` and skipped markers.
- [0004 Severity from CVSS score](../docs/adr/0004-cvss-scoring.md): adds `github.com/pandatix/go-cvss`, the first external dependency.

## Acceptance criteria

| ID | Criterion |
|---|---|
| AC3.1 | Displayed ID: the OSV `id` if it starts with `CVE-`, otherwise the first alias starting with `CVE-`, otherwise the OSV `id` (e.g. a GHSA-only advisory). |
| AC3.2 | Severity is the CVSS base score from `CVSS_V4`, otherwise `CVSS_V3`, computed with `go-cvss` and shown as one decimal plus a label: 0.0 NONE, 0.1–3.9 LOW, 4.0–6.9 MEDIUM, 7.0–8.9 HIGH, 9.0–10.0 CRITICAL. E.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → `9.8 CRITICAL`. If a vector fails to parse, the next one is tried. |
| AC3.3 | With no usable vector, the label comes from `database_specific.severity` (`LOW`, `MODERATE` shown as `MEDIUM`, `HIGH`, `CRITICAL`) without a score; anything else, or invalid JSON there, is `UNKNOWN`. |
| AC3.4 | Fixed versions are every `affected[].ranges[].events[].fixed` from the `affected[]` entries whose package name equals the dependency and whose ecosystem is `npm`, deduplicated in order and joined with `, `; none is shown as `-`. |
| AC3.5 | Links: the first `ADVISORY` reference whose URL is `http` or `https`, followed by `https://osv.dev/vulnerability/<id>` (path-escaped). References with other schemes, no host, or userinfo (`https://github.com@evil.example/`) are ignored. |
| AC3.6 | Only vulnerable packages are listed, in input order, as `name@version` followed by `(dev)` and/or `(from range)` when applicable. Each package's vulns are sorted by score (highest first, unscored after scored), then by displayed ID. Each vuln line shows ID, severity, `fixed:` versions, then the summary and links on indented lines. The exact layout is fixed by a golden test. |
| AC3.7 | Skipped dependencies are listed in a `Skipped` section with their reason. |
| AC3.8 | The output ends with a summary line: packages checked, vulnerable packages, vulnerabilities with a count per label (CRITICAL to UNKNOWN, zero counts omitted), and skipped count. `Write` returns the same numbers in `Summary`. With no vulnerabilities it prints `No known vulnerabilities found.` before the summary. |
| AC3.9 | Every printed string that comes from the project or OSV (package names, versions, reasons, IDs, summaries, fixed versions, URLs) has ANSI escape sequences, other C0/C1 control characters and all Unicode format characters (category `Cf`: bidi controls, zero-width characters, BOM, soft hyphen, tag characters) removed; newlines, tabs and U+2028/U+2029 become spaces. Summaries are cut to 120 characters with `…`. |
| AC3.10 | A non-skipped dependency without a matching OSV result returns an error instead of being reported as clean. An error from the writer is returned. |

## Out of scope

- Exit codes, argument parsing, wiring, overall deadline (CLI slice).
- Colors, JSON or other output formats.
- Temporal/environmental CVSS scores (ADR 0004).
