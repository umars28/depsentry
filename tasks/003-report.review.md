# 003 report review

- BASE: `41e62ed`
- BASE_TEST: `06be97f`
- Reviewed HEAD: `c6dd6f1`
- Rounds: 1, plus a follow-up (`3d5a5e6`) not re-reviewed

## reviewer

VERDICT: APPROVE

| # | File:line | Issue | Required/Suggestion |
|---|---|---|---|
| 1 | internal/report/report.go:94 | `gocvss40` `Score()` includes threat/environmental metrics if a v4 vector carries them; ADR 0004 asks for the base score. OSV vectors are base-only in practice. | Suggestion |
| 2 | internal/report/report.go:83-87 | The `recover()` around go-cvss is untested defensive code. | Suggestion |
| 3 | internal/report/report.go:73 | `database_specific.severity` also accepts `MEDIUM` and lowercase, slightly beyond AC3.3. | Suggestion |
| 4 | internal/report/report.go:230 | Sorting uses the raw display ID while the printed one is sanitized; only differs for IDs with control characters. | Suggestion |

Checked: tests unchanged since BASE_TEST; lint and `go test -race` clean; ADR 0003/0004 conformance, including the corrected go-cvss package choice; only `go-cvss` added to `go.mod` (its testify/yaml requirements are test-only); AC3.1–AC3.10 implemented generally; output buffered so a writer error never leaves a partial report.

## security-reviewer

VERDICT: APPROVE

| # | File:line | Issue | Severity | Required/Suggestion |
|---|---|---|---|---|
| 1 | internal/report/report.go:166-180 | U+2028/U+2029 pass through; some CI log viewers render them as line breaks, allowing fake report lines. | Low | Suggestion |
| 2 | internal/report/report.go:166-180 | Invisible format characters (zero-width, BOM, soft hyphen, tag characters) pass through and allow look-alike package names; use `unicode.Is(unicode.Cf, r)`. | Low | Suggestion |
| 3 | internal/report/report.go:166-170 | DCS/APC/PM/SOS and unterminated OSC payloads remain as text; ESC itself is removed, so cosmetic only. | Low | Suggestion |
| 4 | internal/report/report.go:150-160 | Links with userinfo (`https://github.com@evil.example/`) are accepted and look like a trusted host. | Low | Suggestion |
| 5 | internal/report/report.go:198-201 | Duplicate name@version results overwrite each other. | Low | Suggestion |

Checked: no ESC or C1 character survives `sanitize` across the probes tried (unterminated OSC, raw `0x9b`, U+009B, `ESC ESC [[`, DCS, APC, `ESC (0`); every printed field is sanitized; link schemes limited to `http(s)` with a host; 2M mutated vectors against go-cvss 30/31/40 caused no panic; a missing or mismatched OSV result is an error; govulncheck clean; go-cvss is listed in ADR 0004.

## Follow-up

Applied at the user's request after round 1; not re-reviewed by the agents.

| Finding | AC | Commit | Change |
|---|---|---|---|
| security 1 | AC3.9 | `3d5a5e6` | U+2028/U+2029 become spaces. |
| security 2 | AC3.9 | `3d5a5e6` | All Unicode `Cf` characters are removed; this replaces the hand-listed bidi ranges. |
| security 4 | AC3.5 | `3d5a5e6` | ADVISORY links with userinfo are ignored. |

The new tests were checked to fail against the code before the fix.

Open suggestions: reviewer 1–4, security 3 and 5.
