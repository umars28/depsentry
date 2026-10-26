package report

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/umars28/depsentry/internal/deps"
	"github.com/umars28/depsentry/internal/osv"
)

const (
	v31Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v31High     = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
	v31Medium   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	v31Low      = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
	v31None     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
	v30High     = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
	v40Critical = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	v40Medium   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
)

func sev(typ, score string) osv.Severity {
	return osv.Severity{Type: typ, Score: score}
}

func TestDisplayID_AC3_1(t *testing.T) {
	cases := []struct {
		name string
		v    osv.Vuln
		want string
	}{
		{"id is CVE", osv.Vuln{ID: "CVE-2021-23337", Aliases: []string{"GHSA-35jh-r3h4-6jhm"}}, "CVE-2021-23337"},
		{"CVE in aliases", osv.Vuln{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"SNYK-1", "CVE-2021-23337", "CVE-2021-99999"}}, "CVE-2021-23337"},
		{"GHSA only", osv.Vuln{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"SNYK-1"}}, "GHSA-xxxx-yyyy-zzzz"},
		{"no aliases", osv.Vuln{ID: "MAL-2024-1"}, "MAL-2024-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := displayID(tc.v); got != tc.want {
				t.Fatalf("displayID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSeverity_AC3_2_CVSS(t *testing.T) {
	cases := []struct {
		name string
		sevs []osv.Severity
		want string
	}{
		{"v3.1 critical", []osv.Severity{sev("CVSS_V3", v31Critical)}, "9.8 CRITICAL"},
		{"v3.1 high", []osv.Severity{sev("CVSS_V3", v31High)}, "7.2 HIGH"},
		{"v3.1 medium", []osv.Severity{sev("CVSS_V3", v31Medium)}, "6.1 MEDIUM"},
		{"v3.1 low", []osv.Severity{sev("CVSS_V3", v31Low)}, "1.8 LOW"},
		{"v3.1 none", []osv.Severity{sev("CVSS_V3", v31None)}, "0.0 NONE"},
		{"v3.0", []osv.Severity{sev("CVSS_V3", v30High)}, "8.8 HIGH"},
		{"v4", []osv.Severity{sev("CVSS_V4", v40Medium)}, "6.9 MEDIUM"},
		{"v4 preferred over v3", []osv.Severity{sev("CVSS_V3", v31Low), sev("CVSS_V4", v40Critical)}, "9.3 CRITICAL"},
		{"bad v4 falls back to v3", []osv.Severity{sev("CVSS_V4", "CVSS:4.0/garbage"), sev("CVSS_V3", v31High)}, "7.2 HIGH"},
		{"bad first v3 tries next", []osv.Severity{sev("CVSS_V3", "CVSS:3.1/AV:N"), sev("CVSS_V3", v31Medium)}, "6.1 MEDIUM"},
		{"v2 ignored", []osv.Severity{sev("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"), sev("CVSS_V3", v31Low)}, "1.8 LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := severityOf(osv.Vuln{ID: "X", Severity: tc.sevs}).String(); got != tc.want {
				t.Fatalf("severity = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSeverity_AC3_3_Fallback(t *testing.T) {
	cases := []struct {
		name string
		sevs []osv.Severity
		db   string
		want string
	}{
		{"ghsa high", nil, `{"severity":"HIGH"}`, "HIGH"},
		{"ghsa moderate", nil, `{"severity":"MODERATE"}`, "MEDIUM"},
		{"ghsa low", nil, `{"severity":"LOW"}`, "LOW"},
		{"ghsa critical lowercase", nil, `{"severity":"critical"}`, "CRITICAL"},
		{"unparseable vector uses ghsa", []osv.Severity{sev("CVSS_V3", "nope")}, `{"severity":"HIGH"}`, "HIGH"},
		{"unknown label", nil, `{"severity":"\u001b[31mPWNED"}`, "UNKNOWN"},
		{"severity not a string", nil, `{"severity":7}`, "UNKNOWN"},
		{"invalid json", nil, `{`, "UNKNOWN"},
		{"no database_specific", nil, ``, "UNKNOWN"},
		{"only v2", []osv.Severity{sev("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P")}, ``, "UNKNOWN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := osv.Vuln{ID: "X", Severity: tc.sevs}
			if tc.db != "" {
				v.DatabaseSpecific = json.RawMessage(tc.db)
			}
			if got := severityOf(v).String(); got != tc.want {
				t.Fatalf("severity = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFixedVersions_AC3_4(t *testing.T) {
	v := osv.Vuln{ID: "X", Affected: []osv.Affected{
		{Package: osv.AffectedPackage{Name: "lodash", Ecosystem: "npm"}, Ranges: []osv.Range{
			{Type: "SEMVER", Events: []osv.Event{{Introduced: "0"}, {Fixed: "4.17.21"}}},
			{Type: "SEMVER", Events: []osv.Event{{Introduced: "5.0.0"}, {Fixed: "5.0.1"}, {Fixed: "4.17.21"}}},
		}},
		{Package: osv.AffectedPackage{Name: "lodash", Ecosystem: "PyPI"}, Ranges: []osv.Range{
			{Events: []osv.Event{{Fixed: "9.9.9"}}},
		}},
		{Package: osv.AffectedPackage{Name: "lodash-es", Ecosystem: "npm"}, Ranges: []osv.Range{
			{Events: []osv.Event{{Fixed: "8.8.8"}}},
		}},
		{Package: osv.AffectedPackage{Name: "lodash", Ecosystem: "npm"}, Ranges: []osv.Range{
			{Events: []osv.Event{{Introduced: "6.0.0"}, {LastAffected: "6.1.0"}}},
		}},
	}}
	if got, want := fixedVersions(v, "lodash"), []string{"4.17.21", "5.0.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fixedVersions = %v, want %v", got, want)
	}
	if got := fixedVersions(v, "other"); len(got) != 0 {
		t.Fatalf("fixedVersions(other) = %v, want none", got)
	}
}

func TestLinks_AC3_5(t *testing.T) {
	v := osv.Vuln{ID: "GHSA-35jh-r3h4-6jhm", References: []osv.Reference{
		{Type: "WEB", URL: "https://example.com/blog"},
		{Type: "ADVISORY", URL: "javascript:alert(1)"},
		{Type: "ADVISORY", URL: "ftp://example.com/adv"},
		{Type: "ADVISORY", URL: "https:///no-host"},
		{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
		{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"},
	}}
	want := []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
		"https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
	}
	if got := links(v); !reflect.DeepEqual(got, want) {
		t.Fatalf("links = %v, want %v", got, want)
	}
	if got, want := links(osv.Vuln{ID: "PYSEC-2021:1"}), []string{"https://osv.dev/vulnerability/PYSEC-2021:1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("links without references = %v, want %v", got, want)
	}
}

func lodashVuln() osv.Vuln {
	return osv.Vuln{
		ID:       "GHSA-35jh-r3h4-6jhm",
		Aliases:  []string{"CVE-2021-23337"},
		Summary:  "Command Injection in lodash",
		Severity: []osv.Severity{sev("CVSS_V3", v31High)},
		Affected: []osv.Affected{{Package: osv.AffectedPackage{Name: "lodash", Ecosystem: "npm"}, Ranges: []osv.Range{
			{Type: "SEMVER", Events: []osv.Event{{Introduced: "0"}, {Fixed: "4.17.21"}}},
		}}},
		References: []osv.Reference{{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}},
	}
}

func goldenInput() ([]deps.Dependency, []osv.Result) {
	dependencies := []deps.Dependency{
		{Name: "express", Version: "4.18.2", Source: deps.SourceLockfile},
		{Name: "jest", Version: "29.0.0", Dev: true, Source: deps.SourceRange},
		{Name: "lodash", Version: "4.17.15", Source: deps.SourceLockfile},
		{Name: "mylib", Source: deps.SourceSkipped, SkipReason: "git dependency"},
	}
	results := []osv.Result{
		{Package: osv.Package{Name: "express", Version: "4.18.2"}},
		{Package: osv.Package{Name: "jest", Version: "29.0.0"}, Vulns: []osv.Vuln{
			{ID: "GHSA-aaaa-bbbb-cccc", DatabaseSpecific: json.RawMessage(`{"severity":"MODERATE"}`)},
			{ID: "GHSA-zzzz-yyyy-xxxx", Summary: "Prototype pollution", Severity: []osv.Severity{sev("CVSS_V3", v31Critical)}},
			{ID: "GHSA-0000-1111-2222", Aliases: []string{"CVE-2020-1"}, Severity: []osv.Severity{sev("CVSS_V3", v31Low)}},
		}},
		{Package: osv.Package{Name: "lodash", Version: "4.17.15"}, Vulns: []osv.Vuln{lodashVuln()}},
	}
	return dependencies, results
}

const golden = `jest@29.0.0 (dev) (from range)
  GHSA-zzzz-yyyy-xxxx  9.8 CRITICAL  fixed: -
    Prototype pollution
    https://osv.dev/vulnerability/GHSA-zzzz-yyyy-xxxx
  CVE-2020-1  1.8 LOW  fixed: -
    https://osv.dev/vulnerability/GHSA-0000-1111-2222
  GHSA-aaaa-bbbb-cccc  MEDIUM  fixed: -
    https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc

lodash@4.17.15
  CVE-2021-23337  7.2 HIGH  fixed: 4.17.21
    Command Injection in lodash
    https://nvd.nist.gov/vuln/detail/CVE-2021-23337
    https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm

Skipped:
  mylib  git dependency

Checked 3 packages: 2 vulnerable, 4 vulnerabilities (1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW), 1 skipped.
`

func TestWrite_AC3_6_Golden(t *testing.T) {
	dependencies, results := goldenInput()
	var b strings.Builder
	if _, err := Write(&b, dependencies, results); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if b.String() != golden {
		t.Fatalf("output mismatch\n--- got ---\n%s\n--- want ---\n%s", b.String(), golden)
	}
}

func TestWrite_AC3_6_SortByScoreThenID(t *testing.T) {
	dependencies := []deps.Dependency{{Name: "p", Version: "1.0.0", Source: deps.SourceLockfile}}
	results := []osv.Result{{Package: osv.Package{Name: "p", Version: "1.0.0"}, Vulns: []osv.Vuln{
		{ID: "GHSA-u2", DatabaseSpecific: json.RawMessage(`{"severity":"CRITICAL"}`)},
		{ID: "GHSA-b", Severity: []osv.Severity{sev("CVSS_V3", v31High)}},
		{ID: "GHSA-u1"},
		{ID: "GHSA-a", Severity: []osv.Severity{sev("CVSS_V3", v31High)}},
		{ID: "GHSA-c", Severity: []osv.Severity{sev("CVSS_V3", v31Critical)}},
	}}}
	var b strings.Builder
	if _, err := Write(&b, dependencies, results); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var order []string
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "  GHSA-") {
			order = append(order, strings.Fields(line)[0])
		}
	}
	if want := []string{"GHSA-c", "GHSA-a", "GHSA-b", "GHSA-u1", "GHSA-u2"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestWrite_AC3_7_SkippedSection(t *testing.T) {
	dependencies := []deps.Dependency{
		{Name: "a", Source: deps.SourceSkipped, SkipReason: "local path dependency"},
		{Name: "b", Source: deps.SourceSkipped, SkipReason: "npm alias is not resolved"},
	}
	var b strings.Builder
	sum, err := Write(&b, dependencies, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := "No known vulnerabilities found.\n\nSkipped:\n  a  local path dependency\n  b  npm alias is not resolved\n\nChecked 0 packages: 0 vulnerable, 0 vulnerabilities, 2 skipped.\n"
	if b.String() != want {
		t.Fatalf("output mismatch\n--- got ---\n%s\n--- want ---\n%s", b.String(), want)
	}
	if sum.Skipped != 2 || sum.Checked != 0 {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestWrite_AC3_8_Summary(t *testing.T) {
	dependencies, results := goldenInput()
	sum, err := Write(&strings.Builder{}, dependencies, results)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := Summary{
		Checked:            3,
		Skipped:            1,
		VulnerablePackages: 2,
		Vulns:              4,
		BySeverity:         map[string]int{"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
	}
	if !reflect.DeepEqual(sum, want) {
		t.Fatalf("summary = %+v, want %+v", sum, want)
	}
}

func TestWrite_AC3_8_Clean(t *testing.T) {
	dependencies := []deps.Dependency{
		{Name: "a", Version: "1.0.0", Source: deps.SourceLockfile},
		{Name: "b", Version: "2.0.0", Source: deps.SourceRange},
	}
	results := []osv.Result{
		{Package: osv.Package{Name: "a", Version: "1.0.0"}},
		{Package: osv.Package{Name: "b", Version: "2.0.0"}},
	}
	var b strings.Builder
	sum, err := Write(&b, dependencies, results)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := "No known vulnerabilities found.\n\nChecked 2 packages: 0 vulnerable, 0 vulnerabilities, 0 skipped.\n"
	if b.String() != want {
		t.Fatalf("output mismatch\n--- got ---\n%s\n--- want ---\n%s", b.String(), want)
	}
	if sum.Vulns != 0 || sum.VulnerablePackages != 0 || sum.Checked != 2 {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestSanitize_AC3_9(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain text", "plain text"},
		{"\x1b[31mred\x1b[0m", "red"},
		{"\x1b[1;2;3Hmove", "move"},
		{"\x1b]8;;https://evil.example\x07link\x1b]8;;\x07", "link"},
		{"\x1b]0;title\x1b\\after", "after"},
		{"line1\nline2\r\ttab", "line1 line2  tab"},
		{"bell\x07 del\x7f", "bell del"},
		{"c1\u009b31mx", "c131mx"},
		{"bidi\u202Eevil\u202C \u2066iso\u2069", "bidievil iso"},
		{"bad\xffutf8", "bad\uFFFDutf8"},
		{"lone esc \x1b end", "lone esc  end"},
	}
	for _, tc := range cases {
		if got := sanitize(tc.in); got != tc.want {
			t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWrite_AC3_9_SanitizedOutput(t *testing.T) {
	evil := "\x1b[2J\x1b]8;;https://evil\x07"
	dependencies := []deps.Dependency{
		{Name: "pkg" + evil, Version: "1.0.0", Source: deps.SourceLockfile},
		{Name: "skip\u202E" + evil, Source: deps.SourceSkipped, SkipReason: "reason" + evil},
	}
	results := []osv.Result{{Package: osv.Package{Name: "pkg" + evil, Version: "1.0.0"}, Vulns: []osv.Vuln{{
		ID:         "GHSA-1",
		Aliases:    []string{"CVE-1" + evil},
		Summary:    "summary\ntext" + evil + strings.Repeat("x", 200),
		Affected:   []osv.Affected{{Package: osv.AffectedPackage{Name: "pkg" + evil, Ecosystem: "npm"}, Ranges: []osv.Range{{Events: []osv.Event{{Fixed: "1.0.1" + evil}}}}}},
		References: []osv.Reference{{Type: "ADVISORY", URL: "https://example.com/" + evil}},
	}}}}
	var b strings.Builder
	if _, err := Write(&b, dependencies, results); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := b.String()
	for _, r := range out {
		if r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) {
			t.Fatalf("output contains control rune %U:\n%q", r, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "    summary") {
			text := strings.TrimPrefix(line, "    ")
			if n := len([]rune(text)); n != 120 || !strings.HasSuffix(text, "…") {
				t.Fatalf("summary line has %d runes, want 120 ending in …: %q", n, text)
			}
			return
		}
	}
	t.Fatalf("summary line not found:\n%s", out)
}

func TestTruncate_AC3_9(t *testing.T) {
	if got := truncate(strings.Repeat("a", 120), 120); got != strings.Repeat("a", 120) {
		t.Fatalf("120 runes changed: %q", got)
	}
	got := truncate(strings.Repeat("é", 200), 120)
	if want := strings.Repeat("é", 119) + "…"; got != want {
		t.Fatalf("truncate = %q, want %q", got, want)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWrite_AC3_10_Errors(t *testing.T) {
	t.Run("missing result", func(t *testing.T) {
		dependencies := []deps.Dependency{
			{Name: "a", Version: "1.0.0", Source: deps.SourceLockfile},
			{Name: "b", Version: "1.0.0", Source: deps.SourceLockfile},
		}
		results := []osv.Result{{Package: osv.Package{Name: "a", Version: "1.0.0"}}}
		if _, err := Write(&strings.Builder{}, dependencies, results); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		dependencies := []deps.Dependency{{Name: "a", Version: "1.0.0", Source: deps.SourceLockfile}}
		results := []osv.Result{{Package: osv.Package{Name: "a", Version: "2.0.0"}}}
		if _, err := Write(&strings.Builder{}, dependencies, results); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("writer error", func(t *testing.T) {
		dependencies, results := goldenInput()
		if _, err := Write(failingWriter{}, dependencies, results); err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Fatalf("err = %v, want writer error", err)
		}
	})
}
