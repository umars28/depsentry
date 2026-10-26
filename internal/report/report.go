package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/umars28/depsentry/internal/deps"
	"github.com/umars28/depsentry/internal/osv"
)

type Summary struct {
	Checked            int
	Skipped            int
	VulnerablePackages int
	Vulns              int
	BySeverity         map[string]int
}

const summaryLimit = 120

var labelOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}

type severity struct {
	score  float64
	scored bool
	label  string
}

func (s severity) String() string {
	if s.scored {
		return fmt.Sprintf("%.1f %s", s.score, s.label)
	}
	return s.label
}

func displayID(v osv.Vuln) string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

func severityOf(v osv.Vuln) severity {
	for _, typ := range []string{"CVSS_V4", "CVSS_V3"} {
		for _, s := range v.Severity {
			if s.Type != typ {
				continue
			}
			if score, ok := cvssScore(s.Score); ok {
				return severity{score: score, scored: true, label: labelFor(score)}
			}
		}
	}
	var db struct {
		Severity string `json:"severity"`
	}
	if len(v.DatabaseSpecific) > 0 && json.Unmarshal(v.DatabaseSpecific, &db) == nil {
		switch label := strings.ToUpper(db.Severity); label {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
			return severity{label: label}
		case "MODERATE":
			return severity{label: "MEDIUM"}
		}
	}
	return severity{label: "UNKNOWN"}
}

func cvssScore(vector string) (score float64, ok bool) {
	defer func() {
		if recover() != nil {
			score, ok = 0, false
		}
	}()
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		c, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.Score(), true
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		c, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		c, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	}
	return 0, false
}

func labelFor(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	}
	return "CRITICAL"
}

func fixedVersions(v osv.Vuln, name string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range v.Affected {
		if a.Package.Name != name || a.Package.Ecosystem != "npm" {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

func links(v osv.Vuln) []string {
	var out []string
	for _, r := range v.References {
		if r.Type != "ADVISORY" {
			continue
		}
		u, err := url.Parse(r.URL)
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil {
			out = append(out, r.URL)
			break
		}
	}
	return append(out, "https://osv.dev/vulnerability/"+url.PathEscape(v.ID))
}

var (
	ansiOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	ansiCSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
)

func Sanitize(s string) string {
	return sanitize(s)
}

func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = ansiOSC.ReplaceAllString(s, "")
	s = ansiCSI.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == ' ':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return -1
		case unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

type entry struct {
	vuln osv.Vuln
	id   string
	sev  severity
}

func Write(w io.Writer, dependencies []deps.Dependency, results []osv.Result) (Summary, error) {
	found := make(map[osv.Package][]osv.Vuln, len(results))
	for _, r := range results {
		found[r.Package] = r.Vulns
	}

	sum := Summary{BySeverity: map[string]int{}}
	var b strings.Builder
	var skipped []deps.Dependency
	for _, d := range dependencies {
		if d.Source == deps.SourceSkipped {
			skipped = append(skipped, d)
			continue
		}
		sum.Checked++
		vulns, ok := found[osv.Package{Name: d.Name, Version: d.Version}]
		if !ok {
			return Summary{}, fmt.Errorf("no OSV result for %q@%q", d.Name, d.Version)
		}
		if len(vulns) == 0 {
			continue
		}

		entries := make([]entry, len(vulns))
		for i, v := range vulns {
			entries[i] = entry{vuln: v, id: displayID(v), sev: severityOf(v)}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			a, c := entries[i], entries[j]
			if a.sev.scored != c.sev.scored {
				return a.sev.scored
			}
			if a.sev.score != c.sev.score {
				return a.sev.score > c.sev.score
			}
			return a.id < c.id
		})

		if sum.VulnerablePackages > 0 {
			b.WriteString("\n")
		}
		sum.VulnerablePackages++
		b.WriteString(sanitize(d.Name) + "@" + sanitize(d.Version))
		if d.Dev {
			b.WriteString(" (dev)")
		}
		if d.Source == deps.SourceRange {
			b.WriteString(" (from range)")
		}
		b.WriteString("\n")

		for _, e := range entries {
			fixed := fixedVersions(e.vuln, d.Name)
			for i := range fixed {
				fixed[i] = sanitize(fixed[i])
			}
			fixedText := "-"
			if len(fixed) > 0 {
				fixedText = strings.Join(fixed, ", ")
			}
			fmt.Fprintf(&b, "  %s  %s  fixed: %s\n", sanitize(e.id), e.sev, fixedText)
			if s := strings.TrimSpace(sanitize(e.vuln.Summary)); s != "" {
				fmt.Fprintf(&b, "    %s\n", truncate(s, summaryLimit))
			}
			for _, l := range links(e.vuln) {
				fmt.Fprintf(&b, "    %s\n", sanitize(l))
			}
			sum.Vulns++
			sum.BySeverity[e.sev.label]++
		}
	}
	sum.Skipped = len(skipped)

	if sum.Vulns == 0 {
		b.WriteString("No known vulnerabilities found.\n")
	}
	if len(skipped) > 0 {
		b.WriteString("\nSkipped:\n")
		for _, d := range skipped {
			fmt.Fprintf(&b, "  %s  %s\n", sanitize(d.Name), sanitize(d.SkipReason))
		}
	}

	counts := ""
	if sum.Vulns > 0 {
		var parts []string
		for _, l := range labelOrder {
			if n := sum.BySeverity[l]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, l))
			}
		}
		counts = " (" + strings.Join(parts, ", ") + ")"
	}
	fmt.Fprintf(&b, "\nChecked %s: %d vulnerable, %s%s, %d skipped.\n",
		count(sum.Checked, "package", "packages"), sum.VulnerablePackages,
		count(sum.Vulns, "vulnerability", "vulnerabilities"), counts, sum.Skipped)

	if _, err := io.WriteString(w, b.String()); err != nil {
		return Summary{}, fmt.Errorf("write report: %w", err)
	}
	return sum, nil
}
