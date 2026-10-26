package report

import (
	"errors"
	"io"

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

type severity struct {
	score  float64
	scored bool
	label  string
}

func (s severity) String() string { return "" }

func displayID(v osv.Vuln) string { return "" }

func severityOf(v osv.Vuln) severity { return severity{} }

func fixedVersions(v osv.Vuln, name string) []string { return nil }

func links(v osv.Vuln) []string { return nil }

func sanitize(s string) string { return "" }

func truncate(s string, n int) string { return "" }

func Write(w io.Writer, dependencies []deps.Dependency, results []osv.Result) (Summary, error) {
	return Summary{}, errors.New("not implemented")
}
