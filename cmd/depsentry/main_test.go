package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const lodashDetail = `{
	"id": "GHSA-35jh-r3h4-6jhm",
	"aliases": ["CVE-2021-23337"],
	"summary": "Command Injection in lodash",
	"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
	"affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
	"references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
}`

type fakeOSV struct {
	vulns   map[string][]string
	details map[string]string

	mu      sync.Mutex
	queries []string
	calls   int
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		var req struct {
			Queries []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]map[string]any, len(req.Queries))
		f.mu.Lock()
		for i, q := range req.Queries {
			key := q.Package.Name + "@" + q.Version
			f.queries = append(f.queries, key)
			var vs []map[string]string
			for _, id := range f.vulns[key] {
				vs = append(vs, map[string]string{"id": id})
			}
			results[i] = map[string]any{}
			if len(vs) > 0 {
				results[i]["vulns"] = vs
			}
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		body, ok := f.details[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOSV) sortedQueries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.queries...)
	sort.Strings(out)
	return out
}

func newFake(t *testing.T) (*fakeOSV, string) {
	t.Helper()
	f := &fakeOSV{
		vulns:   map[string][]string{"lodash@4.17.15": {"GHSA-35jh-r3h4-6jhm"}, "lodash@4.17.0": {"GHSA-35jh-r3h4-6jhm"}},
		details: map[string]string{"GHSA-35jh-r3h4-6jhm": lodashDetail},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

type output struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, ctx context.Context, url string, args ...string) output {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(ctx, args, &stdout, &stderr, url)
	return output{code, stdout.String(), stderr.String()}
}

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRun_AC4_1_Usage(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no path", nil},
		{"two paths", []string{fixture("clean"), fixture("clean")}},
		{"unknown flag", []string{"--bogus", fixture("clean")}},
		{"zero timeout", []string{"--timeout", "0s", fixture("clean")}},
		{"negative timeout", []string{"--timeout", "-1s", fixture("clean")}},
		{"invalid timeout", []string{"--timeout", "soon", fixture("clean")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, url := newFake(t)
			out := runCLI(t, context.Background(), url, tc.args...)
			if out.code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr %q)", out.code, out.stderr)
			}
			if !strings.Contains(out.stderr, "usage: depsentry [--timeout <duration>] <project-path>") {
				t.Fatalf("stderr missing usage: %q", out.stderr)
			}
			if out.stdout != "" || f.calls != 0 {
				t.Fatalf("stdout %q, %d OSV calls; want none", out.stdout, f.calls)
			}
		})
	}

	for _, flag := range []string{"-h", "--help"} {
		t.Run(flag, func(t *testing.T) {
			f, url := newFake(t)
			out := runCLI(t, context.Background(), url, flag)
			if out.code != 0 {
				t.Fatalf("exit = %d, want 0", out.code)
			}
			if !strings.Contains(out.stderr, "usage: depsentry") || !strings.Contains(out.stderr, "default 2m0s") {
				t.Fatalf("stderr missing usage or default timeout: %q", out.stderr)
			}
			if out.stdout != "" || f.calls != 0 {
				t.Fatalf("stdout %q, %d OSV calls; want none", out.stdout, f.calls)
			}
		})
	}
}

func TestRun_AC4_2_Clean(t *testing.T) {
	f, url := newFake(t)
	out := runCLI(t, context.Background(), url, fixture("clean"))
	if out.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", out.code, out.stderr)
	}
	if !strings.Contains(out.stdout, "No known vulnerabilities found.") || !strings.Contains(out.stdout, "Checked 2 packages") {
		t.Fatalf("unexpected stdout:\n%s", out.stdout)
	}
	if out.stderr != "" {
		t.Fatalf("stderr = %q, want empty", out.stderr)
	}
	if got, want := f.sortedQueries(), []string{"express@4.21.2", "jest@29.7.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("queries = %v, want %v", got, want)
	}
}

func TestRun_AC4_3_Vulnerable(t *testing.T) {
	f, url := newFake(t)
	out := runCLI(t, context.Background(), url, fixture("vulnerable"))
	if out.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr %q)", out.code, out.stderr)
	}
	for _, want := range []string{
		"lodash@4.17.15\n",
		"CVE-2021-23337  7.2 HIGH  fixed: 4.17.21",
		"Skipped:\n  mylib  git dependency",
		"Checked 2 packages: 1 vulnerable, 1 vulnerability (1 HIGH), 1 skipped.",
	} {
		if !strings.Contains(out.stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, out.stdout)
		}
	}
	if out.stderr != "" {
		t.Errorf("stderr = %q, want empty", out.stderr)
	}
	if got, want := f.sortedQueries(), []string{"express@4.21.2", "lodash@4.17.15"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("queries = %v, want %v", got, want)
	}
}

func TestRun_AC4_4_Versions(t *testing.T) {
	t.Run("lock v1", func(t *testing.T) {
		f, url := newFake(t)
		out := runCLI(t, context.Background(), url, fixture("lock-v1"))
		if out.code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr %q)", out.code, out.stderr)
		}
		if got, want := f.sortedQueries(), []string{"lodash@4.17.21", "minimist@1.2.5"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("queries = %v, want %v", got, want)
		}
	})

	t.Run("no lock", func(t *testing.T) {
		f, url := newFake(t)
		out := runCLI(t, context.Background(), url, fixture("no-lock"))
		if out.code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr %q)", out.code, out.stderr)
		}
		if got, want := f.sortedQueries(), []string{"express@4.18.0", "lodash@4.17.0"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("queries = %v, want %v", got, want)
		}
		if !strings.Contains(out.stdout, "lodash@4.17.0 (from range)\n") {
			t.Fatalf("stdout missing from-range marker:\n%s", out.stdout)
		}
	})

	for name, pkg := range map[string]string{
		"all skipped":     `{"dependencies": {"a": "file:../a", "b": "github:x/b"}}`,
		"no dependencies": `{"name": "empty"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f, url := newFake(t)
			out := runCLI(t, context.Background(), url, writeProject(t, map[string]string{"package.json": pkg}))
			if out.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr %q)", out.code, out.stderr)
			}
			if f.calls != 0 {
				t.Fatalf("%d OSV calls, want none", f.calls)
			}
			if !strings.Contains(out.stdout, "No known vulnerabilities found.") {
				t.Fatalf("unexpected stdout:\n%s", out.stdout)
			}
		})
	}
}

func assertError(t *testing.T, out output) {
	t.Helper()
	if out.code != 2 {
		t.Fatalf("exit = %d, want 2 (stdout %q, stderr %q)", out.code, out.stdout, out.stderr)
	}
	if out.stdout != "" {
		t.Fatalf("stdout = %q, want empty", out.stdout)
	}
	if !strings.HasPrefix(out.stderr, "depsentry: ") || !strings.HasSuffix(out.stderr, "\n") {
		t.Fatalf("stderr = %q, want 'depsentry: <message>\\n'", out.stderr)
	}
}

func TestRun_AC4_5_Errors(t *testing.T) {
	cases := []struct {
		name string
		dir  func(t *testing.T) string
	}{
		{"missing directory", func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") }},
		{"missing package.json", func(t *testing.T) string { return t.TempDir() }},
		{"malformed package.json", func(t *testing.T) string {
			return writeProject(t, map[string]string{"package.json": `{"dependencies": {`})
		}},
		{"malformed lockfile", func(t *testing.T) string {
			return writeProject(t, map[string]string{
				"package.json":      `{"dependencies": {"lodash": "^4.17.0"}}`,
				"package-lock.json": `{"lockfileVersion": 3, "packages": {`,
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, url := newFake(t)
			assertError(t, runCLI(t, context.Background(), url, tc.dir(t)))
			if f.calls != 0 {
				t.Fatalf("%d OSV calls, want none", f.calls)
			}
		})
	}

	for name, code := range map[string]int{"osv 500": http.StatusInternalServerError, "osv 400": http.StatusBadRequest} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", code)
			}))
			t.Cleanup(srv.Close)
			assertError(t, runCLI(t, context.Background(), srv.URL, fixture("vulnerable")))
		})
	}

	t.Run("osv unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		assertError(t, runCLI(t, context.Background(), url, "--timeout", "10s", fixture("vulnerable")))
	})
}

func TestRun_AC4_6_Deadline(t *testing.T) {
	t.Run("hanging server", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		t.Cleanup(srv.Close)
		t.Cleanup(func() { close(release) })
		start := time.Now()
		out := runCLI(t, context.Background(), srv.URL, "--timeout", "200ms", fixture("vulnerable"))
		assertError(t, out)
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("run took %s with a 200ms timeout", elapsed)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		f, url := newFake(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertError(t, runCLI(t, ctx, url, fixture("vulnerable")))
		if f.calls != 0 {
			t.Fatalf("%d OSV calls after cancel, want none", f.calls)
		}
	})
}

func TestRun_AC4_7_SanitizedErrors(t *testing.T) {
	cases := map[string]string{
		"type error with hostile key": `{"dependencies": {"\u001b[2J\u001b]8;;https://evil\u0007x\u202e": 5}}`,
		"hostile lockfile version":    `{"dependencies": {"\u001b[31mevil": "^1.0.0"}}`,
	}
	for name, pkg := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"package.json": pkg}
			if strings.Contains(name, "lockfile") {
				files["package-lock.json"] = `{"lockfileVersion": 3, "packages": {"node_modules/\u001b[31mevil": {"version": 7}}}`
			}
			_, url := newFake(t)
			out := runCLI(t, context.Background(), url, writeProject(t, files))
			assertError(t, out)
			for _, r := range strings.TrimSuffix(out.stderr, "\n") {
				if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e {
					t.Fatalf("stderr contains control rune %U: %q", r, out.stderr)
				}
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRun_AC4_8_ExitCodeIntegrity(t *testing.T) {
	for _, name := range []string{"clean", "vulnerable"} {
		t.Run("report write fails/"+name, func(t *testing.T) {
			_, url := newFake(t)
			var stderr strings.Builder
			code := run(context.Background(), []string{fixture(name)}, failingWriter{}, &stderr, url)
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.HasPrefix(stderr.String(), "depsentry: ") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}

	t.Run("missing OSV detail is not clean", func(t *testing.T) {
		f, url := newFake(t)
		f.details = map[string]string{}
		assertError(t, runCLI(t, context.Background(), url, fixture("vulnerable")))
	})
}
