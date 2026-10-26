//go:build unix

package deps

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func resolveWithin(t *testing.T, dir string, d time.Duration) ([]Dependency, error) {
	t.Helper()
	type result struct {
		deps []Dependency
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		deps, err := Resolve(dir)
		ch <- result{deps, err}
	}()
	select {
	case r := <-ch:
		return r.deps, r.err
	case <-time.After(d):
		t.Fatalf("Resolve blocked for more than %s", d)
		return nil, nil
	}
}

func TestResolve_AC1_12_NonRegularFile(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"package.json fifo", func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "package.json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"package.json symlink to device", func(t *testing.T, dir string) {
			if err := os.Symlink("/dev/null", filepath.Join(dir, "package.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"lockfile fifo", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "package.json"), `{"dependencies": {"a": "1.0.0"}}`)
			if err := syscall.Mkfifo(filepath.Join(dir, "package-lock.json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"lockfile directory", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "package.json"), `{"dependencies": {"a": "1.0.0"}}`)
			if err := os.Mkdir(filepath.Join(dir, "package-lock.json"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			if _, err := resolveWithin(t, dir, 2*time.Second); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestResolve_AC1_12_SymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "real.json"), `{"dependencies": {"a": "^1.2.3"}}`)
	if err := os.Symlink("real.json", filepath.Join(dir, "package.json")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveWithin(t, dir, 2*time.Second)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	want := Dependency{Name: "a", Version: "1.2.3", Source: SourceRange}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v, want [%+v]", got, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
