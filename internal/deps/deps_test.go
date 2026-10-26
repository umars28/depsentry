package deps

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeProject(t *testing.T, pkg, lock string) string {
	t.Helper()
	dir := t.TempDir()
	if pkg != "" {
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if lock != "" {
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustResolve(t *testing.T, dir string) []Dependency {
	t.Helper()
	got, err := Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	return got
}

func find(t *testing.T, deps []Dependency, name string) Dependency {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("dependency %q not found in %+v", name, deps)
	return Dependency{}
}

func TestResolve_AC1_1_ListAndDev(t *testing.T) {
	pkg := `{
		"dependencies": {"zod": "3.22.4", "express": "4.18.2", "shared": "1.0.0"},
		"devDependencies": {"jest": "29.7.0", "shared": "1.0.0"}
	}`
	got := mustResolve(t, writeProject(t, pkg, ""))
	want := []Dependency{
		{Name: "express", Version: "4.18.2", Source: SourceRange},
		{Name: "jest", Version: "29.7.0", Dev: true, Source: SourceRange},
		{Name: "shared", Version: "1.0.0", Source: SourceRange},
		{Name: "zod", Version: "3.22.4", Source: SourceRange},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestResolve_AC1_1_EmptyProject(t *testing.T) {
	got := mustResolve(t, writeProject(t, `{"name": "empty"}`, ""))
	if len(got) != 0 {
		t.Fatalf("got %+v, want no dependencies", got)
	}
}

func TestResolve_AC1_2_LockV1(t *testing.T) {
	pkg := `{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"@types/node": "^20.0.0"}}`
	lock := `{
		"lockfileVersion": 1,
		"dependencies": {
			"lodash": {"version": "4.17.15"},
			"@types/node": {"version": "20.11.5", "dev": true}
		}
	}`
	got := mustResolve(t, writeProject(t, pkg, lock))
	want := []Dependency{
		{Name: "@types/node", Version: "20.11.5", Dev: true, Source: SourceLockfile},
		{Name: "lodash", Version: "4.17.15", Source: SourceLockfile},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func lockV2V3(version int) string {
	v := "2"
	if version == 3 {
		v = "3"
	}
	return `{
		"lockfileVersion": ` + v + `,
		"packages": {
			"": {"dependencies": {"lodash": "^4.17.0"}},
			"node_modules/lodash": {"version": "4.17.15"},
			"node_modules/@babel/core": {"version": "7.23.0", "dev": true},
			"node_modules/foo/node_modules/lodash": {"version": "3.10.1"}
		}
	}`
}

func TestResolve_AC1_3_LockV2(t *testing.T) {
	pkg := `{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"@babel/core": "^7.0.0"}}`
	got := mustResolve(t, writeProject(t, pkg, lockV2V3(2)))
	want := []Dependency{
		{Name: "@babel/core", Version: "7.23.0", Dev: true, Source: SourceLockfile},
		{Name: "lodash", Version: "4.17.15", Source: SourceLockfile},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestResolve_AC1_4_LockV3(t *testing.T) {
	pkg := `{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"@babel/core": "^7.0.0"}}`
	got := mustResolve(t, writeProject(t, pkg, lockV2V3(3)))
	want := []Dependency{
		{Name: "@babel/core", Version: "7.23.0", Dev: true, Source: SourceLockfile},
		{Name: "lodash", Version: "4.17.15", Source: SourceLockfile},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestResolve_AC1_5_RangeFallback(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want string
	}{
		{"caret", "^4.17.0", "4.17.0"},
		{"tilde", "~1.2.3", "1.2.3"},
		{"exact", "1.2.3", "1.2.3"},
		{"gte with upper bound", ">= 1.2.3 < 2", "1.2.3"},
		{"gt", ">1.0.0", "1.0.0"},
		{"eq", "=2.0.0", "2.0.0"},
		{"v prefix", "~v2.0.1", "2.0.1"},
		{"or", "1.0.0 || 2.0.0", "1.0.0"},
		{"hyphen range", "1.2.3 - 2.3.4", "1.2.3"},
		{"prerelease", "^1.0.0-beta.1", "1.0.0-beta.1"},
		{"build", "1.0.0+build.5", "1.0.0+build.5"},
		{"surrounding whitespace", "  ^3.1.4  ", "3.1.4"},
	}
	lockMissing := `{"lockfileVersion": 3, "packages": {"": {}}}`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := `{"dependencies": {"pkg": "` + tc.spec + `"}}`
			got := find(t, mustResolve(t, writeProject(t, pkg, lockMissing)), "pkg")
			want := Dependency{Name: "pkg", Version: tc.want, Source: SourceRange}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestResolve_AC1_5_LockEntryWithoutVersion(t *testing.T) {
	cases := []struct {
		name string
		lock string
	}{
		{"v1", `{"lockfileVersion": 1, "dependencies": {"pkg": {"resolved": "x"}}}`},
		{"v3", `{"lockfileVersion": 3, "packages": {"node_modules/pkg": {"link": true}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := `{"dependencies": {"pkg": "^2.1.0"}}`
			got := find(t, mustResolve(t, writeProject(t, pkg, tc.lock)), "pkg")
			want := Dependency{Name: "pkg", Version: "2.1.0", Source: SourceRange}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestResolve_AC1_6_NoLock(t *testing.T) {
	pkg := `{"dependencies": {"a": "^1.0.0", "b": "~2.3.4"}, "devDependencies": {"c": ">=3.0.0"}}`
	got := mustResolve(t, writeProject(t, pkg, ""))
	want := []Dependency{
		{Name: "a", Version: "1.0.0", Source: SourceRange},
		{Name: "b", Version: "2.3.4", Source: SourceRange},
		{Name: "c", Version: "3.0.0", Dev: true, Source: SourceRange},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestResolve_AC1_7_NonRegistrySkipped(t *testing.T) {
	specs := []string{
		"git+https://github.com/user/repo.git",
		"git+ssh://git@github.com/user/repo.git",
		"git://github.com/user/repo.git",
		"github:user/repo",
		"file:../local",
		"link:../local",
		"workspace:*",
		"http://example.com/pkg.tgz",
		"https://example.com/pkg.tgz",
		"npm:lodash@4.17.21",
		"user/repo",
		"user/repo#v1.0.0",
	}
	locks := []struct {
		name string
		lock string
	}{
		{"no lock", ""},
		{"lock v1 entry", `{"lockfileVersion": 1, "dependencies": {"pkg": {"version": "1.0.0"}}}`},
		{"lock v3 entry", `{"lockfileVersion": 3, "packages": {"node_modules/pkg": {"version": "1.0.0"}}}`},
	}
	for _, l := range locks {
		for _, spec := range specs {
			t.Run(l.name+"/"+spec, func(t *testing.T) {
				pkg := `{"dependencies": {"pkg": "` + spec + `"}}`
				got := find(t, mustResolve(t, writeProject(t, pkg, l.lock)), "pkg")
				if got.Source != SourceSkipped {
					t.Fatalf("source = %q, want %q (%+v)", got.Source, SourceSkipped, got)
				}
				if got.SkipReason == "" {
					t.Fatalf("empty SkipReason: %+v", got)
				}
				if got.Version != "" {
					t.Fatalf("version = %q, want empty for skipped", got.Version)
				}
			})
		}
	}
}

func TestResolve_AC1_8_InexactRegistrySpec(t *testing.T) {
	specs := []string{"*", "latest", "next", "1.x", "1.2.x", ">=1", "^1", "x", ""}
	for _, spec := range specs {
		t.Run("lock/"+spec, func(t *testing.T) {
			pkg := `{"dependencies": {"pkg": "` + spec + `"}}`
			lock := `{"lockfileVersion": 2, "packages": {"node_modules/pkg": {"version": "4.17.15"}}}`
			got := find(t, mustResolve(t, writeProject(t, pkg, lock)), "pkg")
			want := Dependency{Name: "pkg", Version: "4.17.15", Source: SourceLockfile}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
		t.Run("nolock/"+spec, func(t *testing.T) {
			pkg := `{"dependencies": {"pkg": "` + spec + `"}}`
			got := find(t, mustResolve(t, writeProject(t, pkg, "")), "pkg")
			if got.Source != SourceSkipped || got.SkipReason == "" || got.Version != "" {
				t.Fatalf("got %+v, want skipped with reason and no version", got)
			}
		})
	}
}

func TestResolve_AC1_9_PackageJSONErrors(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
	}{
		{"missing", ""},
		{"malformed", `{"dependencies": {`},
		{"not an object", `[]`},
		{"dependencies not object", `{"dependencies": ["lodash"]}`},
		{"devDependencies not object", `{"devDependencies": "lodash"}`},
		{"spec not string", `{"dependencies": {"lodash": 4}}`},
		{"trailing garbage", `{"dependencies": {}} {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Resolve(writeProject(t, tc.pkg, "")); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestResolve_AC1_9_MissingProjectDir(t *testing.T) {
	if _, err := Resolve(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestResolve_AC1_10_LockfileErrors(t *testing.T) {
	cases := []struct {
		name string
		lock string
	}{
		{"malformed", `{"lockfileVersion": 3, "packages": {`},
		{"version 0", `{"lockfileVersion": 0}`},
		{"version missing", `{"packages": {}}`},
		{"version 4", `{"lockfileVersion": 4, "packages": {}}`},
		{"version string", `{"lockfileVersion": "3", "packages": {}}`},
		{"packages not object", `{"lockfileVersion": 3, "packages": []}`},
		{"v1 dependencies not object", `{"lockfileVersion": 1, "dependencies": "x"}`},
		{"entry version not string", `{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": 4}}}`},
		{"not an object", `null`},
	}
	pkg := `{"dependencies": {"lodash": "^4.17.0"}}`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Resolve(writeProject(t, pkg, tc.lock)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestResolve_AC1_11_SizeLimits(t *testing.T) {
	if maxPackageJSONBytes != 10<<20 {
		t.Fatalf("maxPackageJSONBytes = %d, want %d", maxPackageJSONBytes, 10<<20)
	}
	if maxLockfileBytes != 256<<20 {
		t.Fatalf("maxLockfileBytes = %d, want %d", maxLockfileBytes, 256<<20)
	}

	t.Run("package.json over limit", func(t *testing.T) {
		pkg := `{"dependencies": {}}` + strings.Repeat(" ", maxPackageJSONBytes)
		if _, err := Resolve(writeProject(t, pkg, "")); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("package.json at limit", func(t *testing.T) {
		base := `{"dependencies": {"a": "1.0.0"}}`
		pkg := base + strings.Repeat(" ", maxPackageJSONBytes-len(base))
		mustResolve(t, writeProject(t, pkg, ""))
	})

	t.Run("lockfile over limit", func(t *testing.T) {
		orig := maxLockfileBytes
		maxLockfileBytes = 1024
		t.Cleanup(func() { maxLockfileBytes = orig })
		lock := `{"lockfileVersion": 3, "packages": {}}` + strings.Repeat(" ", 1024)
		if _, err := Resolve(writeProject(t, `{"dependencies": {"a": "1.0.0"}}`, lock)); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
