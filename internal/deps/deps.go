package deps

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Source string

const (
	SourceLockfile Source = "lockfile"
	SourceRange    Source = "range"
	SourceSkipped  Source = "skipped"
)

type Dependency struct {
	Name       string
	Version    string
	Dev        bool
	Source     Source
	SkipReason string
}

var (
	maxPackageJSONBytes = 10 << 20
	maxLockfileBytes    = 256 << 20
)

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type lockEntry struct {
	Version string `json:"version"`
}

type lockfile struct {
	LockfileVersion *int                 `json:"lockfileVersion"`
	Packages        map[string]lockEntry `json:"packages"`
	Dependencies    map[string]lockEntry `json:"dependencies"`
}

func (l *lockfile) version(name string) string {
	if l == nil {
		return ""
	}
	if *l.LockfileVersion == 1 {
		return l.Dependencies[name].Version
	}
	return l.Packages["node_modules/"+name].Version
}

func Resolve(projectDir string) ([]Dependency, error) {
	pkg, err := readPackageJSON(filepath.Join(projectDir, "package.json"))
	if err != nil {
		return nil, err
	}
	lock, err := readLockfile(filepath.Join(projectDir, "package-lock.json"))
	if err != nil {
		return nil, err
	}

	specs := make(map[string]string, len(pkg.Dependencies)+len(pkg.DevDependencies))
	dev := make(map[string]bool, len(pkg.DevDependencies))
	for name, spec := range pkg.DevDependencies {
		specs[name] = spec
		dev[name] = true
	}
	for name, spec := range pkg.Dependencies {
		specs[name] = spec
		dev[name] = false
	}

	names := make([]string, 0, len(specs))
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Dependency, 0, len(names))
	for _, name := range names {
		d := resolveOne(name, specs[name], lock)
		d.Dev = dev[name]
		out = append(out, d)
	}
	return out, nil
}

func resolveOne(name, spec string, lock *lockfile) Dependency {
	d := Dependency{Name: name}
	if reason, ok := nonRegistryReason(spec); ok {
		d.Source = SourceSkipped
		d.SkipReason = reason
		return d
	}
	if v := lock.version(name); v != "" {
		if !exactVersion.MatchString(v) {
			d.Source = SourceSkipped
			d.SkipReason = "lockfile version is not an exact version"
			return d
		}
		d.Version = v
		d.Source = SourceLockfile
		return d
	}
	if v, ok := baseVersion(spec); ok {
		d.Version = v
		d.Source = SourceRange
		return d
	}
	d.Source = SourceSkipped
	d.SkipReason = "no exact version in range and no lockfile entry"
	return d
}

var nonRegistryPrefixes = []struct {
	prefix string
	reason string
}{
	{"git+", "git dependency"},
	{"git://", "git dependency"},
	{"github:", "git dependency"},
	{"gitlab:", "git dependency"},
	{"bitbucket:", "git dependency"},
	{"gist:", "git dependency"},
	{"file:", "local path dependency"},
	{"link:", "local path dependency"},
	{"workspace:", "workspace dependency"},
	{"http://", "tarball URL dependency"},
	{"https://", "tarball URL dependency"},
	{"npm:", "npm alias is not resolved"},
}

func nonRegistryReason(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	for _, p := range nonRegistryPrefixes {
		if strings.HasPrefix(s, p.prefix) {
			return p.reason, true
		}
	}
	if strings.Contains(s, "/") {
		return "git or local path dependency", true
	}
	return "", false
}

var exactVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func baseVersion(spec string) (string, bool) {
	fields := strings.Fields(strings.TrimLeft(strings.TrimSpace(spec), "^~>=v \t"))
	if len(fields) == 0 || !exactVersion.MatchString(fields[0]) {
		return "", false
	}
	return fields[0], true
}

func readPackageJSON(path string) (*packageJSON, error) {
	data, err := readLimited(path, maxPackageJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	return &pkg, nil
}

func readLockfile(path string) (*lockfile, error) {
	data, err := readLimited(path, maxLockfileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if lock.LockfileVersion == nil {
		return nil, errors.New("parse package-lock.json: missing lockfileVersion")
	}
	if v := *lock.LockfileVersion; v < 1 || v > 3 {
		return nil, fmt.Errorf("parse package-lock.json: unsupported lockfileVersion %d", v)
	}
	return &lock, nil
}

func checkRegular(f *os.File) (*os.File, error) {
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(f.Name()))
	}
	return f, nil
}

func readLimited(path string, limit int) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}
