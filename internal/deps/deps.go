package deps

import "errors"

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

func Resolve(projectDir string) ([]Dependency, error) {
	return nil, errors.New("not implemented")
}
