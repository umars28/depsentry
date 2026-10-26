package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/umars28/depsentry/internal/deps"
	"github.com/umars28/depsentry/internal/osv"
	"github.com/umars28/depsentry/internal/report"
)

const (
	defaultOSVURL  = "https://api.osv.dev"
	defaultTimeout = 2 * time.Minute
	usageLine      = "usage: depsentry [--timeout <duration>] <project-path>"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultOSVURL)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, osvURL string) int {
	fs := flag.NewFlagSet("depsentry", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", defaultTimeout, "overall deadline for the OSV queries")
	fs.Usage = func() {
		fmt.Fprintln(stderr, usageLine)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 || *timeout <= 0 {
		fs.Usage()
		return 2
	}

	dependencies, err := deps.Resolve(fs.Arg(0))
	if err != nil {
		return fail(stderr, err)
	}

	var pkgs []osv.Package
	for _, d := range dependencies {
		if d.Source != deps.SourceSkipped {
			pkgs = append(pkgs, osv.Package{Name: d.Name, Version: d.Version})
		}
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	results, err := osv.New(osvURL).Check(ctx, pkgs)
	if err != nil {
		return fail(stderr, fmt.Errorf("query OSV: %w", err))
	}

	sum, err := report.Write(stdout, dependencies, results)
	if err != nil {
		return fail(stderr, err)
	}
	if sum.Vulns > 0 {
		return 1
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "depsentry: %s\n", report.Sanitize(err.Error()))
	return 2
}
