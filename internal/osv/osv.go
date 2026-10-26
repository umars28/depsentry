package osv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type Package struct {
	Name    string
	Version string
}

type Result struct {
	Package Package
	Vulns   []Vuln
}

type Vuln struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Severity         []Severity      `json:"severity"`
	Affected         []Affected      `json:"affected"`
	References       []Reference     `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package AffectedPackage `json:"package"`
	Ranges  []Range         `json:"ranges"`
}

type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

var (
	maxBatchQueries   = 1000
	maxPages          = 100
	maxBatchBodyBytes = int64(32 << 20)
	maxVulnBodyBytes  = int64(4 << 20)
	maxAttempts       = 3
	backoffBase       = 500 * time.Millisecond
	maxRetryAfter     = 10 * time.Second
	detailConcurrency = 8
	httpTimeout       = 30 * time.Second
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	sleep      func(context.Context, time.Duration) error
}

func New(baseURL string) *Client {
	return &Client{baseURL: baseURL, httpClient: &http.Client{}}
}

func (c *Client) Check(ctx context.Context, pkgs []Package) ([]Result, error) {
	return nil, errors.New("not implemented")
}
