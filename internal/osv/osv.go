package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
	maxIDsPerPackage  = 1000
	maxUniqueIDs      = 10000
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
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: httpTimeout},
		sleep:      sleepContext,
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) Check(ctx context.Context, pkgs []Package) ([]Result, error) {
	if len(pkgs) == 0 {
		return []Result{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	idsPerPkg, err := c.queryAll(ctx, pkgs)
	if err != nil {
		return nil, err
	}

	var unique []string
	seen := map[string]bool{}
	for _, ids := range idsPerPkg {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				unique = append(unique, id)
			}
		}
	}

	details, err := c.fetchVulns(ctx, unique)
	if err != nil {
		return nil, err
	}

	out := make([]Result, len(pkgs))
	for i, p := range pkgs {
		vulns := make([]Vuln, 0, len(idsPerPkg[i]))
		for _, id := range idsPerPkg[i] {
			vulns = append(vulns, details[id])
		}
		out[i] = Result{Package: p, Vulns: vulns}
	}
	return out, nil
}

type pendingQuery struct {
	index int
	token string
}

type batchQuery struct {
	Package   batchPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}

type batchPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

func (c *Client) queryAll(ctx context.Context, pkgs []Package) ([][]string, error) {
	ids := make([][]string, len(pkgs))
	unique := map[string]bool{}
	for start := 0; start < len(pkgs); start += maxBatchQueries {
		end := min(start+maxBatchQueries, len(pkgs))
		pending := make([]pendingQuery, 0, end-start)
		for i := start; i < end; i++ {
			pending = append(pending, pendingQuery{index: i})
		}
		seen := map[int]map[string]bool{}
		for page := 1; len(pending) > 0; page++ {
			if page > maxPages {
				return nil, fmt.Errorf("querybatch: package %q has more than %d result pages", pkgs[pending[0].index].Name, maxPages)
			}
			resp, err := c.queryBatch(ctx, pkgs, pending)
			if err != nil {
				return nil, err
			}
			var next []pendingQuery
			for i, r := range resp.Results {
				idx := pending[i].index
				if seen[idx] == nil {
					seen[idx] = map[string]bool{}
				}
				for _, v := range r.Vulns {
					if v.ID == "" {
						return nil, fmt.Errorf("querybatch: empty vuln id for package %q", pkgs[idx].Name)
					}
					if seen[idx][v.ID] {
						continue
					}
					seen[idx][v.ID] = true
					ids[idx] = append(ids[idx], v.ID)
					if len(ids[idx]) > maxIDsPerPackage {
						return nil, fmt.Errorf("querybatch: package %q has more than %d vulns", pkgs[idx].Name, maxIDsPerPackage)
					}
					if !unique[v.ID] {
						unique[v.ID] = true
						if len(unique) > maxUniqueIDs {
							return nil, fmt.Errorf("querybatch: more than %d unique vulns", maxUniqueIDs)
						}
					}
				}
				if r.NextPageToken != "" {
					next = append(next, pendingQuery{index: idx, token: r.NextPageToken})
				}
			}
			pending = next
		}
	}
	return ids, nil
}

func (c *Client) queryBatch(ctx context.Context, pkgs []Package, pending []pendingQuery) (*batchResponse, error) {
	queries := make([]batchQuery, len(pending))
	for i, q := range pending {
		p := pkgs[q.index]
		queries[i] = batchQuery{
			Package:   batchPackage{Name: p.Name, Ecosystem: "npm"},
			Version:   p.Version,
			PageToken: q.token,
		}
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, fmt.Errorf("querybatch: encode request: %w", err)
	}
	var resp batchResponse
	if err := c.do(ctx, http.MethodPost, "/v1/querybatch", body, maxBatchBodyBytes, &resp); err != nil {
		return nil, err
	}
	if len(resp.Results) != len(pending) {
		return nil, fmt.Errorf("querybatch: got %d results for %d queries", len(resp.Results), len(pending))
	}
	return &resp, nil
}

func (c *Client) fetchVulns(parent context.Context, ids []string) (map[string]Vuln, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	vulns := make([]Vuln, len(ids))
	sem := make(chan struct{}, detailConcurrency)
	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
	)
loop:
	for i, id := range ids {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := c.fetchVuln(ctx, id)
			if err != nil {
				once.Do(func() {
					firstErr = err
					cancel()
				})
				return
			}
			vulns[i] = v
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}

	out := make(map[string]Vuln, len(ids))
	for i, id := range ids {
		out[id] = vulns[i]
	}
	return out, nil
}

func (c *Client) fetchVuln(ctx context.Context, id string) (Vuln, error) {
	var v Vuln
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, maxVulnBodyBytes, &v); err != nil {
		return Vuln{}, err
	}
	if v.ID != id {
		return Vuln{}, fmt.Errorf("vuln %q: response has id %q", id, v.ID)
	}
	return v, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, limit int64, out any) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var retry bool
		var wait time.Duration
		retry, wait, err = c.attempt(ctx, method, path, body, limit, out)
		if err == nil {
			return nil
		}
		if !retry || ctx.Err() != nil || attempt == maxAttempts-1 {
			break
		}
		if wait < 0 {
			wait = rand.N(backoffBase<<attempt + 1)
		}
		if serr := c.sleep(ctx, wait); serr != nil {
			return fmt.Errorf("%s %s: %w", method, path, serr)
		}
	}
	return err
}

func (c *Client) attempt(ctx context.Context, method, path string, body []byte, limit int64, out any) (bool, time.Duration, error) {
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return false, 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return true, -1, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retry, parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("%s %s: unexpected status %d", method, path, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return true, -1, fmt.Errorf("%s %s: read body: %w", method, path, err)
	}
	if int64(len(data)) > limit {
		return false, 0, fmt.Errorf("%s %s: response exceeds %d bytes", method, path, limit)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, 0, fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return false, 0, nil
}

func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs < 0 {
		return -1
	}
	return min(time.Duration(secs)*time.Second, maxRetryAfter)
}
