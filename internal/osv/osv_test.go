package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sleepLog struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (s *sleepLog) get() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.delays...)
}

func newTestClient(t *testing.T, h http.Handler) (*Client, *sleepLog) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New(srv.URL)
	log := &sleepLog{}
	c.sleep = func(ctx context.Context, d time.Duration) error {
		log.mu.Lock()
		log.delays = append(log.delays, d)
		log.mu.Unlock()
		return ctx.Err()
	}
	return c, log
}

type batchRequest struct {
	Queries []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version   string `json:"version"`
		PageToken string `json:"page_token"`
	} `json:"queries"`
}

type batchResult struct {
	Vulns []map[string]string `json:"vulns,omitempty"`
	Next  string              `json:"next_page_token,omitempty"`
}

type fakeOSV struct {
	pages   map[string][][]string
	details map[string]string
	delay   time.Duration

	mu          sync.Mutex
	batchSizes  []int
	names       []string
	pageTokens  []string
	vulnCalls   map[string]int
	vulnPaths   []string
	inflight    int
	maxInflight int
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		f.batch(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/v1/vulns/"):
		f.vuln(w, r)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
	}
}

func (f *fakeOSV) batch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := make([]batchResult, 0, len(req.Queries))
	f.mu.Lock()
	f.batchSizes = append(f.batchSizes, len(req.Queries))
	for _, q := range req.Queries {
		if q.Package.Ecosystem != "npm" || q.Version == "" {
			f.mu.Unlock()
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		page := 0
		if q.PageToken != "" {
			f.pageTokens = append(f.pageTokens, q.PageToken)
			if _, err := fmt.Sscanf(q.PageToken, "page-%d", &page); err != nil {
				f.mu.Unlock()
				http.Error(w, "bad token", http.StatusBadRequest)
				return
			}
		} else {
			f.names = append(f.names, q.Package.Name)
		}
		res := batchResult{}
		pages := f.pages[q.Package.Name]
		if page < len(pages) {
			for _, id := range pages[page] {
				res.Vulns = append(res.Vulns, map[string]string{"id": id, "modified": "2024-01-01T00:00:00Z"})
			}
			if page+1 < len(pages) {
				res.Next = fmt.Sprintf("page-%d", page+1)
			}
		}
		out = append(out, res)
	}
	f.mu.Unlock()
	writeJSON(w, map[string]any{"results": out})
}

func (f *fakeOSV) vuln(w http.ResponseWriter, r *http.Request) {
	esc := strings.TrimPrefix(r.URL.EscapedPath(), "/v1/vulns/")
	id, err := url.PathUnescape(esc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	if f.vulnCalls == nil {
		f.vulnCalls = map[string]int{}
	}
	f.vulnCalls[id]++
	f.vulnPaths = append(f.vulnPaths, esc)
	f.inflight++
	if f.inflight > f.maxInflight {
		f.maxInflight = f.inflight
	}
	body, ok := f.details[id]
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if !ok {
		b, _ := json.Marshal(map[string]string{"id": id})
		body = string(b)
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, body)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func ids(r Result) []string {
	out := []string{}
	for _, v := range r.Vulns {
		out = append(out, v.ID)
	}
	return out
}

func TestCheck_AC2_1_QueryBatchOrder(t *testing.T) {
	f := &fakeOSV{pages: map[string][][]string{
		"lodash":      {{"GHSA-a", "GHSA-b"}},
		"@scope/name": {{"GHSA-c"}},
	}}
	c, _ := newTestClient(t, f)
	pkgs := []Package{
		{Name: "lodash", Version: "4.17.15"},
		{Name: "@scope/name", Version: "1.0.0"},
		{Name: "clean", Version: "1.0.0"},
	}
	got, err := c.Check(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(got) != len(pkgs) {
		t.Fatalf("got %d results, want %d", len(got), len(pkgs))
	}
	want := [][]string{{"GHSA-a", "GHSA-b"}, {"GHSA-c"}, {}}
	for i, r := range got {
		if r.Package != pkgs[i] {
			t.Errorf("result %d package = %+v, want %+v", i, r.Package, pkgs[i])
		}
		if !reflect.DeepEqual(ids(r), want[i]) {
			t.Errorf("result %d ids = %v, want %v", i, ids(r), want[i])
		}
	}
	if !reflect.DeepEqual(f.batchSizes, []int{3}) {
		t.Errorf("batch sizes = %v, want [3]", f.batchSizes)
	}
	if !reflect.DeepEqual(f.names, []string{"lodash", "@scope/name", "clean"}) {
		t.Errorf("queried names = %v", f.names)
	}
	for _, p := range f.vulnPaths {
		if strings.Contains(p, "scope") {
			t.Errorf("package name leaked into URL path %q", p)
		}
	}
}

func TestCheck_AC2_2_SplitBatches(t *testing.T) {
	f := &fakeOSV{pages: map[string][][]string{
		"pkg-0":    {{"GHSA-0"}},
		"pkg-1500": {{"GHSA-1500"}},
		"pkg-2499": {{"GHSA-2499"}},
	}}
	c, _ := newTestClient(t, f)
	pkgs := make([]Package, 2500)
	for i := range pkgs {
		pkgs[i] = Package{Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"}
	}
	got, err := c.Check(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	sizes := append([]int(nil), f.batchSizes...)
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))
	if !reflect.DeepEqual(sizes, []int{1000, 1000, 500}) {
		t.Fatalf("batch sizes = %v, want 1000, 1000, 500", f.batchSizes)
	}
	if len(got) != len(pkgs) {
		t.Fatalf("got %d results, want %d", len(got), len(pkgs))
	}
	for i, r := range got {
		if r.Package != pkgs[i] {
			t.Fatalf("result %d package = %+v, want %+v", i, r.Package, pkgs[i])
		}
	}
	for _, i := range []int{0, 1500, 2499} {
		if want := []string{fmt.Sprintf("GHSA-%d", i)}; !reflect.DeepEqual(ids(got[i]), want) {
			t.Errorf("result %d ids = %v, want %v", i, ids(got[i]), want)
		}
	}
	if len(got[1].Vulns) != 0 {
		t.Errorf("result 1 ids = %v, want none", ids(got[1]))
	}
}

func TestCheck_AC2_3_Pagination(t *testing.T) {
	f := &fakeOSV{pages: map[string][][]string{
		"multi":  {{"GHSA-a"}, {"GHSA-b"}, {"GHSA-c"}},
		"single": {{"GHSA-d"}},
	}}
	c, _ := newTestClient(t, f)
	got, err := c.Check(context.Background(), []Package{{Name: "multi", Version: "1.0.0"}, {Name: "single", Version: "1.0.0"}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if want := []string{"GHSA-a", "GHSA-b", "GHSA-c"}; !reflect.DeepEqual(ids(got[0]), want) {
		t.Errorf("multi ids = %v, want %v", ids(got[0]), want)
	}
	if want := []string{"GHSA-d"}; !reflect.DeepEqual(ids(got[1]), want) {
		t.Errorf("single ids = %v, want %v", ids(got[1]), want)
	}
	if want := []string{"page-1", "page-2"}; !reflect.DeepEqual(f.pageTokens, want) {
		t.Errorf("page tokens sent = %v, want %v", f.pageTokens, want)
	}
}

func TestCheck_AC2_3_PageLimit(t *testing.T) {
	cases := []struct {
		pages   int
		wantErr bool
	}{
		{100, false},
		{101, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.pages), func(t *testing.T) {
			f := &fakeOSV{pages: map[string][][]string{"loop": make([][]string, tc.pages)}}
			c, _ := newTestClient(t, f)
			got, err := c.Check(context.Background(), []Package{{Name: "loop", Version: "1.0.0"}})
			if tc.wantErr {
				if err == nil || got != nil {
					t.Fatalf("got %v, %v; want nil results and an error", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
		})
	}
}

func TestCheck_AC2_4_FetchDetailsOncePerID(t *testing.T) {
	full := `{"id":"GHSA-shared","aliases":["CVE-2021-23337"],"summary":"Command injection","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],"references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],"database_specific":{"severity":"HIGH"}}`
	f := &fakeOSV{
		pages: map[string][][]string{
			"a": {{"GHSA-shared", "ODD/ID?x"}},
			"b": {{"GHSA-shared"}},
		},
		details: map[string]string{"GHSA-shared": full},
	}
	c, _ := newTestClient(t, f)
	got, err := c.Check(context.Background(), []Package{{Name: "a", Version: "1.0.0"}, {Name: "b", Version: "1.0.0"}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if f.vulnCalls["GHSA-shared"] != 1 || f.vulnCalls["ODD/ID?x"] != 1 {
		t.Errorf("vuln calls = %v, want each ID once", f.vulnCalls)
	}
	found := false
	for _, p := range f.vulnPaths {
		if p == "ODD%2FID%3Fx" {
			found = true
		}
	}
	if !found {
		t.Errorf("escaped path not requested; paths = %v", f.vulnPaths)
	}
	want := Vuln{
		ID:         "GHSA-shared",
		Aliases:    []string{"CVE-2021-23337"},
		Summary:    "Command injection",
		Severity:   []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}},
		Affected:   []Affected{{Package: AffectedPackage{Name: "lodash", Ecosystem: "npm"}, Ranges: []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "4.17.21"}}}}}},
		References: []Reference{{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}},
	}
	for i, r := range []Vuln{got[0].Vulns[0], got[1].Vulns[0]} {
		if string(r.DatabaseSpecific) != `{"severity":"HIGH"}` {
			t.Errorf("result %d database_specific = %s", i, r.DatabaseSpecific)
		}
		r.DatabaseSpecific = nil
		if !reflect.DeepEqual(r, want) {
			t.Errorf("result %d vuln = %+v\nwant %+v", i, r, want)
		}
	}
	if got[0].Vulns[1].ID != "ODD/ID?x" {
		t.Errorf("second vuln of a = %q", got[0].Vulns[1].ID)
	}
}

func TestCheck_AC2_5_ConcurrencyLimit(t *testing.T) {
	f := &fakeOSV{pages: map[string][][]string{}, delay: 30 * time.Millisecond}
	pkgs := make([]Package, 30)
	for i := range pkgs {
		name := fmt.Sprintf("pkg-%d", i)
		pkgs[i] = Package{Name: name, Version: "1.0.0"}
		f.pages[name] = [][]string{{fmt.Sprintf("GHSA-%d", i)}}
	}
	c, _ := newTestClient(t, f)
	if _, err := c.Check(context.Background(), pkgs); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if f.maxInflight > 8 {
		t.Errorf("max in-flight detail requests = %d, want <= 8", f.maxInflight)
	}
	if f.maxInflight < 2 {
		t.Errorf("max in-flight detail requests = %d, want parallel fetches", f.maxInflight)
	}
}

func TestCheck_AC2_6_EmptyInput(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	got, err := c.Check(context.Background(), nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(got) != 0 || calls.Load() != 0 {
		t.Fatalf("got %d results and %d requests, want none", len(got), calls.Load())
	}
}

func route(batch, vuln http.HandlerFunc) http.Handler {
	if batch == nil {
		batch = func(w http.ResponseWriter, r *http.Request) {
			var req batchRequest
			json.NewDecoder(r.Body).Decode(&req)
			out := make([]batchResult, len(req.Queries))
			for i := range out {
				out[i] = batchResult{Vulns: []map[string]string{{"id": "GHSA-1"}}}
			}
			writeJSON(w, map[string]any{"results": out})
		}
	}
	if vuln == nil {
		vuln = func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"id": strings.TrimPrefix(r.URL.Path, "/v1/vulns/")})
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			batch(w, r)
			return
		}
		vuln(w, r)
	})
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", code)
	}
}

func raw(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
}

func TestCheck_AC2_7_Errors(t *testing.T) {
	cases := []struct {
		name string
		h    http.Handler
	}{
		{"batch 400", route(status(http.StatusBadRequest), nil)},
		{"vuln 404", route(nil, status(http.StatusNotFound))},
		{"batch malformed", route(raw(`{"results": [`), nil)},
		{"vuln malformed", route(nil, raw(`{"id": `))},
		{"batch results count mismatch", route(raw(`{"results": []}`), nil)},
		{"batch results missing", route(raw(`{}`), nil)},
		{"empty vuln id", route(raw(`{"results": [{"vulns": [{"id": ""}]}]}`), nil)},
		{"vuln id mismatch", route(nil, raw(`{"id": "GHSA-other"}`))},
		{"vuln not an object", route(nil, raw(`null`))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, tc.h)
			got, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got != nil {
				t.Fatalf("got partial results %+v", got)
			}
		})
	}
}

func TestCheck_AC2_8_Timeout(t *testing.T) {
	if got := New("http://example.invalid").httpClient.Timeout; got != 30*time.Second {
		t.Fatalf("default timeout = %s, want 30s", got)
	}

	t.Run("request exceeds timeout", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}))
		c.httpClient.Timeout = 50 * time.Millisecond
		start := time.Now()
		got, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}})
		if err == nil || got != nil {
			t.Fatalf("got %v, %v; want nil results and an error", got, err)
		}
		if time.Since(start) > 1500*time.Millisecond {
			t.Fatalf("Check took %s, timeout not applied", time.Since(start))
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		var calls atomic.Int32
		c, log := newTestClient(t, route(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			status(http.StatusServiceUnavailable)(w, r)
		}, nil))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := c.Check(ctx, []Package{{Name: "lodash", Version: "4.17.15"}})
		if !errors.Is(err, context.Canceled) || got != nil {
			t.Fatalf("got %v, %v; want nil results and context.Canceled", got, err)
		}
		if calls.Load() != 0 || len(log.get()) != 0 {
			t.Fatalf("%d requests and %d sleeps after cancel, want none", calls.Load(), len(log.get()))
		}
	})
}

type countingBody struct {
	io.ReadCloser
	closed *atomic.Int32
}

func (b countingBody) Close() error {
	b.closed.Add(1)
	return b.ReadCloser.Close()
}

type countingTransport struct {
	opened, closed atomic.Int32
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	t.opened.Add(1)
	resp.Body = countingBody{resp.Body, &t.closed}
	return resp, nil
}

func TestCheck_AC2_9_BodyLimits(t *testing.T) {
	if maxBatchBodyBytes != 32<<20 || maxVulnBodyBytes != 4<<20 {
		t.Fatalf("limits = %d/%d, want %d/%d", maxBatchBodyBytes, maxVulnBodyBytes, 32<<20, 4<<20)
	}

	t.Run("vuln over limit", func(t *testing.T) {
		big := `{"id":"GHSA-1","summary":"` + strings.Repeat("a", int(maxVulnBodyBytes)) + `"}`
		c, _ := newTestClient(t, route(nil, raw(big)))
		got, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}})
		if err == nil || got != nil {
			t.Fatalf("got %v, %v; want nil results and an error", got, err)
		}
	})

	t.Run("batch over limit", func(t *testing.T) {
		orig := maxBatchBodyBytes
		maxBatchBodyBytes = 1024
		t.Cleanup(func() { maxBatchBodyBytes = orig })
		body := `{"results": [{}]}` + strings.Repeat(" ", 1024)
		c, _ := newTestClient(t, route(raw(body), nil))
		got, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}})
		if err == nil || got != nil {
			t.Fatalf("got %v, %v; want nil results and an error", got, err)
		}
	})
}

func TestCheck_AC2_9_BodiesClosed(t *testing.T) {
	cases := []struct {
		name string
		h    http.Handler
	}{
		{"success", route(nil, nil)},
		{"vuln 404", route(nil, status(http.StatusNotFound))},
		{"batch 503 retried", route(status(http.StatusServiceUnavailable), nil)},
		{"vuln malformed", route(nil, raw(`{"id": `))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, tc.h)
			tr := &countingTransport{}
			c.httpClient.Transport = tr
			c.Check(context.Background(), []Package{{Name: "a", Version: "1.0.0"}, {Name: "b", Version: "1.0.0"}})
			if tr.opened.Load() == 0 || tr.opened.Load() != tr.closed.Load() {
				t.Fatalf("opened %d bodies, closed %d", tr.opened.Load(), tr.closed.Load())
			}
		})
	}
}

func TestCheck_AC2_10_TrailingSlash(t *testing.T) {
	f := &fakeOSV{pages: map[string][][]string{"lodash": {{"GHSA-a"}}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.EscapedPath(), "//") {
			http.Error(w, "double slash", http.StatusNotFound)
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL + "/")
	got, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if want := []string{"GHSA-a"}; !reflect.DeepEqual(ids(got[0]), want) {
		t.Fatalf("ids = %v, want %v", ids(got[0]), want)
	}
}

func failFirst(n int32, fail http.HandlerFunc, ok http.HandlerFunc, calls *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= n {
			fail(w, r)
			return
		}
		if ok == nil {
			return
		}
		ok(w, r)
	}
}

func retryAfter(code int, value string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", value)
		http.Error(w, "slow down", code)
	}
}

func hangUp(w http.ResponseWriter, r *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	conn.Close()
}

var okBatch = func(w http.ResponseWriter, r *http.Request) {
	route(nil, nil).ServeHTTP(w, r)
}

func TestCheck_AC2_11_Retry(t *testing.T) {
	okVuln := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"id": "GHSA-1"})
	}
	cases := []struct {
		name      string
		batch     func(calls *atomic.Int32) http.HandlerFunc
		vuln      func(calls *atomic.Int32) http.HandlerFunc
		wantErr   bool
		wantCalls int32
	}{
		{"batch 503 then ok", func(c *atomic.Int32) http.HandlerFunc { return failFirst(2, status(503), okBatch, c) }, nil, false, 3},
		{"batch 500 always", func(c *atomic.Int32) http.HandlerFunc { return failFirst(99, status(500), nil, c) }, nil, true, 3},
		{"batch 429 always", func(c *atomic.Int32) http.HandlerFunc { return failFirst(99, status(429), nil, c) }, nil, true, 3},
		{"batch 400 not retried", func(c *atomic.Int32) http.HandlerFunc { return failFirst(99, status(400), nil, c) }, nil, true, 1},
		{"batch malformed not retried", func(c *atomic.Int32) http.HandlerFunc { return failFirst(99, raw(`{`), nil, c) }, nil, true, 1},
		{"batch connection reset then ok", func(c *atomic.Int32) http.HandlerFunc { return failFirst(1, hangUp, okBatch, c) }, nil, false, 2},
		{"vuln 502 then ok", nil, func(c *atomic.Int32) http.HandlerFunc { return failFirst(1, status(502), okVuln, c) }, false, 2},
		{"vuln 404 not retried", nil, func(c *atomic.Int32) http.HandlerFunc { return failFirst(99, status(404), nil, c) }, true, 1},
		{"vuln connection reset then ok", nil, func(c *atomic.Int32) http.HandlerFunc { return failFirst(2, hangUp, okVuln, c) }, false, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var batch, vuln http.HandlerFunc
			if tc.batch != nil {
				batch = tc.batch(&calls)
			}
			if tc.vuln != nil {
				vuln = tc.vuln(&calls)
			}
			c, _ := newTestClient(t, route(batch, vuln))
			got, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}})
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && got != nil {
				t.Fatalf("got partial results %+v", got)
			}
			if !tc.wantErr && (len(got) != 1 || len(got[0].Vulns) != 1) {
				t.Fatalf("got %+v, want one result with one vuln", got)
			}
			if calls.Load() != tc.wantCalls {
				t.Fatalf("attempts = %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestCheck_AC2_11_OversizedNotRetried(t *testing.T) {
	orig := maxVulnBodyBytes
	maxVulnBodyBytes = 64
	t.Cleanup(func() { maxVulnBodyBytes = orig })
	var calls atomic.Int32
	big := `{"id":"GHSA-1","summary":"` + strings.Repeat("a", 128) + `"}`
	c, _ := newTestClient(t, route(nil, failFirst(99, raw(big), nil, &calls)))
	if _, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}}); err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", calls.Load())
	}
}

func TestCheck_AC2_11_Backoff(t *testing.T) {
	var calls atomic.Int32
	c, log := newTestClient(t, route(failFirst(2, status(503), okBatch, &calls), nil))
	if _, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	delays := log.get()
	if len(delays) != 2 {
		t.Fatalf("delays = %v, want 2", delays)
	}
	if delays[0] < 0 || delays[0] > 500*time.Millisecond {
		t.Errorf("first delay = %s, want within [0, 500ms]", delays[0])
	}
	if delays[1] < 0 || delays[1] > time.Second {
		t.Errorf("second delay = %s, want within [0, 1s]", delays[1])
	}
}

func TestCheck_AC2_11_RetryAfter(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"3", 3 * time.Second},
		{"60", 10 * time.Second},
		{"0", 0},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			var calls atomic.Int32
			c, log := newTestClient(t, route(failFirst(1, retryAfter(429, tc.header), okBatch, &calls), nil))
			if _, err := c.Check(context.Background(), []Package{{Name: "lodash", Version: "4.17.15"}}); err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got := log.get(); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("delays = %v, want [%s]", got, tc.want)
			}
		})
	}
}
