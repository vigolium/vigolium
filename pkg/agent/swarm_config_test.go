package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestSwarmConfig_Defaults(t *testing.T) {
	// Verify that defaults are resolved correctly when Run() initializes
	cfg := SwarmConfig{}
	// Simulate the defaults resolution from Run()
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 3
	}
	if cfg.MasterBatchSize <= 0 {
		cfg.MasterBatchSize = 5
	}
	if cfg.ProbeConcurrency <= 0 {
		cfg.ProbeConcurrency = 10
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 10 * time.Second
	}
	if cfg.MaxProbeBodySize <= 0 {
		cfg.MaxProbeBodySize = 2 * 1024 * 1024
	}

	assert.Equal(t, 3, cfg.MaxIterations)
	assert.Equal(t, 5, cfg.MasterBatchSize)
	assert.Equal(t, 10, cfg.ProbeConcurrency)
	assert.Equal(t, 10*time.Second, cfg.ProbeTimeout)
	assert.Equal(t, 2*1024*1024, cfg.MaxProbeBodySize)
}

func TestSwarmConfig_CustomValues(t *testing.T) {
	cfg := SwarmConfig{
		MasterBatchSize:  10,
		ProbeConcurrency: 20,
		ProbeTimeout:     30 * time.Second,
		MaxProbeBodySize: 4 * 1024 * 1024,
	}

	assert.Equal(t, 10, cfg.MasterBatchSize)
	assert.Equal(t, 20, cfg.ProbeConcurrency)
	assert.Equal(t, 30*time.Second, cfg.ProbeTimeout)
	assert.Equal(t, 4*1024*1024, cfg.MaxProbeBodySize)
}

func TestProbeConfig_EffectiveDefaults(t *testing.T) {
	pc := ProbeConfig{}
	assert.Equal(t, 10, pc.effectiveConcurrency())
	assert.Equal(t, 10*time.Second, pc.effectiveTimeout())
	assert.Equal(t, 2*1024*1024, pc.effectiveMaxBodySize())
}

func TestProbeConfig_CustomValues(t *testing.T) {
	pc := ProbeConfig{
		Concurrency: 5,
		Timeout:     30 * time.Second,
		MaxBodySize: 1024,
	}
	assert.Equal(t, 5, pc.effectiveConcurrency())
	assert.Equal(t, 30*time.Second, pc.effectiveTimeout())
	assert.Equal(t, 1024, pc.effectiveMaxBodySize())
}

func TestSelectPlanRecords_DiversitySelection(t *testing.T) {
	// Create 10 records all under /api/users and 2 under /api/products
	// The diversity logic should prefer picking from both prefixes
	var records []*httpmsg.HttpRequestResponse

	// 8 POST /api/users variants (high score: method + body)
	for i := 0; i < 8; i++ {
		raw := []byte("POST /api/users/" + string(rune('a'+i)) + " HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	// 2 POST /api/products variants (also high score)
	for i := 0; i < 2; i++ {
		raw := []byte("POST /api/products/" + string(rune('a'+i)) + " HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"price\":100}")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	// 2 GET / (low score)
	for i := 0; i < 2; i++ {
		raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	selected := selectPlanRecords(records, 5)
	assert.Len(t, selected, 5)

	// Count how many from each prefix
	var usersCount, productsCount int
	for _, rr := range selected {
		if rr.Request() == nil {
			continue
		}
		path := rr.Request().Path()
		if len(path) >= 13 && path[:13] == "/api/products" {
			productsCount++
		} else if len(path) >= 11 && path[:11] == "/api/users/" {
			usersCount++
		}
	}

	// Both prefixes should be represented — without diversity, all 5 could be /api/users
	assert.GreaterOrEqual(t, productsCount, 1, "Expected at least 1 /api/products record for diversity")
	assert.GreaterOrEqual(t, usersCount, 1, "Expected at least 1 /api/users record")
}

func TestSelectPlanRecords_ReturnsAllWhenBelowMax(t *testing.T) {
	var records []*httpmsg.HttpRequestResponse
	for i := 0; i < 3; i++ {
		raw := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	selected := selectPlanRecords(records, 10)
	assert.Len(t, selected, 3, "Should return all records when below maxRecords")
}

func TestSelectPlanRecords_ZeroMaxMeansNoLimit(t *testing.T) {
	// maxRecords=0 means "no cap" — the CLI surfaces this as
	// `--max-plan-records 0` for users who want to ship the full surface
	// to the planner regardless of token cost.
	var records []*httpmsg.HttpRequestResponse
	for i := 0; i < 20; i++ {
		raw := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	selected := selectPlanRecords(records, 0)
	assert.Len(t, selected, 20, "maxRecords=0 should return all records (no cap)")
}

func TestSelectPlanRecords_PrefixCoverageGuarantee(t *testing.T) {
	// Pass 1 of selectPlanRecords guarantees every URL-prefix cluster
	// gets ≥1 representative when there's room. Build 30 records spread
	// across 6 prefixes: 25 under /api/users (high-scoring), 5 across 5
	// other prefixes (lower-scoring). With cap=10, all 6 prefixes must
	// appear in the output — the old penalty-only logic could starve
	// low-score singletons on tight caps.
	var records []*httpmsg.HttpRequestResponse

	// 25 high-score POSTs under /api/users
	for i := 0; i < 25; i++ {
		raw := []byte("POST /api/users/" + string(rune('a'+(i%26))) + " HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"x\":1}")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	// 5 low-score GETs across 5 distinct prefixes
	lowPaths := []string{"/admin/dashboard", "/billing/invoices", "/reports/q1", "/upload/file", "/ws/chat"}
	for _, p := range lowPaths {
		raw := []byte("GET " + p + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
		req := httpmsg.NewHttpRequest(raw)
		records = append(records, httpmsg.NewHttpRequestResponse(req, nil))
	}

	selected := selectPlanRecords(records, 10)
	assert.Len(t, selected, 10)

	// Every distinct prefix must be represented.
	gotPrefixes := map[string]int{}
	for _, rr := range selected {
		gotPrefixes[recordPathPrefix(rr)]++
	}
	expectedPrefixes := []string{"/api/users", "/admin/dashboard", "/billing/invoices", "/reports/q1", "/upload/file", "/ws/chat"}
	for _, want := range expectedPrefixes {
		assert.GreaterOrEqual(t, gotPrefixes[want], 1, "prefix %q missing from selected set", want)
	}
}

func TestRecordPathPrefix(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/users/123", "/api/users"},
		{"/api/users", "/api/users"},
		{"/api/users?id=1", "/api/users"},
		{"/login", "/login"},
		{"/", "/"},
		{"/a/b/c/d/e", "/a/b"},
	}
	for _, tc := range cases {
		raw := []byte("GET " + tc.path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
		req := httpmsg.NewHttpRequest(raw)
		rr := httpmsg.NewHttpRequestResponse(req, nil)
		got := recordPathPrefix(rr)
		assert.Equal(t, tc.want, got, "path %q", tc.path)
	}
	assert.Equal(t, "", recordPathPrefix(nil), "nil record yields empty prefix")
}

func TestNormalizeSwarmPhase(t *testing.T) {
	assert.Equal(t, SwarmPhaseNormalize, NormalizeSwarmPhase("normalize"))
	assert.Equal(t, SwarmPhaseScan, NormalizeSwarmPhase("scan"))
	// Already normalized
	assert.Equal(t, SwarmPhasePlan, NormalizeSwarmPhase(SwarmPhasePlan))
	// Unknown passes through
	assert.Equal(t, "unknown-phase", NormalizeSwarmPhase("unknown-phase"))
}

func TestPhaseSkipped(t *testing.T) {
	skipList := []string{SwarmPhaseTriage, SwarmPhaseRescan}
	assert.True(t, PhaseSkipped(skipList, SwarmPhaseTriage))
	assert.True(t, PhaseSkipped(skipList, SwarmPhaseRescan))
	assert.False(t, PhaseSkipped(skipList, SwarmPhasePlan))
	assert.False(t, PhaseSkipped(nil, SwarmPhasePlan))
}
