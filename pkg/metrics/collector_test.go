package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gatherMetrics(t *testing.T, c *Collector) map[string]*dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)

	result := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		result[mf.GetName()] = mf
	}
	return result
}

func TestCollector_NilDeps(t *testing.T) {
	// Collector should work gracefully with nil Queue, DB, and ScanState.
	c := NewCollector(CollectorConfig{
		StartTime: time.Now().Add(-10 * time.Second),
		Version:   "1.0.0-test",
		Commit:    "abc1234",
	})

	mfs := gatherMetrics(t, c)

	// Core server metrics should always be present
	assert.Contains(t, mfs, "vigolium_server_uptime_seconds")
	assert.Contains(t, mfs, "vigolium_server_info")
	assert.Contains(t, mfs, "vigolium_memory_low")
	assert.Contains(t, mfs, "vigolium_modules_registered_total")

	// Queue metrics should NOT be present when queue is nil
	assert.NotContains(t, mfs, "vigolium_queue_depth")
	assert.NotContains(t, mfs, "vigolium_queue_enqueued_total")

	// Scan running should NOT be present when ScanState is nil
	assert.NotContains(t, mfs, "vigolium_scan_running")

	// DB metrics should NOT be present when DB is nil
	assert.NotContains(t, mfs, "vigolium_db_http_records_total")
	assert.NotContains(t, mfs, "vigolium_db_findings_total")
}

func TestCollector_UptimeIncreases(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	c := NewCollector(CollectorConfig{
		StartTime: start,
		Version:   "1.0.0",
	})

	mfs := gatherMetrics(t, c)
	mf := mfs["vigolium_server_uptime_seconds"]
	require.NotNil(t, mf)

	val := mf.GetMetric()[0].GetGauge().GetValue()
	assert.Greater(t, val, 4.0, "uptime should be at least 4 seconds")
}

func TestCollector_ServerInfo(t *testing.T) {
	c := NewCollector(CollectorConfig{
		StartTime: time.Now(),
		Version:   "2.5.0",
		Commit:    "deadbeefcafe",
	})

	mfs := gatherMetrics(t, c)
	mf := mfs["vigolium_server_info"]
	require.NotNil(t, mf)

	m := mf.GetMetric()[0]
	assert.Equal(t, 1.0, m.GetGauge().GetValue())

	labels := make(map[string]string)
	for _, lp := range m.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}
	assert.Equal(t, "2.5.0", labels["version"])
	assert.Equal(t, "deadbee", labels["commit"], "commit should be truncated to 7 chars")
	assert.True(t, strings.HasPrefix(labels["go_version"], "go"), "go_version should start with 'go'")
}

type mockScanState struct {
	running bool
}

func (m *mockScanState) IsScanRunning() bool { return m.running }

func TestCollector_ScanRunning(t *testing.T) {
	state := &mockScanState{running: true}
	c := NewCollector(CollectorConfig{
		StartTime: time.Now(),
		ScanState: state,
	})

	mfs := gatherMetrics(t, c)
	mf := mfs["vigolium_scan_running"]
	require.NotNil(t, mf)
	assert.Equal(t, 1.0, mf.GetMetric()[0].GetGauge().GetValue())

	// Flip to not running
	state.running = false
	mfs = gatherMetrics(t, c)
	mf = mfs["vigolium_scan_running"]
	require.NotNil(t, mf)
	assert.Equal(t, 0.0, mf.GetMetric()[0].GetGauge().GetValue())
}

func TestCollector_MetricTypes(t *testing.T) {
	c := NewCollector(CollectorConfig{
		StartTime: time.Now(),
		Version:   "1.0.0",
	})

	mfs := gatherMetrics(t, c)

	// Verify gauge types
	for _, name := range []string{
		"vigolium_server_uptime_seconds",
		"vigolium_server_info",
		"vigolium_memory_low",
		"vigolium_modules_registered_total",
	} {
		mf, ok := mfs[name]
		require.True(t, ok, "metric %s should be present", name)
		assert.Equal(t, dto.MetricType_GAUGE, mf.GetType(), "metric %s should be a gauge", name)
	}
}

func TestCollector_DBCacheTTL(t *testing.T) {
	// Without a real DB, verify that the cache fields are properly initialized
	c := NewCollector(CollectorConfig{
		StartTime:  time.Now(),
		DBCacheTTL: 10 * time.Second,
	})
	assert.Equal(t, 10*time.Second, c.cfg.DBCacheTTL)

	// Default TTL
	c2 := NewCollector(CollectorConfig{
		StartTime: time.Now(),
	})
	assert.Equal(t, 30*time.Second, c2.cfg.DBCacheTTL)
}

func TestCollector_Describe(t *testing.T) {
	c := NewCollector(CollectorConfig{
		StartTime: time.Now(),
		Version:   "1.0.0",
	})

	ch := make(chan *prometheus.Desc, 20)
	c.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}

	// Should have exactly 13 descriptors
	assert.Len(t, descs, 13)
}
