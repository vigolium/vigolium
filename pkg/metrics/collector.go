package metrics

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/prometheus/client_golang/prometheus"
)

// ScanStateProvider reports whether a scan is currently running.
type ScanStateProvider interface {
	IsScanRunning() bool
}

// CollectorConfig configures the custom Prometheus collector.
type CollectorConfig struct {
	Queue         queue.Queue       // may be nil
	DB            *database.DB      // may be nil
	ScanState     ScanStateProvider // may be nil
	StartTime     time.Time
	Version       string
	Commit        string
	DBCacheTTL    time.Duration // default 30s
}

// Collector is a custom prometheus.Collector that pulls from existing Vigolium
// data sources on each scrape.
type Collector struct {
	cfg CollectorConfig

	// Descriptors
	uptimeDesc           *prometheus.Desc
	infoDesc             *prometheus.Desc
	queueDepthDesc       *prometheus.Desc
	queueEnqueuedDesc    *prometheus.Desc
	queueDequeuedDesc    *prometheus.Desc
	queueCompletedDesc   *prometheus.Desc
	queueEnqErrDesc      *prometheus.Desc
	queueDeqErrDesc      *prometheus.Desc
	scanRunningDesc      *prometheus.Desc
	memoryLowDesc        *prometheus.Desc
	modulesRegisteredDesc *prometheus.Desc
	dbHTTPRecordsDesc    *prometheus.Desc
	dbFindingsDesc       *prometheus.Desc

	// DB cache
	dbCacheMu      sync.Mutex
	dbCacheExpiry  time.Time
	cachedRecords  float64
	cachedFindings map[string]float64
}

// NewCollector creates a Collector with the given configuration.
func NewCollector(cfg CollectorConfig) *Collector {
	if cfg.DBCacheTTL == 0 {
		cfg.DBCacheTTL = 30 * time.Second
	}
	if cfg.StartTime.IsZero() {
		cfg.StartTime = time.Now()
	}

	return &Collector{
		cfg: cfg,

		uptimeDesc: prometheus.NewDesc(
			"vigolium_server_uptime_seconds",
			"Time in seconds since the server started.",
			nil, nil,
		),
		infoDesc: prometheus.NewDesc(
			"vigolium_server_info",
			"Server build information.",
			[]string{"version", "commit", "go_version"}, nil,
		),
		queueDepthDesc: prometheus.NewDesc(
			"vigolium_queue_depth",
			"Current number of pending tasks in the queue.",
			nil, nil,
		),
		queueEnqueuedDesc: prometheus.NewDesc(
			"vigolium_queue_enqueued_total",
			"Total number of tasks enqueued.",
			nil, nil,
		),
		queueDequeuedDesc: prometheus.NewDesc(
			"vigolium_queue_dequeued_total",
			"Total number of tasks dequeued.",
			nil, nil,
		),
		queueCompletedDesc: prometheus.NewDesc(
			"vigolium_queue_completed_total",
			"Total number of tasks completed.",
			nil, nil,
		),
		queueEnqErrDesc: prometheus.NewDesc(
			"vigolium_queue_enqueue_errors_total",
			"Total number of enqueue failures.",
			nil, nil,
		),
		queueDeqErrDesc: prometheus.NewDesc(
			"vigolium_queue_dequeue_errors_total",
			"Total number of dequeue failures.",
			nil, nil,
		),
		scanRunningDesc: prometheus.NewDesc(
			"vigolium_scan_running",
			"Whether a scan is currently running (1=yes, 0=no).",
			nil, nil,
		),
		memoryLowDesc: prometheus.NewDesc(
			"vigolium_memory_low",
			"Whether memory pressure is detected (1=yes, 0=no).",
			nil, nil,
		),
		modulesRegisteredDesc: prometheus.NewDesc(
			"vigolium_modules_registered_total",
			"Number of registered scanner modules.",
			[]string{"type"}, nil,
		),
		dbHTTPRecordsDesc: prometheus.NewDesc(
			"vigolium_db_http_records_total",
			"Total HTTP records stored in the database.",
			nil, nil,
		),
		dbFindingsDesc: prometheus.NewDesc(
			"vigolium_db_findings_total",
			"Total findings stored in the database.",
			[]string{"severity"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.uptimeDesc
	ch <- c.infoDesc
	ch <- c.queueDepthDesc
	ch <- c.queueEnqueuedDesc
	ch <- c.queueDequeuedDesc
	ch <- c.queueCompletedDesc
	ch <- c.queueEnqErrDesc
	ch <- c.queueDeqErrDesc
	ch <- c.scanRunningDesc
	ch <- c.memoryLowDesc
	ch <- c.modulesRegisteredDesc
	ch <- c.dbHTTPRecordsDesc
	ch <- c.dbFindingsDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// Server uptime
	ch <- prometheus.MustNewConstMetric(
		c.uptimeDesc, prometheus.GaugeValue,
		time.Since(c.cfg.StartTime).Seconds(),
	)

	// Server info (constant 1 with labels)
	commit := c.cfg.Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	ch <- prometheus.MustNewConstMetric(
		c.infoDesc, prometheus.GaugeValue, 1,
		c.cfg.Version, commit, runtime.Version(),
	)

	// Queue metrics
	if c.cfg.Queue != nil {
		if m := c.cfg.Queue.Metrics(); m != nil {
			ch <- prometheus.MustNewConstMetric(c.queueDepthDesc, prometheus.GaugeValue, float64(m.Depth))
			ch <- prometheus.MustNewConstMetric(c.queueEnqueuedDesc, prometheus.CounterValue, float64(m.TotalEnqueued))
			ch <- prometheus.MustNewConstMetric(c.queueDequeuedDesc, prometheus.CounterValue, float64(m.TotalDequeued))
			ch <- prometheus.MustNewConstMetric(c.queueCompletedDesc, prometheus.CounterValue, float64(m.TotalCompleted))
			ch <- prometheus.MustNewConstMetric(c.queueEnqErrDesc, prometheus.CounterValue, float64(m.EnqueueErrors))
			ch <- prometheus.MustNewConstMetric(c.queueDeqErrDesc, prometheus.CounterValue, float64(m.DequeueErrors))
		}
	}

	// Scan state
	if c.cfg.ScanState != nil {
		val := 0.0
		if c.cfg.ScanState.IsScanRunning() {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.scanRunningDesc, prometheus.GaugeValue, val)
	}

	// Memory pressure
	val := 0.0
	if network.IsLowOnMemory() {
		val = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.memoryLowDesc, prometheus.GaugeValue, val)

	// Module counts
	ch <- prometheus.MustNewConstMetric(
		c.modulesRegisteredDesc, prometheus.GaugeValue,
		float64(modules.DefaultRegistry.ActiveModuleCount()),
		"active",
	)
	ch <- prometheus.MustNewConstMetric(
		c.modulesRegisteredDesc, prometheus.GaugeValue,
		float64(modules.DefaultRegistry.PassiveModuleCount()),
		"passive",
	)

	// Database metrics (cached)
	if c.cfg.DB != nil {
		c.collectDBMetrics(ch)
	}
}

// collectDBMetrics emits DB metrics, using a TTL cache to avoid expensive queries on every scrape.
func (c *Collector) collectDBMetrics(ch chan<- prometheus.Metric) {
	c.dbCacheMu.Lock()
	defer c.dbCacheMu.Unlock()

	if time.Now().Before(c.dbCacheExpiry) {
		// Serve from cache
		ch <- prometheus.MustNewConstMetric(c.dbHTTPRecordsDesc, prometheus.GaugeValue, c.cachedRecords)
		for sev, count := range c.cachedFindings {
			ch <- prometheus.MustNewConstMetric(c.dbFindingsDesc, prometheus.GaugeValue, count, sev)
		}
		return
	}

	// Refresh cache
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recordCount, err := c.cfg.DB.NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		// On error, serve stale data if available
		if c.cachedFindings != nil {
			ch <- prometheus.MustNewConstMetric(c.dbHTTPRecordsDesc, prometheus.GaugeValue, c.cachedRecords)
			for sev, count := range c.cachedFindings {
				ch <- prometheus.MustNewConstMetric(c.dbFindingsDesc, prometheus.GaugeValue, count, sev)
			}
		}
		return
	}

	severityCounts, err := database.CountFindingsBySeverity(ctx, c.cfg.DB, "")
	if err != nil {
		// Partial success: emit records, serve stale findings
		c.cachedRecords = float64(recordCount)
		ch <- prometheus.MustNewConstMetric(c.dbHTTPRecordsDesc, prometheus.GaugeValue, c.cachedRecords)
		if c.cachedFindings != nil {
			for sev, count := range c.cachedFindings {
				ch <- prometheus.MustNewConstMetric(c.dbFindingsDesc, prometheus.GaugeValue, count, sev)
			}
		}
		return
	}

	// Update cache
	c.cachedRecords = float64(recordCount)
	c.cachedFindings = make(map[string]float64, len(severityCounts))
	for sev, count := range severityCounts {
		c.cachedFindings[sev] = float64(count)
	}
	c.dbCacheExpiry = time.Now().Add(c.cfg.DBCacheTTL)

	// Emit
	ch <- prometheus.MustNewConstMetric(c.dbHTTPRecordsDesc, prometheus.GaugeValue, c.cachedRecords)
	for sev, count := range c.cachedFindings {
		ch <- prometheus.MustNewConstMetric(c.dbFindingsDesc, prometheus.GaugeValue, count, sev)
	}
}
