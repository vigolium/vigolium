//go:build memoryleak

package discovery

import (
	"context"
	"fmt"
	"hash/fnv"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// =============================================================================
// MEMORY LEAK TEST CONFIGURATION
// =============================================================================

// MemoryLeakTestConfig defines parameters for memory leak tests.
type MemoryLeakTestConfig struct {
	// Scale parameters
	EndpointCount  int   // Number of valid endpoints in mock server
	MaxDepth       int   // Maximum directory depth
	TargetRequests int64 // Target number of requests before test ends
	WorkerCount    int   // Number of discovery workers

	// Timing
	WarmupDuration time.Duration // Warm-up period before measuring
	SampleInterval time.Duration // Memory sampling interval
	MaxDuration    time.Duration // Maximum test duration

	// Memory thresholds
	MaxHeapGrowthMB       int64   // Maximum heap growth in MB
	MaxBytesPerRequest    float64 // Maximum bytes allocated per request
	MaxGoroutineGrowth    int     // Maximum goroutine count increase
	MaxGrowthRateKBPerSec float64 // Maximum heap growth rate in KB/sec

	// Behavior
	StopOnThresholdBreach bool // Stop test early if threshold breached
}

// DefaultFullScaleConfig is the configuration for full-scale 30M request tests.
var DefaultFullScaleConfig = MemoryLeakTestConfig{
	EndpointCount:         2000,
	MaxDepth:              16,
	TargetRequests:        30_000_000,
	WorkerCount:           80,
	WarmupDuration:        2 * time.Minute,
	SampleInterval:        30 * time.Second,
	MaxDuration:           60 * time.Minute,
	MaxHeapGrowthMB:       500,
	MaxBytesPerRequest:    100.0,
	MaxGoroutineGrowth:    50,
	MaxGrowthRateKBPerSec: 10.0,
	StopOnThresholdBreach: false,
}

// QuickCheckConfig is the configuration for quick validation tests (~2-3 min).
var QuickCheckConfig = MemoryLeakTestConfig{
	EndpointCount:         200,
	MaxDepth:              8,
	TargetRequests:        100_000,
	WorkerCount:           40,
	WarmupDuration:        10 * time.Second,
	SampleInterval:        5 * time.Second,
	MaxDuration:           3 * time.Minute,
	MaxHeapGrowthMB:       100,
	MaxBytesPerRequest:    150.0,
	MaxGoroutineGrowth:    30,
	MaxGrowthRateKBPerSec: 50.0,
	StopOnThresholdBreach: true,
}

// =============================================================================
// MOCK DISCOVERY SERVER
// =============================================================================

// EndpointSpec defines a single endpoint's response behavior.
type EndpointSpec struct {
	Path        string
	StatusCode  int
	ContentType string
	Body        []byte
}

// MockDiscoveryServer simulates a web server with scattered endpoints.
type MockDiscoveryServer struct {
	server       *httptest.Server
	endpoints    map[string]*EndpointSpec
	directories  map[string]bool
	requestCount atomic.Uint64

	// Metrics
	dirRedirects   atomic.Uint64
	validResponses atomic.Uint64
	notFounds      atomic.Uint64
}

// NewMockDiscoveryServer creates a mock server with the specified number of endpoints.
func NewMockDiscoveryServer(endpointCount, maxDepth int) *MockDiscoveryServer {
	mock := &MockDiscoveryServer{
		endpoints:   make(map[string]*EndpointSpec),
		directories: make(map[string]bool),
	}

	mock.generateEndpointTree(endpointCount, maxDepth)
	mock.server = httptest.NewServer(http.HandlerFunc(mock.ServeHTTP))

	return mock
}

// generateEndpointTree creates a directory structure with scattered endpoints.
func (m *MockDiscoveryServer) generateEndpointTree(count, maxDepth int) {
	// Base directories at various depths
	baseDirs := []string{
		"/api", "/api/v1", "/api/v2", "/api/v1/users", "/api/v1/posts",
		"/admin", "/admin/users", "/admin/settings", "/admin/logs",
		"/static", "/static/js", "/static/css", "/static/images",
		"/uploads", "/uploads/files", "/uploads/images", "/uploads/docs",
		"/docs", "/docs/api", "/docs/guides", "/docs/tutorials",
		"/internal", "/internal/tools", "/internal/reports",
		"/data", "/data/exports", "/data/imports", "/data/backups",
	}

	// Generate deep nested paths up to maxDepth
	deepPaths := m.generateDeepPaths(maxDepth)
	allDirs := append(baseDirs, deepPaths...)

	// Mark all directories
	for _, dir := range allDirs {
		m.directories[dir+"/"] = true
		// Also mark all parent directories
		parts := strings.Split(strings.Trim(dir, "/"), "/")
		for i := 1; i <= len(parts); i++ {
			parentDir := "/" + strings.Join(parts[:i], "/") + "/"
			m.directories[parentDir] = true
		}
	}
	m.directories["/"] = true

	// Filenames to use
	filenames := []string{
		"index", "config", "settings", "admin", "users",
		"login", "logout", "register", "profile", "dashboard",
		"data", "export", "import", "backup", "restore",
		"list", "view", "edit", "delete", "create",
		"search", "filter", "sort", "page", "details",
		"api", "handler", "controller", "service", "model",
	}

	extensions := []string{"", ".php", ".html", ".json", ".xml", ".txt", ".jsp", ".asp"}

	// Distribute endpoints across directories
	endpointIdx := 0
	for endpointIdx < count {
		for _, dir := range allDirs {
			if endpointIdx >= count {
				break
			}

			// Add 1-3 endpoints per directory
			numEndpoints := 1 + (endpointIdx % 3)
			for j := 0; j < numEndpoints && endpointIdx < count; j++ {
				filename := filenames[(endpointIdx+j)%len(filenames)]
				ext := extensions[(endpointIdx+j)%len(extensions)]
				path := dir + "/" + filename + ext

				// Skip if already exists
				if _, exists := m.endpoints[path]; exists {
					continue
				}

				m.endpoints[path] = &EndpointSpec{
					Path:        path,
					StatusCode:  http.StatusOK,
					ContentType: contentTypeForExt(ext),
					Body:        m.generateContent(path),
				}
				endpointIdx++
			}
		}
	}
}

// generateDeepPaths creates paths with increasing depth up to maxDepth.
func (m *MockDiscoveryServer) generateDeepPaths(maxDepth int) []string {
	var paths []string
	segments := []string{"level", "deep", "nested", "sub", "inner", "layer", "node", "branch"}

	// Generate multiple paths at each depth level
	for depth := 5; depth <= maxDepth; depth++ {
		// Create several variations at each depth
		for variation := 0; variation < 3; variation++ {
			var pathParts []string
			for i := 0; i < depth; i++ {
				seg := segments[(i+variation)%len(segments)]
				pathParts = append(pathParts, fmt.Sprintf("%s%d", seg, i))
			}
			paths = append(paths, "/"+strings.Join(pathParts, "/"))
		}
	}

	return paths
}

// generateContent creates unique content for an endpoint.
func (m *MockDiscoveryServer) generateContent(path string) []byte {
	h := fnv.New64a()
	h.Write([]byte(path))
	hash := h.Sum64()

	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%s</title></head>
<body>
<h1>Resource: %s</h1>
<p>Hash: %016x</p>
<div id="content-%016x">
<p>This is unique content for path: %s</p>
<ul>
<li>Item 1</li>
<li>Item 2</li>
<li>Item 3</li>
</ul>
</div>
<footer>Generated content</footer>
</body>
</html>`, path, path, hash, hash, path))
}

// ServeHTTP handles HTTP requests to the mock server.
func (m *MockDiscoveryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.requestCount.Add(1)
	path := r.URL.Path

	// Check if path is a directory without trailing slash - redirect to with slash
	if !strings.HasSuffix(path, "/") {
		if m.directories[path+"/"] {
			m.dirRedirects.Add(1)
			w.Header().Set("Location", path+"/")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
	}

	// Check if endpoint exists
	if spec, exists := m.endpoints[path]; exists {
		m.validResponses.Add(1)
		w.Header().Set("Content-Type", spec.ContentType)
		w.WriteHeader(spec.StatusCode)
		_, _ = w.Write(spec.Body)
		return
	}

	// Check if it's a valid directory (return directory listing)
	if m.directories[path] {
		m.validResponses.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Index of %s</title></head>
<body>
<h1>Index of %s</h1>
<ul>
<li><a href="../">Parent Directory</a></li>
<li><a href="index.html">index.html</a></li>
<li><a href="config.php">config.php</a></li>
</ul>
</body>
</html>`, path, path)))
		return
	}

	// Return 404 for non-existent paths
	m.notFounds.Add(1)
	m.return404(w, path)
}

// return404 sends a consistent 404 response for fingerprint learning.
func (m *MockDiscoveryServer) return404(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL %s was not found on this server.</p>
</body>
</html>`, html.EscapeString(path))))
}

// URL returns the server's base URL.
func (m *MockDiscoveryServer) URL() string {
	return m.server.URL
}

// Close shuts down the mock server.
func (m *MockDiscoveryServer) Close() {
	m.server.Close()
}

// GetMetrics returns server metrics.
func (m *MockDiscoveryServer) GetMetrics() (requests, redirects, valid, notFound uint64) {
	return m.requestCount.Load(), m.dirRedirects.Load(), m.validResponses.Load(), m.notFounds.Load()
}

// contentTypeForExt returns the appropriate content type for a file extension.
func contentTypeForExt(ext string) string {
	switch ext {
	case ".html", ".htm", "":
		return "text/html"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".txt":
		return "text/plain"
	case ".php", ".jsp", ".asp":
		return "text/html"
	default:
		return "text/html"
	}
}

// =============================================================================
// MEMORY TRACKING UTILITIES
// =============================================================================

// ExtendedMemStats captures comprehensive memory state.
type ExtendedMemStats struct {
	HeapAlloc    uint64
	HeapInuse    uint64
	HeapIdle     uint64
	HeapReleased uint64
	HeapObjects  uint64
	StackInuse   uint64
	NumGC        uint32
	NumGoroutine int
	RequestCount uint64
	Timestamp    time.Time
}

// captureExtendedMemStats reads current memory statistics.
func captureExtendedMemStats(requestCount uint64) ExtendedMemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return ExtendedMemStats{
		HeapAlloc:    m.HeapAlloc,
		HeapInuse:    m.HeapInuse,
		HeapIdle:     m.HeapIdle,
		HeapReleased: m.HeapReleased,
		HeapObjects:  m.HeapObjects,
		StackInuse:   m.StackInuse,
		NumGC:        m.NumGC,
		NumGoroutine: runtime.NumGoroutine(),
		RequestCount: requestCount,
		Timestamp:    time.Now(),
	}
}

// String returns a formatted string representation.
func (s ExtendedMemStats) String() string {
	return fmt.Sprintf("HeapAlloc=%s HeapInuse=%s Objects=%d Goroutines=%d GCs=%d",
		formatBytesLeak(s.HeapAlloc),
		formatBytesLeak(s.HeapInuse),
		s.HeapObjects,
		s.NumGoroutine,
		s.NumGC)
}

// formatBytesLeak formats bytes as human-readable string.
func formatBytesLeak(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// MemoryTrendAnalyzer tracks and analyzes memory usage patterns.
type MemoryTrendAnalyzer struct {
	samples  []ExtendedMemStats
	baseline ExtendedMemStats
	mu       sync.Mutex
}

// NewMemoryTrendAnalyzer creates a new analyzer.
func NewMemoryTrendAnalyzer() *MemoryTrendAnalyzer {
	return &MemoryTrendAnalyzer{
		samples: make([]ExtendedMemStats, 0, 1000),
	}
}

// SetBaseline sets the baseline memory state.
func (a *MemoryTrendAnalyzer) SetBaseline(s ExtendedMemStats) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.baseline = s
}

// AddSample adds a memory sample.
func (a *MemoryTrendAnalyzer) AddSample(s ExtendedMemStats) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.samples = append(a.samples, s)
}

// CalculateGrowthRate returns heap growth in bytes per second.
func (a *MemoryTrendAnalyzer) CalculateGrowthRate() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.samples) < 2 {
		return 0
	}

	first := a.samples[0]
	last := a.samples[len(a.samples)-1]

	heapGrowth := float64(last.HeapAlloc) - float64(first.HeapAlloc)
	duration := last.Timestamp.Sub(first.Timestamp).Seconds()

	if duration <= 0 {
		return 0
	}
	return heapGrowth / duration
}

// CalculateBytesPerRequest returns average bytes allocated per request.
func (a *MemoryTrendAnalyzer) CalculateBytesPerRequest() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.samples) < 2 {
		return 0
	}

	first := a.samples[0]
	last := a.samples[len(a.samples)-1]

	heapGrowth := float64(last.HeapAlloc) - float64(first.HeapAlloc)
	requestDelta := float64(last.RequestCount - first.RequestCount)

	if requestDelta <= 0 {
		return 0
	}
	return heapGrowth / requestDelta
}

// GetHeapGrowth returns total heap growth from baseline.
func (a *MemoryTrendAnalyzer) GetHeapGrowth() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.samples) == 0 {
		return 0
	}
	return int64(a.samples[len(a.samples)-1].HeapAlloc) - int64(a.baseline.HeapAlloc)
}

// GetGoroutineDelta returns goroutine count change from baseline.
func (a *MemoryTrendAnalyzer) GetGoroutineDelta() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.samples) == 0 {
		return 0
	}
	return a.samples[len(a.samples)-1].NumGoroutine - a.baseline.NumGoroutine
}

// DetectLeakPattern analyzes samples for monotonic growth pattern.
func (a *MemoryTrendAnalyzer) DetectLeakPattern() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.samples) < 10 {
		return false, "insufficient samples"
	}

	// Check if heap consistently grows across windows
	windowSize := len(a.samples) / 5
	if windowSize < 2 {
		windowSize = 2
	}

	var growthCount int
	numWindows := 0

	for i := windowSize; i < len(a.samples); i += windowSize {
		end := i + windowSize
		if end > len(a.samples) {
			end = len(a.samples)
		}

		prevWindow := a.samples[i-windowSize : i]
		currWindow := a.samples[i:end]

		prevAvg := avgHeapAlloc(prevWindow)
		currAvg := avgHeapAlloc(currWindow)

		numWindows++
		if currAvg > prevAvg*1.05 { // 5% growth threshold
			growthCount++
		}
	}

	// If 80%+ of windows show growth, likely leak
	if numWindows > 0 && float64(growthCount)/float64(numWindows) >= 0.8 {
		return true, fmt.Sprintf("consistent heap growth in %d/%d windows", growthCount, numWindows)
	}

	return false, "no consistent growth pattern"
}

// avgHeapAlloc calculates average heap allocation for samples.
func avgHeapAlloc(samples []ExtendedMemStats) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum uint64
	for _, s := range samples {
		sum += s.HeapAlloc
	}
	return float64(sum) / float64(len(samples))
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

// createTempWordlist creates a temporary wordlist file with test words.
func createTempWordlist(t *testing.T, words []string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "wordlist-*.txt")
	require.NoError(t, err)
	defer tmpFile.Close()

	for _, word := range words {
		_, err := tmpFile.WriteString(word + "\n")
		require.NoError(t, err)
	}

	return tmpFile.Name()
}

// runMemoryLeakTest executes the memory leak test with given configuration.
func runMemoryLeakTest(t *testing.T, cfg MemoryLeakTestConfig) {
	t.Helper()

	// ===== PHASE 1: SETUP =====
	t.Log("=== Phase 1: Setup & Baseline ===")

	// Force initial GC for clean baseline
	runtime.GC()
	debug.FreeOSMemory()
	time.Sleep(100 * time.Millisecond)

	// Create mock server with endpoints
	t.Logf("Creating mock server with %d endpoints, depth %d",
		cfg.EndpointCount, cfg.MaxDepth)
	mockServer := NewMockDiscoveryServer(cfg.EndpointCount, cfg.MaxDepth)
	defer mockServer.Close()

	t.Logf("Mock server started at %s", mockServer.URL())
	t.Logf("Endpoints: %d, Directories: %d", len(mockServer.endpoints), len(mockServer.directories))

	// Create temporary wordlists for discovery
	fileWords := []string{
		"index", "config", "settings", "admin", "users",
		"login", "logout", "register", "profile", "dashboard",
		"data", "export", "import", "backup", "restore",
		"list", "view", "edit", "delete", "create",
		"search", "filter", "sort", "page", "details",
		"api", "handler", "controller", "service", "model",
		"test", "debug", "status", "health", "info",
		"home", "main", "app", "core", "base",
	}
	dirWords := []string{
		"api", "v1", "v2", "admin", "users", "static",
		"js", "css", "images", "uploads", "docs",
		"internal", "data", "exports", "imports", "backups",
		"level", "deep", "nested", "sub", "inner",
	}

	shortFilePath := createTempWordlist(t, fileWords)
	defer os.Remove(shortFilePath)
	shortDirPath := createTempWordlist(t, dirWords)
	defer os.Remove(shortDirPath)

	// Create engine configuration
	engineCfg := &config.Config{
		Target: config.TargetConfig{
			StartURL: mockServer.URL() + "/",
			Mode:     config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{
				Enabled:  true,
				MaxDepth: int16(cfg.MaxDepth),
			},
		},
		Filenames: config.FilenameConfig{
			Wordlists: config.WordlistConfig{
				ShortFilePath: shortFilePath,
				ShortDirPath:  shortDirPath,
			},
			UseObservedNames: true,
			UseObservedPaths: true,
		},
		Extensions: config.ExtensionConfig{
			TestCustom:      true,
			CustomList:      []string{"php", "html", "json", "xml", "txt"},
			TestObserved:    true,
			TestNoExtension: true,
		},
		Engine: config.EngineConfig{
			CaseSensitivity:         config.CaseSensitive,
			DiscoveryThreads:        cfg.WorkerCount,
			Timeout:                 30 * time.Second,
			SkipFingerprintLearning: true, // Skip for faster test startup
			MaxConsecutiveErrors:    0,    // Disable for stress test
			ObservedMaxItems:        50000,
		},
	}

	// Create ephemeral storage for the test
	st, err := storage.NewSiteMap(storage.DefaultConfig())
	require.NoError(t, err)
	defer st.Close()

	engine, err := NewEngine(engineCfg, st)
	require.NoError(t, err)

	// Set learner delay to 0 for faster fingerprint learning
	engine.fpLearner.SetDelay(0)

	// Capture baseline memory
	runtime.GC()
	analyzer := NewMemoryTrendAnalyzer()
	baseline := captureExtendedMemStats(0)
	analyzer.SetBaseline(baseline)

	t.Logf("Baseline memory: %s", baseline)
	t.Logf("Baseline goroutines: %d", baseline.NumGoroutine)

	// ===== PHASE 2: WARM-UP =====
	t.Log("=== Phase 2: Warm-up ===")

	// Start engine
	require.NoError(t, engine.Start())

	// Run warm-up period to let system stabilize
	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), cfg.WarmupDuration)
	defer warmupCancel()

	warmupTicker := time.NewTicker(cfg.SampleInterval)
	defer warmupTicker.Stop()

	warmupStart := time.Now()

warmupLoop:
	for {
		select {
		case <-warmupCtx.Done():
			break warmupLoop
		case <-warmupTicker.C:
			metrics := engine.GetMetrics()
			sample := captureExtendedMemStats(metrics.RequestsSent)

			t.Logf("Warm-up progress: requests=%d, heap=%s, goroutines=%d",
				metrics.RequestsSent,
				formatBytesLeak(sample.HeapAlloc),
				sample.NumGoroutine)

			// Check if engine is idle (no more work)
			if engine.taskQueue.IsStopped() {
				t.Log("Engine queue stopped during warm-up")
				break warmupLoop
			}
		}
	}

	t.Logf("Warm-up complete in %v", time.Since(warmupStart))

	// Check if we have any requests
	warmupMetrics := engine.GetMetrics()
	if warmupMetrics.RequestsSent == 0 {
		t.Log("WARNING: No requests sent during warm-up")
	}

	// Reset baseline after warm-up for steady-state analysis
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	postWarmupBaseline := captureExtendedMemStats(warmupMetrics.RequestsSent)
	analyzer = NewMemoryTrendAnalyzer() // Reset analyzer
	analyzer.SetBaseline(postWarmupBaseline)
	analyzer.AddSample(postWarmupBaseline)

	t.Logf("Post-warmup baseline: %s", postWarmupBaseline)

	// ===== PHASE 3: STRESS TEST =====
	t.Log("=== Phase 3: Stress Test ===")

	stressCtx, stressCancel := context.WithTimeout(context.Background(), cfg.MaxDuration)
	defer stressCancel()

	sampleTicker := time.NewTicker(cfg.SampleInterval)
	defer sampleTicker.Stop()

	progressTicker := time.NewTicker(1 * time.Minute)
	defer progressTicker.Stop()

	stressStart := time.Now()
	var lastSampleRequestCount uint64   // For queue exhaustion detection
	var lastProgressRequestCount uint64 // For progress reporting
	idleCheckCount := 0

stressLoop:
	for {
		select {
		case <-stressCtx.Done():
			t.Log("Stress test reached max duration")
			break stressLoop

		case <-sampleTicker.C:
			metrics := engine.GetMetrics()
			sample := captureExtendedMemStats(metrics.RequestsSent)
			analyzer.AddSample(sample)

			// Check if target reached
			if metrics.RequestsSent >= uint64(cfg.TargetRequests) {
				t.Logf("Target request count reached: %d", metrics.RequestsSent)
				break stressLoop
			}

			// Check if engine is idle (no more work)
			if engine.taskQueue.IsStopped() {
				t.Log("Engine queue stopped during stress test")
				break stressLoop
			}

			// Check for queue exhaustion (discovery completed)
			// 2 consecutive samples with no new requests = discovery done
			if metrics.RequestsSent > 100 && metrics.RequestsSent == lastSampleRequestCount {
				idleCheckCount++
				if idleCheckCount >= 2 {
					coordMetrics := engine.coordinator.Metrics()
					if engine.taskQueue.Size() == 0 && coordMetrics.InFlightItems.Load() == 0 {
						t.Logf("Discovery completed - queue exhausted at %d requests", metrics.RequestsSent)
						break stressLoop
					}
				}
			} else {
				idleCheckCount = 0
			}
			lastSampleRequestCount = metrics.RequestsSent

			// Check threshold breaches
			if cfg.StopOnThresholdBreach {
				bytesPerReq := analyzer.CalculateBytesPerRequest()
				goroutineDelta := analyzer.GetGoroutineDelta()

				if bytesPerReq > cfg.MaxBytesPerRequest && metrics.RequestsSent > 10000 {
					t.Logf("WARNING: bytes/request threshold breach: %.2f > %.2f",
						bytesPerReq, cfg.MaxBytesPerRequest)
				}
				if goroutineDelta > cfg.MaxGoroutineGrowth {
					t.Logf("WARNING: goroutine growth threshold breach: %d > %d",
						goroutineDelta, cfg.MaxGoroutineGrowth)
				}
			}

		case <-progressTicker.C:
			metrics := engine.GetMetrics()
			sample := captureExtendedMemStats(metrics.RequestsSent)

			reqPerSec := float64(metrics.RequestsSent-lastProgressRequestCount) / 60.0
			lastProgressRequestCount = metrics.RequestsSent

			t.Logf("Progress: requests=%d (%.0f/sec), discovered=%d, heap=%s, goroutines=%d, GCs=%d",
				metrics.RequestsSent,
				reqPerSec,
				metrics.URLsDiscovered,
				formatBytesLeak(sample.HeapAlloc),
				sample.NumGoroutine,
				sample.NumGC)

			// Server metrics
			srvReqs, srvRedirects, srvValid, srvNotFound := mockServer.GetMetrics()
			t.Logf("Server: total=%d, redirects=%d, valid=%d, 404s=%d",
				srvReqs, srvRedirects, srvValid, srvNotFound)
		}
	}

	stressDuration := time.Since(stressStart)
	t.Logf("Stress test complete in %v", stressDuration)

	// ===== PHASE 4: ANALYSIS =====
	t.Log("=== Phase 4: Memory Analysis ===")

	// Stop engine
	engine.Stop()

	// Force final GC and wait for cleanup
	runtime.GC()
	debug.FreeOSMemory()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalMetrics := engine.GetMetrics()
	finalSample := captureExtendedMemStats(finalMetrics.RequestsSent)
	analyzer.AddSample(finalSample)

	// Calculate analysis metrics
	heapGrowth := int64(finalSample.HeapAlloc) - int64(postWarmupBaseline.HeapAlloc)
	heapGrowthMB := float64(heapGrowth) / (1024 * 1024)
	bytesPerRequest := analyzer.CalculateBytesPerRequest()
	growthRate := analyzer.CalculateGrowthRate()
	growthRateKB := growthRate / 1024
	goroutineDelta := analyzer.GetGoroutineDelta()

	isLeak, leakReason := analyzer.DetectLeakPattern()

	// Report results
	t.Log("=== RESULTS ===")
	t.Logf("Total Duration: %v", stressDuration)
	t.Logf("Total Requests: %d", finalMetrics.RequestsSent)
	if stressDuration.Seconds() > 0 {
		t.Logf("Requests/Second: %.2f", float64(finalMetrics.RequestsSent)/stressDuration.Seconds())
	}
	t.Logf("URLs Discovered: %d", finalMetrics.URLsDiscovered)
	t.Logf("Tasks Generated: %d", finalMetrics.TasksGenerated)
	t.Log("")
	t.Logf("Baseline Heap: %s", formatBytesLeak(postWarmupBaseline.HeapAlloc))
	t.Logf("Final Heap: %s", formatBytesLeak(finalSample.HeapAlloc))
	if heapGrowth > 0 {
		t.Logf("Heap Growth: %s (%.2f MB)", formatBytesLeak(uint64(heapGrowth)), heapGrowthMB)
	} else {
		t.Logf("Heap Growth: -%s (%.2f MB)", formatBytesLeak(uint64(-heapGrowth)), heapGrowthMB)
	}
	t.Logf("Heap Growth Rate: %.2f KB/sec", growthRateKB)
	t.Logf("Bytes per Request: %.2f", bytesPerRequest)
	t.Log("")
	t.Logf("Baseline Goroutines: %d", postWarmupBaseline.NumGoroutine)
	t.Logf("Final Goroutines: %d", finalSample.NumGoroutine)
	t.Logf("Goroutine Delta: %d", goroutineDelta)
	t.Log("")
	t.Logf("GC Cycles: %d", finalSample.NumGC-postWarmupBaseline.NumGC)
	t.Logf("Leak Pattern Detected: %v (%s)", isLeak, leakReason)

	// Server final metrics
	srvReqs, srvRedirects, srvValid, srvNotFound := mockServer.GetMetrics()
	t.Log("")
	t.Log("=== SERVER METRICS ===")
	t.Logf("Total Requests: %d", srvReqs)
	t.Logf("Directory Redirects: %d", srvRedirects)
	t.Logf("Valid Responses: %d", srvValid)
	t.Logf("404 Responses: %d", srvNotFound)

	// Assertions
	t.Log("")
	t.Log("=== ASSERTIONS ===")

	// Only check thresholds if we had meaningful traffic
	if finalMetrics.RequestsSent < 1000 {
		t.Log("SKIP: Insufficient requests for meaningful analysis")
		return
	}

	// Memory assertions
	if heapGrowthMB > float64(cfg.MaxHeapGrowthMB) {
		t.Errorf("FAIL: Heap growth %.2f MB exceeds threshold %d MB",
			heapGrowthMB, cfg.MaxHeapGrowthMB)
	} else {
		t.Logf("PASS: Heap growth %.2f MB within threshold %d MB",
			heapGrowthMB, cfg.MaxHeapGrowthMB)
	}

	if bytesPerRequest > cfg.MaxBytesPerRequest && bytesPerRequest > 0 {
		t.Errorf("FAIL: Bytes/request %.2f exceeds threshold %.2f",
			bytesPerRequest, cfg.MaxBytesPerRequest)
	} else {
		t.Logf("PASS: Bytes/request %.2f within threshold %.2f",
			bytesPerRequest, cfg.MaxBytesPerRequest)
	}

	if growthRateKB > cfg.MaxGrowthRateKBPerSec && growthRateKB > 0 {
		t.Errorf("FAIL: Growth rate %.2f KB/sec exceeds threshold %.2f KB/sec",
			growthRateKB, cfg.MaxGrowthRateKBPerSec)
	} else {
		t.Logf("PASS: Growth rate %.2f KB/sec within threshold %.2f KB/sec",
			growthRateKB, cfg.MaxGrowthRateKBPerSec)
	}

	if goroutineDelta > cfg.MaxGoroutineGrowth {
		t.Errorf("FAIL: Goroutine growth %d exceeds threshold %d",
			goroutineDelta, cfg.MaxGoroutineGrowth)
	} else {
		t.Logf("PASS: Goroutine growth %d within threshold %d",
			goroutineDelta, cfg.MaxGoroutineGrowth)
	}

	if isLeak {
		t.Errorf("FAIL: Memory leak pattern detected - %s", leakReason)
	} else {
		t.Logf("PASS: No memory leak pattern detected")
	}
}

// =============================================================================
// TEST FUNCTIONS
// =============================================================================

// TestMemoryLeak_DiscoveryEngine_FullScale is the comprehensive memory leak test.
// Scale: 2000 endpoints, 30M requests target, depth 16 recursion.
// Duration: ~30-60 minutes depending on hardware.
func TestMemoryLeak_DiscoveryEngine_FullScale(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full-scale memory leak test in short mode")
	}

	if os.Getenv("SKIP_HEAVY_TESTS") == "1" {
		t.Skip("Skipping due to SKIP_HEAVY_TESTS=1")
	}

	runMemoryLeakTest(t, DefaultFullScaleConfig)
}

// TestMemoryLeak_DiscoveryEngine_QuickCheck is a shorter validation test.
// Scale: 200 endpoints, 1M requests, depth 8 recursion.
// Duration: ~5 minutes.
func TestMemoryLeak_DiscoveryEngine_QuickCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	runMemoryLeakTest(t, QuickCheckConfig)
}

// TestMemoryLeak_DiscoveryEngine_GoroutineStability tests goroutine lifecycle.
// Verifies no goroutine leaks during start/stop cycles.
func TestMemoryLeak_DiscoveryEngine_GoroutineStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping goroutine stability test in short mode")
	}

	// Warm up runtime
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	const iterations = 10

	for i := 0; i < iterations; i++ {
		// Create mock server
		mockServer := NewMockDiscoveryServer(100, 4)

		// Create ephemeral storage
		st, err := storage.NewSiteMap(storage.DefaultConfig())
		require.NoError(t, err)

		// Create engine
		cfg := &config.Config{
			Target: config.TargetConfig{
				StartURL: mockServer.URL() + "/",
				Mode:     config.ModeFilesAndDirs,
				Recursion: config.RecursionConfig{
					Enabled:  true,
					MaxDepth: 4,
				},
			},
			Filenames: config.FilenameConfig{
				UseObservedNames: true,
			},
			Extensions: config.ExtensionConfig{
				TestCustom:      true,
				CustomList:      []string{"php"},
				TestNoExtension: true,
			},
			Engine: config.EngineConfig{
				DiscoveryThreads:        10,
				Timeout:                 10 * time.Second,
				SkipFingerprintLearning: true,
			},
		}

		engine, err := NewEngine(cfg, st)
		require.NoError(t, err)

		// Start and run briefly
		require.NoError(t, engine.Start())
		time.Sleep(500 * time.Millisecond)

		// Stop and cleanup
		engine.Stop()
		st.Close()
		mockServer.Close()

		// Check goroutines periodically
		if (i+1)%5 == 0 {
			runtime.GC()
			time.Sleep(100 * time.Millisecond)
			currentGoroutines := runtime.NumGoroutine()
			delta := currentGoroutines - baselineGoroutines
			t.Logf("Iteration %d: goroutines=%d (delta=%d)", i+1, currentGoroutines, delta)
		}
	}

	// Final check
	time.Sleep(1 * time.Second)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDelta := finalGoroutines - baselineGoroutines

	t.Logf("Final goroutines: %d", finalGoroutines)
	t.Logf("Goroutine delta: %d", goroutineDelta)

	// Allow some growth but catch severe leaks
	maxAllowedGrowth := 20
	if goroutineDelta > maxAllowedGrowth {
		t.Errorf("Potential goroutine leak: grew by %d (max allowed: %d)", goroutineDelta, maxAllowedGrowth)
	} else {
		t.Logf("PASS: Goroutine count stable (delta=%d, max=%d)", goroutineDelta, maxAllowedGrowth)
	}
}

// TestMockDiscoveryServer_RedirectBehavior verifies redirect handling.
func TestMockDiscoveryServer_RedirectBehavior(t *testing.T) {
	mockServer := NewMockDiscoveryServer(100, 4)
	defer mockServer.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Test that /api redirects to /api/
	resp, err := client.Get(mockServer.URL() + "/api")
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("Expected 301, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/api/" {
		t.Errorf("Expected Location: /api/, got %s", location)
	}

	// Test that /api/ returns content
	resp2, err := client.Get(mockServer.URL() + "/api/")
	require.NoError(t, err)
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for /api/, got %d", resp2.StatusCode)
	}

	t.Log("PASS: Redirect behavior verified")
}

// TestMockDiscoveryServer_EndpointDistribution verifies endpoint generation.
func TestMockDiscoveryServer_EndpointDistribution(t *testing.T) {
	mockServer := NewMockDiscoveryServer(2000, 16)
	defer mockServer.Close()

	t.Logf("Generated %d endpoints", len(mockServer.endpoints))
	t.Logf("Generated %d directories", len(mockServer.directories))

	// Verify endpoint count
	if len(mockServer.endpoints) < 1800 { // Allow some tolerance
		t.Errorf("Expected ~2000 endpoints, got %d", len(mockServer.endpoints))
	}

	// Verify depth distribution
	depthCounts := make(map[int]int)
	for path := range mockServer.endpoints {
		depth := strings.Count(path, "/") - 1
		depthCounts[depth]++
	}

	t.Log("Endpoint distribution by depth:")
	for depth := 0; depth <= 16; depth++ {
		if count := depthCounts[depth]; count > 0 {
			t.Logf("  Depth %2d: %d endpoints", depth, count)
		}
	}

	// Verify we have endpoints at deep levels
	deepEndpoints := 0
	for depth := 10; depth <= 16; depth++ {
		deepEndpoints += depthCounts[depth]
	}
	if deepEndpoints == 0 {
		t.Error("No endpoints at depths 10-16")
	} else {
		t.Logf("PASS: %d endpoints at depths 10-16", deepEndpoints)
	}
}
