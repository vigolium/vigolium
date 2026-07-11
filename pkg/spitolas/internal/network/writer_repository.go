package network

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"go.uber.org/zap"
)

// RecordSaver persists HTTP request/response pairs to a database.
// Matches the interface used by DeparosDiscoverySource in pkg/input/source/deparos_discovery.go.
type RecordSaver interface {
	SaveRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error)
	SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error)
}

const (
	// writerQueueSize buffers converted records between the CDP capture callback
	// and the batch-flush goroutine so a burst of captures is never blocked on the
	// database. Sized generously — the flush goroutine drains it via SaveRecordBatch
	// far faster than the browser produces records, so it only backpressures under
	// genuine DB saturation (the correct behavior).
	writerQueueSize = 512
	// writerBatchSize flushes once this many records accumulate, so a busy crawl
	// coalesces records into one SaveRecordBatch instead of paying the underlying
	// writer's per-record flush wait (the "Write-in-a-loop" trap).
	writerBatchSize = 64
	// writerFlushInterval bounds how long a partial batch waits before flushing, so
	// a trickle of records still lands promptly.
	writerFlushInterval = 100 * time.Millisecond
)

// writeItem is one converted record queued for batched persistence, carrying the
// original entry so spec ingestion can inspect the response body after the record
// is saved.
type writeItem struct {
	rr    *httpmsg.HttpRequestResponse
	entry *TrafficEntry
}

// RepositoryWriter implements the Writer interface by converting TrafficEntry
// to httpmsg.HttpRequestResponse and saving via vigolium's database.Repository.
//
// Writes are asynchronous: Write converts the entry (cheap, CPU-only) and hands
// it to a background flush goroutine that coalesces records into SaveRecordBatch
// calls. This keeps the CDP capture callback — which holds the capture mutex —
// off the blocking database path entirely, so capture no longer serializes one
// DB write at a time (the old SaveRecord-per-record path paid a per-record flush
// wait AND stalled the whole capture pipeline behind each write).
type RepositoryWriter struct {
	repo        RecordSaver
	source      string
	projectUUID string
	ScopeFilter func(host, path string) bool

	mu    sync.Mutex
	count int
	// specSeen tracks already-parsed spec content hashes to avoid re-parsing.
	specSeen map[string]struct{}

	queue     chan writeItem
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewRepositoryWriter creates a Writer that stores traffic in vigolium's HTTPRecord table.
func NewRepositoryWriter(repo RecordSaver, source string, projectUUID string) *RepositoryWriter {
	w := &RepositoryWriter{
		repo:        repo,
		source:      source,
		projectUUID: projectUUID,
		specSeen:    make(map[string]struct{}),
		queue:       make(chan writeItem, writerQueueSize),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go w.flushLoop()
	return w
}

// Write converts a TrafficEntry to HttpRequestResponse and enqueues it for batched
// persistence. It blocks only when the queue is full (natural backpressure) or
// returns immediately if the writer has been closed.
func (w *RepositoryWriter) Write(entry *TrafficEntry) error {
	if w.ScopeFilter != nil {
		u, parseErr := url.Parse(entry.Request.URL)
		if parseErr == nil {
			if !w.ScopeFilter(u.Hostname(), u.Path) {
				zap.L().Debug("Skipping out-of-scope spidering record",
					zap.String("url", entry.Request.URL))
				return nil
			}
		}
	}

	httpRR, err := ToHttpRequestResponse(entry)
	if err != nil {
		zap.L().Debug("Failed to convert TrafficEntry to HttpRequestResponse",
			zap.String("url", entry.Request.URL),
			zap.Error(err))
		return err
	}

	select {
	case w.queue <- writeItem{rr: httpRR, entry: entry}:
	case <-w.stop:
		// Writer closed — drop late CDP events rather than blocking forever. This
		// mirrors the capture's own post-Close drop of late Loading events.
	}
	return nil
}

// flushLoop drains the write queue, coalescing records into SaveRecordBatch calls
// on size or a short interval, and runs spec ingestion after each batch lands. It
// exits after Close signals stop and the queue is drained, flushing what remains.
func (w *RepositoryWriter) flushLoop() {
	defer close(w.done)

	ticker := time.NewTicker(writerFlushInterval)
	defer ticker.Stop()

	pending := make([]writeItem, 0, writerBatchSize)

	flush := func() {
		if len(pending) == 0 {
			return
		}
		records := make([]*httpmsg.HttpRequestResponse, len(pending))
		for i, it := range pending {
			records[i] = it.rr
		}
		ids, err := w.repo.SaveRecordBatch(context.Background(), records, w.source, w.projectUUID)
		if err != nil {
			zap.L().Debug("Failed to save spidering record batch",
				zap.Int("count", len(records)), zap.Error(err))
		} else {
			w.mu.Lock()
			w.count += len(ids)
			w.mu.Unlock()
		}
		// Detect and parse API specs (OpenAPI/Swagger/Postman) from spidered
		// responses after the batch is persisted. Cheap to reject for non-specs.
		for _, it := range pending {
			w.ingestSpecEndpoints(it.entry, it.rr)
		}
		pending = pending[:0]
	}

	for {
		select {
		case it := <-w.queue:
			pending = append(pending, it)
			if len(pending) >= writerBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stop:
			// Drain whatever is still buffered without blocking, then flush and exit.
			for {
				select {
				case it := <-w.queue:
					pending = append(pending, it)
				default:
					flush()
					return
				}
			}
		}
	}
}

// ingestSpecEndpoints checks if a spidered response contains an API spec
// and saves the extracted endpoints as additional http_records.
func (w *RepositoryWriter) ingestSpecEndpoints(entry *TrafficEntry, httpRR *httpmsg.HttpRequestResponse) {
	if entry.Response == nil || entry.Response.Status < 200 || entry.Response.Status >= 300 {
		return
	}

	body := entry.Response.Body
	if len(body) < specutil.MinSpecBodySize || len(body) > specutil.MaxSpecBodySize {
		return
	}

	// Quick content-type check
	ct := strings.ToLower(entry.ContentType)
	if !specutil.IsSpecContentType(ct) {
		return
	}

	// Detect spec type
	st := specutil.DetectSpecType(body)
	if st == specutil.Unknown {
		return
	}

	// Content dedup
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	w.mu.Lock()
	if _, seen := w.specSeen[hash]; seen {
		w.mu.Unlock()
		return
	}
	w.specSeen[hash] = struct{}{}
	w.mu.Unlock()

	// Derive base URL
	baseURL := ""
	if httpRR.Service() != nil {
		baseURL = httpRR.Service().Protocol() + "://" + httpRR.Service().Host()
	}

	endpoints, err := specutil.ParseSpecTyped(st, body, baseURL, httpRR.Service())
	if err != nil {
		zap.L().Debug("Failed to parse API spec from spidered response",
			zap.String("url", entry.Request.URL),
			zap.Error(err))
		return
	}

	if len(endpoints) == 0 {
		return
	}

	// Batch save parsed endpoints
	_, saveErr := w.repo.SaveRecordBatch(context.Background(), endpoints, "spec-ingest", w.projectUUID)
	if saveErr != nil {
		zap.L().Debug("Failed to save spec-ingested endpoints",
			zap.String("source_url", entry.Request.URL),
			zap.Error(saveErr))
		return
	}

	w.mu.Lock()
	w.count += len(endpoints)
	w.mu.Unlock()

	zap.L().Info("Ingested API spec endpoints from spidered response",
		zap.String("source_url", entry.Request.URL),
		zap.Int("endpoints", len(endpoints)))
}

// Close signals the flush goroutine to drain and persist any buffered records,
// then blocks until it has finished so Count() reflects everything saved. Safe to
// call more than once.
func (w *RepositoryWriter) Close() error {
	w.closeOnce.Do(func() { close(w.stop) })
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	zap.L().Debug("RepositoryWriter closed",
		zap.Int("records_saved", w.count),
		zap.String("source", w.source))
	return nil
}

// Count returns the number of records saved so far.
func (w *RepositoryWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
