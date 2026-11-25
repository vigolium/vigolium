package network

import (
	"context"
	"crypto/sha256"
	"errors"
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

// Shutdown budgets. Variables rather than constants so lifecycle tests can shrink
// them and still exercise the real code path; nothing in production reassigns
// them.
//
// Worst-case Close latency is writerSaveTimeout (an in-flight batch) +
// writerDrainTimeout (the final drain), which stays under the runner's 90s
// spideringTeardownGrace watchdog with room to spare. Raising either without
// checking that relationship turns a counted, reported loss into an abandoned
// teardown.
var (
	// writerSaveTimeout bounds a single SaveRecordBatch call.
	//
	// This is load-bearing for shutdown, not just hygiene. The flush loop is the
	// only thing that drains the queue, producers block when the queue fills, and
	// Close waits for in-flight producers before it can proceed. An unbounded save
	// against a locked SQLite file or a stalled Postgres therefore stops the
	// drainer, which backs up the queue, which pins a producer, which blocks
	// Close — a cycle nothing breaks. With a deadline the drainer always makes
	// progress, so every link in that chain is bounded too.
	//
	// Derived from context.Background(), deliberately not from the crawl context:
	// the final flush must survive crawl cancellation, since that is exactly when
	// there is a tail of captured records still to persist.
	writerSaveTimeout = 30 * time.Second
	// writerDrainTimeout bounds the ENTIRE final drain, not each batch in it.
	//
	// Per-batch bounding is not enough on this path: a full 512-record queue is
	// eight batches, so a stalled store would cost 8 x writerSaveTimeout and Close
	// would take minutes.
	writerDrainTimeout = 30 * time.Second
)

// ErrWriterClosed is returned by Write when the writer has stopped admitting
// records. It is a refusal, not a failure: the caller learns the record was NOT
// accepted, instead of receiving nil for a record that will never be persisted.
var ErrWriterClosed = errors.New("repository writer closed")

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
	// failed counts records dropped because their SaveRecordBatch failed, so a
	// crawl that lost traffic to a failing DB doesn't silently report success.
	failed int
	// accepted counts records Write admitted to the queue; refused counts the
	// ones it turned away with ErrWriterClosed. drainComplete is set once the
	// final drain has given every admitted record an outcome within its budget
	// (persisted or failed) — false while open, and after an abandoned drain.
	accepted      int
	refused       int
	drainComplete bool
	closed        bool
	// specSeen tracks already-parsed spec content hashes to avoid re-parsing.
	specSeen map[string]struct{}

	queue chan writeItem
	// stop is the single shutdown signal: Close closes it, producers stop being
	// admitted, and the flush loop begins its final drain.
	stop chan struct{}
	done chan struct{}
	// admitMu is the admission barrier between producers and the final drain.
	//
	// Producers hold it for READ across their enqueue; the flush loop takes it for
	// WRITE before draining. Without it, Write's
	// `select { case queue <- item; case <-stop }` had a real race: when the queue
	// has room AND stop is already closed, Go picks a ready case at random, so a
	// late write was enqueued after the drainer had exited about half the time —
	// accepted, never persisted, and reported to the caller as success. Checking
	// stop first only narrows that window; it does not close it.
	//
	// The barrier lives on the DRAINER rather than in Close, which is what keeps
	// it deadlock-free. A producer blocked on a full queue holds the read lock and
	// is released by close(stop) taking its own select branch; the drainer then
	// acquires the write lock, and from that moment the queue's contents are final
	// because any producer arriving later sees stop closed and is refused. Had
	// Close taken the write lock instead, it would have been waiting on the
	// drainer — which is exactly the thing a stalled database has stopped.
	admitMu   sync.RWMutex
	closeOnce sync.Once

	// WebSocket frames (websocket.go), buffered under frameMu and saved by the
	// flush loop beside the records when repo is a FrameSaver.
	frameMu       sync.Mutex
	frames        []WebSocketFrame
	framesClosed  bool
	framesSaved   int
	framesDropped int
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

// Write converts a TrafficEntry to HttpRequestResponse and enqueues it for
// batched persistence. It blocks only when the queue is full (natural
// backpressure), and returns ErrWriterClosed once the writer has stopped
// admitting.
//
// A nil return is a promise: the record was admitted and the drainer will either
// persist it or count it failed. That promise is what admitMu exists to keep.
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

	// Hold the admission barrier for the whole enqueue, so the final drain cannot
	// slip between the closed-check and the send. See admitMu.
	w.admitMu.RLock()
	defer w.admitMu.RUnlock()

	select {
	case <-w.stop:
		// Writer closed — refuse late CDP events rather than blocking forever, and
		// say so. This mirrors the capture's own post-Close drop of late Loading
		// events, but the caller can now tell the difference between "stored" and
		// "arrived too late".
		return w.refuse()
	default:
	}

	select {
	case w.queue <- writeItem{rr: httpRR, entry: entry}:
		// Admitted. Even if stop closed concurrently and this case won the coin
		// flip, the item is safe: the drainer cannot have taken the write lock
		// while this producer holds the read lock, so the final drain has not
		// started and will see this item.
		w.mu.Lock()
		w.accepted++
		w.mu.Unlock()
		return nil
	case <-w.stop:
		// Shutdown began while this producer was blocked on a full queue. Refuse
		// explicitly rather than returning nil for a record nothing will store —
		// returning nil here is precisely the bug this whole barrier is about.
		return w.refuse()
	}
}

// refuse counts a record turned away after shutdown began.
func (w *RepositoryWriter) refuse() error {
	w.mu.Lock()
	w.refused++
	w.mu.Unlock()
	return ErrWriterClosed
}

// flushLoop drains the write queue, coalescing records into SaveRecordBatch calls
// on size or a short interval, and runs spec ingestion after each batch lands. It
// exits after Close fences admission and the queue is drained, flushing what
// remains within one bounded shutdown budget.
func (w *RepositoryWriter) flushLoop() {
	defer close(w.done)

	ticker := time.NewTicker(writerFlushInterval)
	defer ticker.Stop()

	pending := make([]writeItem, 0, writerBatchSize)

	// flush persists the pending batch by the given absolute deadline. During
	// shutdown every batch shares ONE deadline, so the final drain is bounded as a
	// whole rather than per batch: a large backlog against a stalled database
	// would otherwise cost writerSaveTimeout for every 64 records, and Close would
	// take minutes instead of seconds.
	flush := func(deadline time.Time) {
		if len(pending) == 0 {
			return
		}
		records := make([]*httpmsg.HttpRequestResponse, len(pending))
		for i, it := range pending {
			records[i] = it.rr
		}

		saveCtx, cancel := context.WithDeadline(context.Background(), deadline)
		ids, err := w.repo.SaveRecordBatch(saveCtx, records, w.source, w.projectUUID)
		cancel()
		if err != nil {
			zap.L().Warn("Failed to save spidering record batch; records dropped",
				zap.Int("count", len(records)), zap.Error(err))
			w.mu.Lock()
			w.failed += len(records)
			w.mu.Unlock()
		} else {
			w.mu.Lock()
			// The result is index-aligned with the input and carries "" for a
			// record that was skipped, so len(ids) over-reports. Counted inline
			// rather than via database.CountSaved: this package talks to the
			// repository through a structural interface and does not import it.
			for _, id := range ids {
				if id != "" {
					w.count++
				}
			}
			w.mu.Unlock()
		}
		// Detect and parse API specs (OpenAPI/Swagger/Postman/WSDL) from spidered
		// responses after the batch is persisted. Cheap to reject for non-specs.
		for _, it := range pending {
			w.ingestSpecEndpoints(it.entry, it.rr)
		}
		pending = pending[:0]
	}

	// finalDrain empties the queue and persists it under ONE shutdown budget,
	// counting whatever does not make it as dropped. Close is on the crawl
	// teardown path, which the runner already caps with its own watchdog, so an
	// unbounded drain is not "more durable" — it just gets abandoned somewhere
	// less accountable, with the loss invisible.
	//
	// Declared here rather than as a method so it shares `pending` and `flush`
	// with the loop above instead of aliasing them through a pointer.
	finalDrain := func() {
		// Fence admission first: a producer mid-enqueue still holds the read lock,
		// so this waits it out, and any producer arriving afterwards sees stop
		// closed and is refused. From here the queue's contents are final.
		w.admitMu.Lock()
		w.admitMu.Unlock() //nolint:staticcheck // lock/unlock is the barrier, not a guarded section

		deadline := time.Now().Add(writerDrainTimeout)
		w.closeFrames()
		defer w.flushFrames(deadline)
		for time.Now().Before(deadline) {
			select {
			case it := <-w.queue:
				pending = append(pending, it)
				if len(pending) >= writerBatchSize {
					flush(deadline)
				}
			default:
				flush(deadline)
				w.mu.Lock()
				w.drainComplete = true
				w.mu.Unlock()
				return
			}
		}
		w.abandonQueued(&pending)
	}

	for {
		select {
		case it := <-w.queue:
			pending = append(pending, it)
			if len(pending) >= writerBatchSize {
				flush(time.Now().Add(writerSaveTimeout))
			}
		case <-ticker.C:
			flush(time.Now().Add(writerSaveTimeout))
			w.flushFrames(time.Now().Add(writerSaveTimeout))
		case <-w.stop:
			finalDrain()
			return
		}
	}
}

// abandonQueued counts everything still buffered or queued as dropped, so the
// tally Close reports covers records that were admitted and never reached the
// database — not only those a save actively rejected.
func (w *RepositoryWriter) abandonQueued(pending *[]writeItem) {
	dropped := len(*pending)
	*pending = (*pending)[:0]
	for {
		select {
		case <-w.queue:
			dropped++
		default:
			w.mu.Lock()
			// The budget ran out exactly as the queue emptied: nothing was left
			// behind, so the drain did finish.
			w.drainComplete = dropped == 0
			w.mu.Unlock()
			if dropped > 0 {
				zap.L().Warn("RepositoryWriter shutdown budget exhausted; queued records abandoned",
					zap.Int("abandoned", dropped),
					zap.Duration("budget", writerDrainTimeout),
					zap.String("source", w.source))
				w.mu.Lock()
				w.failed += dropped
				w.mu.Unlock()
			}
			return
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

	// Batch save parsed endpoints. Bounded for the same reason as the main flush:
	// this runs on the drainer goroutine, so an unbounded call here stalls the
	// queue just as effectively.
	saveCtx, cancel := context.WithTimeout(context.Background(), writerSaveTimeout)
	_, saveErr := w.repo.SaveRecordBatch(saveCtx, endpoints, "spec-ingest", w.projectUUID)
	cancel()
	if saveErr != nil {
		zap.L().Debug("Failed to save spec-ingested endpoints",
			zap.String("source_url", entry.Request.URL),
			zap.Error(saveErr))
		w.mu.Lock()
		w.failed += len(endpoints)
		w.mu.Unlock()
		return
	}

	w.mu.Lock()
	w.count += len(endpoints)
	w.mu.Unlock()

	zap.L().Info("Ingested API spec endpoints from spidered response",
		zap.String("source_url", entry.Request.URL),
		zap.Int("endpoints", len(endpoints)))
}

// Close stops admission, waits for producers already mid-enqueue, then drains
// and persists whatever is buffered, blocking until the flush goroutine has
// finished so Count() reflects everything saved. Safe to call more than once.
//
// It returns a non-nil error when records were dropped to save failures. It used
// to return nil unconditionally, which made a crawl that lost its entire corpus
// to a failing database indistinguishable from a clean one at the only place a
// caller could have noticed. Existing callers discard or log the error, so the
// change surfaces the loss without altering control flow.
func (w *RepositoryWriter) Close() error {
	first := false
	w.closeOnce.Do(func() { close(w.stop); first = true })
	<-w.done

	w.mu.Lock()
	w.closed = true
	saved, failed := w.count, w.failed
	w.mu.Unlock()

	err := closeError(saved, failed, w.source)
	if !first {
		// Already reported by the first Close; later calls only return it.
		return err
	}
	if err != nil {
		zap.L().Warn("RepositoryWriter closed with dropped records (DB save failures)",
			zap.Int("records_saved", saved),
			zap.Int("records_dropped", failed),
			zap.String("source", w.source))
		return err
	}

	zap.L().Debug("RepositoryWriter closed",
		zap.Int("records_saved", saved),
		zap.String("source", w.source))
	return nil
}

// closeError is the error Close reports: non-nil when any admitted record
// failed to persist. Carries counts only, never record content.
func closeError(saved, failed int, source string) error {
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("repository writer: %d record(s) dropped to save failures (%d saved, source %q)",
		failed, saved, source)
}

// Receipt is a writer's own account of what it retained. Persisted can exceed
// Accepted: it also counts endpoints ingested from a captured API spec.
type Receipt struct {
	Accepted  int // records Write admitted
	Persisted int // rows the repository confirmed
	Refused   int // records turned away with ErrWriterClosed
	Failed    int // save failures plus records abandoned by an over-budget drain
	// DrainComplete: Close drained the queue within its budget, so every
	// admitted record has an outcome. False while the writer is open.
	DrainComplete bool
	Closed        bool
	Err           string // Close's error text when records were lost
}

// Receipt returns the writer's current account. It is final once Close has
// returned; before that it is a running snapshot. Safe for concurrent use.
func (w *RepositoryWriter) Receipt() Receipt {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := Receipt{
		Accepted:      w.accepted,
		Persisted:     w.count,
		Refused:       w.refused,
		Failed:        w.failed,
		DrainComplete: w.drainComplete,
		Closed:        w.closed,
	}
	if err := closeError(w.count, w.failed, w.source); w.closed && err != nil {
		r.Err = err.Error()
	}
	return r
}

// Count returns the number of records saved so far.
func (w *RepositoryWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
