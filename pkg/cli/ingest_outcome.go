package cli

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// ingestOutcome is what one ingest source actually did to the database.
//
// It exists because `ingest` used to print `executor.Processed() + directSaved`
// as "N records ingested". Processed() counts items the executor ATTEMPTED, so
// a HAR replayed against a host that no longer resolves printed "30 records
// ingested" over a table with zero rows in it. Stored is the only number that
// may be reported as ingested; Failed is what the caller has to be told about
// instead of discovering with a row count.
type ingestOutcome struct {
	// Stored counts records that are in the database because of this run.
	Stored int64
	// Failed counts records that should have been stored and were not: a write
	// the database refused, or a request that never got a response to store.
	Failed int64
	// Skipped counts records a filter deliberately dropped — a static asset, or
	// a request outside the configured scope. Not a failure: nothing was lost
	// that the configuration asked to keep. Records dropped by the executor's
	// pre-fetch filters are not visible here and are not counted.
	Skipped int64
	// Written counts the rows this run added to http_records; a record that
	// was already stored counts in Stored but not here. -1 means unknown.
	Written int64

	// Submitted and Errors are remote mode's (-s/--server) own counters, which
	// are about HTTP submissions rather than rows: the server owns the store.
	Submitted int64
	Errors    int64

	// Formats names the input formats this outcome covers, in first-seen order.
	Formats []string

	// Reasons counts why records were not stored, by core.Drop* reason, and
	// Failures holds the first few of them. Failed alone could not say whether
	// the host was dead, every answer was a WAF page, or the budget ran out.
	Reasons  map[string]int64
	Failures []core.DropSample

	// Records are the records this run left in the store (capped at
	// maxIngestedRecords; RecordsTruncated says more exist).
	Records          []ingestedRecord
	RecordsTruncated bool
}

// maxIngestedRecords bounds the records an ingest -j lists. The counts carry
// the size; the list exists so a caller can read back what landed by UUID.
const maxIngestedRecords = 50

// ingestedRecord is one stored record, as `ingest -j` lists it.
type ingestedRecord struct {
	UUID       string `json:"uuid"`
	UUIDShort  string `json:"uuid_short"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

func newIngestedRecord(uuid string, rr *httpmsg.HttpRequestResponse) ingestedRecord {
	rec := ingestedRecord{UUID: uuid, UUIDShort: uuidShort(uuid), URL: rr.Target()}
	if rr.Request() != nil {
		rec.Method = rr.Request().Method()
	}
	if rr.Response() != nil {
		rec.StatusCode = rr.Response().StatusCode()
	}
	return rec
}

// noteRecord adds one stored record to the list, within the cap.
func (o *ingestOutcome) noteRecord(rec ingestedRecord) {
	if len(o.Records) >= maxIngestedRecords {
		o.RecordsTruncated = true
		return
	}
	o.Records = append(o.Records, rec)
}

// noteReason counts one unstored record under reason, keeping a sample.
func (o *ingestOutcome) noteReason(reason string, sample core.DropSample) {
	if o.Reasons == nil {
		o.Reasons = map[string]int64{}
	}
	o.Reasons[reason]++
	o.addFailures(sample)
}

// addFailures appends samples within core.MaxDropSamples, the executor's own
// cap, so a batch reports as many examples as one run.
func (o *ingestOutcome) addFailures(samples ...core.DropSample) {
	room := core.MaxDropSamples - len(o.Failures)
	if room > len(samples) {
		room = len(samples)
	}
	if room > 0 {
		o.Failures = append(o.Failures, samples[:room]...)
	}
}

// add folds another source's outcome into this one.
func (o *ingestOutcome) add(other ingestOutcome) {
	o.Stored += other.Stored
	o.Failed += other.Failed
	o.Skipped += other.Skipped
	if other.Written < 0 || o.Written < 0 {
		o.Written = -1
	} else {
		o.Written += other.Written
	}
	o.Submitted += other.Submitted
	o.Errors += other.Errors
	for _, f := range other.Formats {
		o.noteFormat(f)
	}
	for k, v := range other.Reasons {
		if o.Reasons == nil {
			o.Reasons = map[string]int64{}
		}
		o.Reasons[k] += v
	}
	o.addFailures(other.Failures...)
	for _, r := range other.Records {
		o.noteRecord(r)
	}
	if other.RecordsTruncated {
		o.RecordsTruncated = true
	}
}

// noteFormat records an input format once, preserving the order they were seen
// in so a batch reports "har,urls" rather than whichever one finished last.
func (o *ingestOutcome) noteFormat(format string) {
	if format == "" {
		return
	}
	for _, existing := range o.Formats {
		if existing == format {
			return
		}
	}
	o.Formats = append(o.Formats, format)
}

// ingestSaver writes records that already carry their response straight to the
// database, applying the same static-file and scope filters the executor would,
// and counting exactly what it did with each one.
//
// Safe for concurrent use: InputSource.Next may be called from more than one
// goroutine, and preloadedResponseSource saves from inside it.
type ingestSaver struct {
	repo          *database.Repository
	projectUUID   string
	staticMatcher *config.ScopeMatcher
	// scopeMatcher is nil unless scope.applied_on_ingest is set.
	scopeMatcher *config.ScopeMatcher

	mu      sync.Mutex
	outcome ingestOutcome
}

// save stores one record that already has its response, or counts why it did
// not. It never re-fetches: the response the caller supplied is the one that
// lands in the database.
func (s *ingestSaver) save(ctx context.Context, rr *httpmsg.HttpRequestResponse) {
	if rr == nil || rr.Request() == nil {
		return
	}

	// staticMatcher and scopeMatcher are built from the same scope and
	// targets; scopeMatcher only marks that applied_on_ingest is set.
	if !s.staticMatcher.AdmitIngest(rr, s.scopeMatcher != nil) {
		s.count(func(o *ingestOutcome) { o.Skipped++ })
		return
	}

	uuid, err := s.repo.SaveRecord(ctx, rr, database.RecordSourceIngestCLI, s.projectUUID)
	if err != nil {
		zap.L().Warn("ingest: failed to store record",
			zap.String("url", rr.Target()), zap.Error(err))
		s.count(func(o *ingestOutcome) {
			o.Failed++
			o.noteReason(core.DropStoreError, core.DropSample{URL: rr.Target(), Reason: core.DropStoreError, Detail: err.Error()})
		})
		return
	}
	s.count(func(o *ingestOutcome) { o.Stored++ })
	s.noteStored(uuid, rr)
}

// noteStored lists one stored record — saved here or fetched and written by the
// executor — building its entry only while the list has room.
func (s *ingestSaver) noteStored(uuid string, rr *httpmsg.HttpRequestResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.outcome.Records) >= maxIngestedRecords {
		s.outcome.RecordsTruncated = true
		return
	}
	s.outcome.Records = append(s.outcome.Records, newIngestedRecord(uuid, rr))
}

func (s *ingestSaver) count(fn func(*ingestOutcome)) {
	s.mu.Lock()
	fn(&s.outcome)
	s.mu.Unlock()
}

// result returns a snapshot of what this saver has done so far.
func (s *ingestSaver) result() ingestOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outcome
}

// preloadedResponseSource peels records that ALREADY carry a response off the
// stream and writes them directly, so the executor only ever sees records that
// still need a live fetch.
//
// Without it, "no live refetch" was a property of the stdin auto-detect path
// alone: anything that arrived through a FORMAT parser — a HAR, a Burp XML
// export, a Postman collection — reached the executor with its captured
// response attached and had it thrown away and re-fetched. Ingesting a capture
// then required every origin in it to still resolve, which is the opposite of
// what a capture is for.
type preloadedResponseSource struct {
	inner source.InputSource
	save  func(context.Context, *httpmsg.HttpRequestResponse)
}

// Next returns the next record that still needs a response, having written any
// record it passed over on the way.
func (s *preloadedResponseSource) Next(ctx context.Context) (*work.WorkItem, error) {
	for {
		item, err := s.inner.Next(ctx)
		if err != nil {
			return nil, err
		}
		if item == nil || item.Request == nil || !item.Request.HasResponse() {
			return item, nil
		}
		s.save(ctx, item.Request)
		item.Complete()
	}
}

func (s *preloadedResponseSource) Close() error { return s.inner.Close() }

// Count reports the inner source's total. It is the size of the INPUT, which is
// what the executor uses it for (sizing the insertion-point cache and the
// progress denominator); the peeled records are part of that input even though
// no worker will see them.
func (s *preloadedResponseSource) Count() int64 { return source.GetTotal(s.inner) }
