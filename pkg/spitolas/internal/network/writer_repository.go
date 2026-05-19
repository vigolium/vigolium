package network

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
	"sync"

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

// RepositoryWriter implements the Writer interface by converting TrafficEntry
// to httpmsg.HttpRequestResponse and saving via vigolium's database.Repository.
type RepositoryWriter struct {
	repo        RecordSaver
	source      string
	projectUUID string
	mu          sync.Mutex
	count       int
	ScopeFilter func(host, path string) bool

	// specSeen tracks already-parsed spec content hashes to avoid re-parsing.
	specSeen map[string]struct{}
}

// NewRepositoryWriter creates a Writer that stores traffic in vigolium's HTTPRecord table.
func NewRepositoryWriter(repo RecordSaver, source string, projectUUID string) *RepositoryWriter {
	return &RepositoryWriter{
		repo:        repo,
		source:      source,
		projectUUID: projectUUID,
		specSeen:    make(map[string]struct{}),
	}
}

// Write converts a TrafficEntry to HttpRequestResponse and saves it via the repository.
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

	_, err = w.repo.SaveRecord(context.Background(), httpRR, w.source, w.projectUUID)
	if err != nil {
		zap.L().Debug("Failed to save spidering record",
			zap.String("url", entry.Request.URL),
			zap.Error(err))
		return err
	}

	w.mu.Lock()
	w.count++
	w.mu.Unlock()

	// Detect and parse API specs (OpenAPI/Swagger/Postman) from spidered responses
	w.ingestSpecEndpoints(entry, httpRR)

	return nil
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

// Close flushes any pending writes. RepositoryWriter writes synchronously so this is a no-op.
func (w *RepositoryWriter) Close() error {
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
