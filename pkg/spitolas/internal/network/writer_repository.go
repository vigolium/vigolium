package network

import (
	"context"
	"net/url"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
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
}

// NewRepositoryWriter creates a Writer that stores traffic in vigolium's HTTPRecord table.
func NewRepositoryWriter(repo RecordSaver, source string, projectUUID string) *RepositoryWriter {
	return &RepositoryWriter{
		repo:        repo,
		source:      source,
		projectUUID: projectUUID,
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

	return nil
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
