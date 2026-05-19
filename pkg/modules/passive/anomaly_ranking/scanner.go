package anomaly_ranking

import (
	"context"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/anomaly"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const (
	// flushThreshold is the number of responses per host before ranking and flushing.
	flushThreshold = 50

	// maxRecordsPerHost caps the buffer size for a single host.
	maxRecordsPerHost = 500

	// maxTrackedHosts limits how many distinct hosts we track concurrently.
	maxTrackedHosts = 1000

	// minBatchSize is the minimum number of records needed for meaningful ranking.
	minBatchSize = 3
)

// bufferedEntry pairs extracted attributes with the request hash for UUID resolution.
type bufferedEntry struct {
	attrs       *anomaly.AttributeSet
	requestHash string
}

// Module implements a passive module that ranks HTTP responses by statistical
// anomaly and updates risk_score on the corresponding database records.
// It buffers per-host response attributes and flushes when the threshold is reached.
type Module struct {
	modkit.BasePassiveModule

	mu      sync.Mutex
	buffers map[string][]bufferedEntry // key: hostname
	engine  *anomaly.Engine
}

// New creates a new anomaly ranking passive module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		buffers: make(map[string][]bufferedEntry),
		engine:  anomaly.NewDefaultEngine(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest extracts response attributes and buffers them per host.
// When a host buffer reaches the flush threshold, it ranks and updates risk scores.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil || ctx.Service() == nil {
		return nil, nil
	}

	host := ctx.Service().Host()
	if host == "" {
		return nil, nil
	}

	statusCode := ctx.Response().StatusCode()
	body := ctx.Response().BodyToString()
	headers := headersToMap(ctx.Response().Headers())

	attrs, err := anomaly.ExtractAttributesFromRaw(statusCode, body, headers)
	if err != nil {
		return nil, nil // silently skip extraction failures
	}

	reqHash := ctx.Request().ID()

	m.mu.Lock()

	// Enforce max tracked hosts
	if _, exists := m.buffers[host]; !exists && len(m.buffers) >= maxTrackedHosts {
		m.mu.Unlock()
		return nil, nil
	}

	buf := m.buffers[host]

	// Enforce max records per host
	if len(buf) >= maxRecordsPerHost {
		m.mu.Unlock()
		return nil, nil
	}

	buf = append(buf, bufferedEntry{attrs: attrs, requestHash: reqHash})
	m.buffers[host] = buf

	if len(buf) >= flushThreshold {
		// Take ownership of buffer and clear it
		batch := buf
		delete(m.buffers, host)
		m.mu.Unlock()

		m.rankAndUpdate(batch, scanCtx)
	} else {
		m.mu.Unlock()
	}

	return nil, nil
}

// Flush implements modules.Flusher. Called after all workers finish to rank
// any remaining buffered records.
func (m *Module) Flush(scanCtx *modkit.ScanContext) {
	m.mu.Lock()
	remaining := m.buffers
	m.buffers = make(map[string][]bufferedEntry)
	m.mu.Unlock()

	for _, batch := range remaining {
		if len(batch) < minBatchSize {
			continue
		}
		m.rankAndUpdate(batch, scanCtx)
	}
}

// rankAndUpdate ranks a batch of buffered entries and updates risk scores in the database.
func (m *Module) rankAndUpdate(batch []bufferedEntry, scanCtx *modkit.ScanContext) {
	if scanCtx == nil || scanCtx.RiskScoreUpdater == nil || scanCtx.RequestUUIDResolver == nil {
		return
	}

	// Build ResponseRecords for the engine
	records := make([]*anomaly.ResponseRecord, len(batch))
	for i, entry := range batch {
		records[i] = anomaly.NewResponseRecord(*entry.attrs, entry.requestHash)
	}

	if err := m.engine.RankAndSort(records); err != nil {
		zap.L().Debug("Anomaly ranking failed", zap.Error(err))
		return
	}

	batchSize := len(records)
	scores := make(map[string]int, batchSize)

	for rank, rec := range records {
		reqHash, ok := rec.Metadata.(string)
		if !ok {
			continue
		}
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(reqHash)
		if uuid == "" {
			continue
		}

		// Percentile: rank 0 (highest anomaly) gets ~100, last gets ~0
		percentile := min((batchSize-rank)*100/batchSize, 100)
		scores[uuid] = percentile
	}

	if len(scores) == 0 {
		return
	}

	if err := scanCtx.RiskScoreUpdater.UpdateRiskScores(context.Background(), scores); err != nil {
		zap.L().Debug("Failed to update risk scores", zap.Error(err))
	}
}

// headersToMap converts httpmsg.HttpHeader slice to the map format expected by ExtractAttributesFromRaw.
func headersToMap(headers []httpmsg.HttpHeader) map[string][]string {
	m := make(map[string][]string, len(headers))
	for _, h := range headers {
		key := strings.ToLower(h.Name)
		m[key] = append(m[key], h.Value)
	}
	return m
}
