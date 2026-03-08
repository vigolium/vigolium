package discovery

import (
	"encoding/json"
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"go.uber.org/zap"
)

// ============ Extraction Storage Methods ============

// storeSpiderLinks persists spider-discovered links to database.
// Called asynchronously after spider extraction completes.
func (e *Engine) storeSpiderLinks(sourceURL *url.URL, links []*spider.DiscoveredLink) {
	if e.storage == nil || len(links) == 0 {
		return
	}

	nodeID := e.getNodeIDForURL(sourceURL)
	sessionID := e.storage.SessionDBID()
	repo := e.storage.Extractions()

	if repo == nil {
		return
	}

	if err := repo.BatchStoreSpiderLinks(nodeID, sessionID, links); err != nil {
		logger.Warn("Failed to store spider links",
			zap.String("source", sourceURL.String()),
			zap.Int("count", len(links)),
			zap.Error(err))
	} else {
		logger.Debug("Stored spider links to DB",
			zap.String("source", sourceURL.String()),
			zap.Int("count", len(links)))
	}
}

// storeJSScanRequests persists jsscan extracted requests to database.
// Called asynchronously after jsscan extraction completes.
func (e *Engine) storeJSScanRequests(jsURL *url.URL, reqs []jsscan.ExtractedRequest) {
	if e.storage == nil || len(reqs) == 0 {
		return
	}

	nodeID := e.getNodeIDForURL(jsURL)
	sessionID := e.storage.SessionDBID()
	repo := e.storage.Extractions()

	if repo == nil {
		return
	}

	if err := repo.BatchStoreJSScanRequests(nodeID, sessionID, reqs); err != nil {
		logger.Warn("Failed to store jsscan requests",
			zap.String("source", jsURL.String()),
			zap.Int("count", len(reqs)),
			zap.Error(err))
	} else {
		logger.Debug("Stored jsscan requests to DB",
			zap.String("source", jsURL.String()),
			zap.Int("count", len(reqs)))
	}
}

// storeFormRequests persists form requests to database.
// Called asynchronously after form extraction completes.
func (e *Engine) storeFormRequests(sourceURL *url.URL, forms []*spider.FormRequest) {
	if e.storage == nil || len(forms) == 0 {
		return
	}

	nodeID := e.getNodeIDForURL(sourceURL)
	sessionID := e.storage.SessionDBID()
	repo := e.storage.Extractions()

	if repo == nil {
		return
	}

	if err := repo.BatchStoreFormRequests(nodeID, sessionID, forms); err != nil {
		logger.Warn("Failed to store form requests",
			zap.String("source", sourceURL.String()),
			zap.Int("count", len(forms)),
			zap.Error(err))
	} else {
		logger.Debug("Stored form requests to DB",
			zap.String("source", sourceURL.String()),
			zap.Int("count", len(forms)))
	}
}

// getNodeIDForURL retrieves the node database ID for a URL.
// Returns 0 if the URL is not found in storage.
func (e *Engine) getNodeIDForURL(u *url.URL) int64 {
	if e.storage == nil || u == nil {
		return 0
	}

	node, err := e.storage.Get(u)
	if err != nil || node == nil {
		return 0
	}

	return node.ID()
}

// ============ Extraction Loading Methods ============

// loadExtractionsFromDB loads previously stored extractions from database.
// Called during engine initialization when resuming a session with existing DB.
func (e *Engine) loadExtractionsFromDB() error {
	if e.storage == nil {
		return nil
	}

	repo := e.storage.Extractions()
	if repo == nil {
		return nil
	}

	sessionID := e.storage.SessionDBID()

	// Load JSScan requests from all sessions (for full history)
	// Note: We load from all sessions because extracted endpoints may be useful
	// even if discovered in previous sessions
	jsRequests, err := repo.GetJSScanRequests(sessionID)
	if err != nil {
		return err
	}

	loadedCount := 0
	for _, model := range jsRequests {
		req := convertModelToJSScanRequest(model)
		// Use dedup to avoid duplicates
		if e.AddExtractedRequest(&req) {
			loadedCount++
		}
	}

	if loadedCount > 0 {
		logger.Info("Loaded jsscan extractions from DB",
			zap.Int("loaded", loadedCount),
			zap.Int("total", len(jsRequests)))
	}

	return nil
}

// convertModelToJSScanRequest converts a storage model to jsscan request.
func convertModelToJSScanRequest(m storage.ExtractionModel) jsscan.ExtractedRequest {
	var headers []string
	var cookies []string

	if m.Headers.Valid && m.Headers.String != "" {
		_ = json.Unmarshal([]byte(m.Headers.String), &headers)
	}
	if m.Cookies.Valid && m.Cookies.String != "" {
		_ = json.Unmarshal([]byte(m.Cookies.String), &cookies)
	}

	return jsscan.ExtractedRequest{
		URL:     m.URL,
		Method:  m.Method,
		Body:    m.Body.String,
		Headers: headers,
		Cookies: cookies,
	}
}
