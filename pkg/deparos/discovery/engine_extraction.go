package discovery

import (
	"encoding/json"
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
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

// storeJSTangleRequests persists jstangle extracted requests to database.
// Called asynchronously after jstangle extraction completes.
func (e *Engine) storeJSTangleRequests(jsURL *url.URL, reqs []jstangle.ExtractedRequest) {
	if e.storage == nil || len(reqs) == 0 {
		return
	}

	nodeID := e.getNodeIDForURL(jsURL)
	sessionID := e.storage.SessionDBID()
	repo := e.storage.Extractions()

	if repo == nil {
		return
	}

	if err := repo.BatchStoreJSTangleRequests(nodeID, sessionID, reqs); err != nil {
		logger.Warn("Failed to store jstangle requests",
			zap.String("source", jsURL.String()),
			zap.Int("count", len(reqs)),
			zap.Error(err))
	} else {
		logger.Debug("Stored jstangle requests to DB",
			zap.String("source", jsURL.String()),
			zap.Int("count", len(reqs)))
	}
}

func (e *Engine) storeJSTangleFacts(jsURL *url.URL, facts []jstangle.HTTPRequestFact) {
	if jsURL == nil {
		return
	}
	e.storeJSTangleFactsAtSource(jsURL, jsURL.String(), facts)
}

// storeJSTangleFactsAtSource keeps the database node anchored to the fetched
// generated asset while allowing source-map facts to retain their virtual
// original-source URL. That source URL is authoritative for provenance and
// source-relative replay after a discovery session is resumed.
func (e *Engine) storeJSTangleFactsAtSource(nodeURL *url.URL, sourceURL string, facts []jstangle.HTTPRequestFact) {
	if e.storage == nil || nodeURL == nil || sourceURL == "" || len(facts) == 0 {
		return
	}
	repo := e.storage.Extractions()
	if repo == nil {
		return
	}
	if err := repo.BatchStoreJSTangleFacts(
		e.getNodeIDForURL(nodeURL), e.storage.SessionDBID(), sourceURL, facts,
	); err != nil {
		logger.Warn("Failed to store typed jstangle facts",
			zap.String("source", sourceURL), zap.Int("count", len(facts)), zap.Error(err))
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

	// Load JSTangle requests from all sessions (for full history)
	// Note: We load from all sessions because extracted endpoints may be useful
	// even if discovered in previous sessions
	jsRequests, err := repo.GetJSTangleRequests(sessionID)
	if err != nil {
		return err
	}

	loadedCount := 0
	for _, model := range jsRequests {
		if model.SchemaVersion >= 2 && model.TemplateJSON.Valid {
			var fact jstangle.HTTPRequestFact
			if err := json.Unmarshal([]byte(model.TemplateJSON.String), &fact); err == nil {
				if e.AddRequestFact(model.SourceURL.String, fact) {
					loadedCount++
				}
				continue
			}
		}
		req := convertModelToJSTangleRequest(model)
		// Use dedup to avoid duplicates
		if e.AddExtractedRequest(&req) {
			loadedCount++
		}
	}

	if loadedCount > 0 {
		logger.Info("Loaded jstangle extractions from DB",
			zap.Int("loaded", loadedCount),
			zap.Int("total", len(jsRequests)))
	}

	// Restore non-HTTP capability facts separately. Grouping by source preserves
	// source-relative GraphQL endpoint and route resolution while WS/SSE records
	// remain metadata-only.
	capabilityRows, err := repo.GetJSTangleCapabilityFacts(sessionID)
	if err != nil {
		return err
	}
	bySource := make(map[string]*jstangle.ScanResult)
	for _, model := range capabilityRows {
		if !model.TemplateJSON.Valid || !model.RecordKind.Valid {
			continue
		}
		sourceURL := model.SourceURL.String
		result := bySource[sourceURL]
		if result == nil {
			result = &jstangle.ScanResult{}
			bySource[sourceURL] = result
		}
		payload := []byte(model.TemplateJSON.String)
		switch model.RecordKind.String {
		case "graphqlOperation":
			var fact jstangle.GraphQLOperationFact
			if json.Unmarshal(payload, &fact) == nil {
				result.GraphQLOperations = append(result.GraphQLOperations, fact)
			}
		case "websocket":
			var fact jstangle.WebSocketFact
			if json.Unmarshal(payload, &fact) == nil {
				result.WebSockets = append(result.WebSockets, fact)
			}
		case "eventSource":
			var fact jstangle.EventSourceFact
			if json.Unmarshal(payload, &fact) == nil {
				result.EventSources = append(result.EventSources, fact)
			}
		case "clientRoute":
			var fact jstangle.ClientRouteFact
			if json.Unmarshal(payload, &fact) == nil {
				result.ClientRoutes = append(result.ClientRoutes, fact)
			}
		case "browserSecurityFlow":
			var fact jstangle.BrowserSecurityFlowFact
			if json.Unmarshal(payload, &fact) == nil {
				result.BrowserFlows = append(result.BrowserFlows, fact)
			}
		}
	}
	for sourceURL, result := range bySource {
		e.processJSTangleCapabilityFacts(sourceURL, result)
	}

	return nil
}

// extractRoutesFromStoredJS feeds JavaScript that earlier phases (notably
// spidering) already captured through the SAME jstangle + linkfinder extraction the
// discovery crawl runs on JS it fetches itself. The discovery crawl only parses
// JS it fetches during its own run, so a bundle the browser collected — e.g. a
// Salesforce Aura/Lightning app bundle that embeds an /apex/... route for a
// captcha iframe which only mounts after the login form is interacted with — sits
// in storage unparsed and its routes are never requested. linkfinder extracts the
// root-relative routes (AddObservedPath also preserves a query param by queuing it
// as an ExtractedRequest, so `/apex/X?source=Y` is fetched with its param) and
// jstangle extracts XHR/fetch endpoints. Best-effort; runs once at init before tasks
// are generated. Re-uses the already-stored body, so no JS is re-fetched.
func (e *Engine) extractRoutesFromStoredJS() {
	if e.storage == nil {
		return
	}

	var jsFiles, paths, requests int
	_ = e.storage.WalkFiles(func(node *storage.DiscoveredNode) error {
		if e.ctx.Err() != nil {
			return e.ctx.Err()
		}
		resp := node.Response()
		if resp == nil || len(resp.Body) == 0 || !isJavaScriptResponse(node.URL(), resp.MIMEType) {
			return nil
		}
		jsFiles++

		body := resp.Body
		// jstangle extracts HTTP requests (XHR/fetch endpoints) and returns
		// transformed code that linkfinder reads more reliably. It parses/transforms
		// the whole body, so skip it for very large bundles to keep this init step
		// bounded — linkfinder (a cheap regex pass below) still mines their routes.
		if e.jstangleService != nil && len(body) <= maxStoredJSTangleBytes {
			sourceURL := ""
			if u := node.URL(); u != nil {
				sourceURL = u.String()
			}
			if sr, err := e.jstangleService.ScanWithOptions(e.ctx, body, e.jsTangleOptions(jstangle.ProfileDiscovery, sourceURL)); err == nil && sr != nil {
				if len(sr.RequestFacts) > 0 {
					for i := range sr.RequestFacts {
						if e.AddRequestFact(sourceURL, sr.RequestFacts[i]) {
							requests++
						}
					}
				} else {
					for i := range sr.Requests {
						if e.AddExtractedRequest(&sr.Requests[i]) {
							requests++
						}
					}
				}
				if sr.HasCode() {
					body = []byte(sr.Code.Content)
				}
				e.processAssetFacts(e.ctx, sourceURL, resp.Body, sr.AssetFacts)
				e.processJSTangleCapabilityFacts(sourceURL, sr)
			}
		}

		// linkfinder extracts root-relative routes; AddObservedPath preserves any
		// query param by also queuing the full path as an ExtractedRequest.
		for _, p := range linkfinder.ExtractPaths(body) {
			if name, _ := ExtractFilename(p); name != "" {
				e.AddObservedName(name)
			}
			if p != "" {
				e.AddObservedPath(p)
				paths++
			}
		}
		return nil
	})

	if jsFiles > 0 {
		logger.Info("Parsed already-collected JS for routes",
			zap.Int("js_files", jsFiles),
			zap.Int("paths", paths),
			zap.Int("requests", requests))
	}
}

// maxStoredJSTangleBytes caps the body size fed to jstangle during the stored-JS
// route mining (jstangle parses/transforms the whole body); larger bundles are
// still mined by the cheap linkfinder regex pass, just not jstangle-transformed.
const maxStoredJSTangleBytes = 4 * 1024 * 1024

// isJavaScriptResponse reports whether a stored response is JavaScript, by MIME
// type or URL extension (the extension catches framework bundles served with an
// odd content-type, e.g. Salesforce's application/x-javascript aurafile bundles).
// Delegates to the canonical coordinator classifiers.
func isJavaScriptResponse(u *url.URL, mime string) bool {
	return isJavaScriptContentType(mime) || (u != nil && hasJavaScriptExtension(u))
}

// convertModelToJSTangleRequest converts a storage model to jstangle request.
func convertModelToJSTangleRequest(m storage.ExtractionModel) jstangle.ExtractedRequest {
	var headers []string
	var cookies []string

	if m.Headers.Valid && m.Headers.String != "" {
		if err := json.Unmarshal([]byte(m.Headers.String), &headers); err != nil {
			zap.L().Debug("failed to decode stored jstangle headers", zap.Error(err))
		}
	}
	if m.Cookies.Valid && m.Cookies.String != "" {
		if err := json.Unmarshal([]byte(m.Cookies.String), &cookies); err != nil {
			zap.L().Debug("failed to decode stored jstangle cookies", zap.Error(err))
		}
	}

	return jstangle.ExtractedRequest{
		URL:     m.URL,
		Method:  m.Method,
		Body:    m.Body.String,
		Headers: headers,
		Cookies: cookies,
	}
}
