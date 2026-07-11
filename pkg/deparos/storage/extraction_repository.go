package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/url"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
)

// computeExtractionHash computes FNV-1a hash for deduplication.
// Hash includes: source + url + method + body
func computeExtractionHash(source ExtractionSource, urlStr, method, body string) string {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%d|%s|%s|%s", source, urlStr, method, body)
	return fmt.Sprintf("%016x", h.Sum64())
}

// ExtractionRepository provides database operations for extraction results.
type ExtractionRepository struct {
	db bun.IDB
}

// NewExtractionRepository creates a new extraction repository.
func NewExtractionRepository(db bun.IDB) *ExtractionRepository {
	return &ExtractionRepository{db: db}
}

// ============ Spider Link Methods ============

// StoreSpiderLink stores a spider-discovered link.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) StoreSpiderLink(
	sourceNodeID, sessionID int64,
	link *spider.DiscoveredLink,
) error {
	if link == nil || link.URL == nil {
		return nil
	}

	ctx := context.Background()
	urlStr := link.URL.String()
	hash := computeExtractionHash(SourceSpider, urlStr, "GET", "")
	hostname := ParseHostname(link.URL).Hostname

	model := &ExtractionModel{
		SourceNodeID: sourceNodeID,
		SessionID:    sessionID,
		Hash:         hash,
		Source:       uint8(SourceSpider),
		SourceSub:    uint8(link.SourceType),
		Hostname:     hostname,
		URL:          urlStr,
		Method:       "GET",
		CreatedAt:    time.Now().Unix(),
	}

	// OnConflict DoNothing - silently ignore duplicates
	_, err := r.db.NewInsert().Model(model).
		On("CONFLICT DO NOTHING").
		Exec(ctx)
	return err
}

// BatchStoreSpiderLinks stores multiple spider links efficiently.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) BatchStoreSpiderLinks(
	sourceNodeID, sessionID int64,
	links []*spider.DiscoveredLink,
) error {
	if len(links) == 0 {
		return nil
	}

	ctx := context.Background()
	models := make([]ExtractionModel, 0, len(links))
	now := time.Now().Unix()

	for _, link := range links {
		if link == nil || link.URL == nil {
			continue
		}
		urlStr := link.URL.String()
		hash := computeExtractionHash(SourceSpider, urlStr, "GET", "")
		hostname := ParseHostname(link.URL).Hostname

		models = append(models, ExtractionModel{
			SourceNodeID: sourceNodeID,
			SessionID:    sessionID,
			Hash:         hash,
			Source:       uint8(SourceSpider),
			SourceSub:    uint8(link.SourceType),
			Hostname:     hostname,
			URL:          urlStr,
			Method:       "GET",
			CreatedAt:    now,
		})
	}

	if len(models) == 0 {
		return nil
	}

	// Insert in batches
	return r.insertInBatches(ctx, models, 100)
}

// ============ JSTangle Methods ============

// StoreJSTangleRequest stores a jstangle extracted request.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) StoreJSTangleRequest(
	sourceNodeID, sessionID int64,
	req *jstangle.ExtractedRequest,
) error {
	if req == nil {
		return nil
	}

	ctx := context.Background()

	// Build URL with params if present
	finalURL := req.URL
	if req.Params != "" {
		if u, err := url.Parse(req.URL); err == nil {
			if u.RawQuery != "" {
				u.RawQuery += "&" + req.Params
			} else {
				u.RawQuery = req.Params
			}
			finalURL = u.String()
		}
	}

	hash := computeExtractionHash(SourceJSTangle, finalURL, req.Method, req.Body)
	hostname := ExtractHostname(finalURL)

	model := &ExtractionModel{
		SourceNodeID: sourceNodeID,
		SessionID:    sessionID,
		Hash:         hash,
		Source:       uint8(SourceJSTangle),
		Hostname:     hostname,
		URL:          finalURL,
		Method:       req.Method,
		Body:         nullString(req.Body),
		CreatedAt:    time.Now().Unix(),
	}

	if len(req.Headers) > 0 {
		headersJSON, _ := json.Marshal(req.Headers)
		model.Headers = nullString(string(headersJSON))
	}

	if len(req.Cookies) > 0 {
		cookiesJSON, _ := json.Marshal(req.Cookies)
		model.Cookies = nullString(string(cookiesJSON))
	}

	// OnConflict DoNothing - silently ignore duplicates
	_, err := r.db.NewInsert().Model(model).
		On("CONFLICT DO NOTHING").
		Exec(ctx)
	return err
}

// BatchStoreJSTangleRequests stores multiple jstangle requests efficiently.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) BatchStoreJSTangleRequests(
	sourceNodeID, sessionID int64,
	reqs []jstangle.ExtractedRequest,
) error {
	if len(reqs) == 0 {
		return nil
	}

	ctx := context.Background()
	models := make([]ExtractionModel, 0, len(reqs))
	now := time.Now().Unix()

	for i := range reqs {
		req := &reqs[i]

		// Build URL with params if present
		finalURL := req.URL
		if req.Params != "" {
			if u, err := url.Parse(req.URL); err == nil {
				if u.RawQuery != "" {
					u.RawQuery += "&" + req.Params
				} else {
					u.RawQuery = req.Params
				}
				finalURL = u.String()
			}
		}

		hash := computeExtractionHash(SourceJSTangle, finalURL, req.Method, req.Body)
		hostname := ExtractHostname(finalURL)

		model := ExtractionModel{
			SourceNodeID: sourceNodeID,
			SessionID:    sessionID,
			Hash:         hash,
			Source:       uint8(SourceJSTangle),
			Hostname:     hostname,
			URL:          finalURL,
			Method:       req.Method,
			Body:         nullString(req.Body),
			CreatedAt:    now,
		}

		if len(req.Headers) > 0 {
			headersJSON, _ := json.Marshal(req.Headers)
			model.Headers = nullString(string(headersJSON))
		}

		if len(req.Cookies) > 0 {
			cookiesJSON, _ := json.Marshal(req.Cookies)
			model.Cookies = nullString(string(cookiesJSON))
		}

		models = append(models, model)
	}

	// Insert in batches
	return r.insertInBatches(ctx, models, 100)
}

// StoreJSTangleFact stores the complete typed v2 request template while also
// populating compatibility columns used by existing extraction queries.
func (r *ExtractionRepository) StoreJSTangleFact(
	sourceNodeID, sessionID int64,
	sourceURL string,
	fact *jstangle.HTTPRequestFact,
) error {
	if fact == nil {
		return nil
	}
	model := extractionModelFromFact(sourceNodeID, sessionID, sourceURL, fact, time.Now().Unix())
	_, err := r.db.NewInsert().Model(&model).On("CONFLICT DO NOTHING").Exec(context.Background())
	return err
}

func (r *ExtractionRepository) BatchStoreJSTangleFacts(
	sourceNodeID, sessionID int64,
	sourceURL string,
	facts []jstangle.HTTPRequestFact,
) error {
	if len(facts) == 0 {
		return nil
	}
	now := time.Now().Unix()
	models := make([]ExtractionModel, 0, len(facts))
	for i := range facts {
		models = append(models, extractionModelFromFact(sourceNodeID, sessionID, sourceURL, &facts[i], now))
	}
	return r.insertInBatches(context.Background(), models, 100)
}

func extractionModelFromFact(sourceNodeID, sessionID int64, sourceURL string, fact *jstangle.HTTPRequestFact, now int64) ExtractionModel {
	query := renderFactQuery(fact.Query)
	finalURL := fact.URL.Rendered
	if query != "" {
		if parsed, err := url.Parse(finalURL); err == nil {
			if parsed.RawQuery == "" {
				parsed.RawQuery = query
			} else {
				parsed.RawQuery += "&" + query
			}
			finalURL = parsed.String()
		}
	}
	body := ""
	contentType := ""
	if fact.Body != nil {
		body = fact.Body.Value.Rendered
		contentType = fact.Body.ContentType
	}
	headers := make([]string, 0, len(fact.Headers))
	for _, header := range fact.Headers {
		headers = append(headers, header.Name.Rendered+": "+header.Value.Rendered)
		if contentType == "" && strings.EqualFold(header.Name.Rendered, "Content-Type") {
			contentType = header.Value.Rendered
		}
	}
	cookies := make([]string, 0, len(fact.Cookies))
	for _, cookie := range fact.Cookies {
		cookies = append(cookies, cookie.Name.Rendered+"="+cookie.Value.Rendered)
	}
	templateJSON, _ := json.Marshal(fact)
	headersJSON, _ := json.Marshal(headers)
	cookiesJSON, _ := json.Marshal(cookies)
	identity := sourceURL + "|" + fact.ID + "|" + finalURL + "|" + fact.Method.Rendered + "|" + body
	model := ExtractionModel{
		SourceNodeID: sourceNodeID, SessionID: sessionID,
		Hash:   computeExtractionHash(SourceJSTangle, identity, fact.Method.Rendered, body),
		Source: uint8(SourceJSTangle), Hostname: ExtractHostname(finalURL), URL: finalURL,
		Method: fact.Method.Rendered, Body: nullString(body), ContentType: nullString(contentType),
		Headers: nullString(string(headersJSON)), Cookies: nullString(string(cookiesJSON)),
		SourceURL: nullString(sourceURL), RecordKind: nullString("httpRequest"),
		Confidence: nullString(fact.Provenance.Confidence), Extractor: nullString(fact.Provenance.Extractor),
		ModulePath: nullString(fact.Provenance.ModulePath), TemplateJSON: nullString(string(templateJSON)),
		SchemaVersion: 2, CreatedAt: now,
	}
	if fact.Provenance.Start != nil && fact.Provenance.Start.Line > 0 {
		model.SourceLine = sql.NullInt64{Int64: int64(fact.Provenance.Start.Line), Valid: true}
	}
	return model
}

// BatchStoreJSTangleCapabilityFacts persists non-HTTP protocol, route, and
// browser-flow records. They share the additive v2 extraction schema for
// export/resume compatibility but are deliberately excluded from
// GetJSTangleRequests so no generic HTTP replay path can consume them.
func (r *ExtractionRepository) BatchStoreJSTangleCapabilityFacts(
	sourceNodeID, sessionID int64,
	sourceURL string,
	result *jstangle.ScanResult,
) error {
	if result == nil {
		return nil
	}
	now := time.Now().Unix()
	models := make([]ExtractionModel, 0,
		len(result.GraphQLOperations)+len(result.WebSockets)+len(result.EventSources)+
			len(result.ClientRoutes)+len(result.BrowserFlows))
	appendRecord := func(kind, id, target, method string, provenance jstangle.Provenance, value any) {
		payload, err := json.Marshal(value)
		if err != nil {
			return
		}
		if target == "" {
			target = sourceURL
		}
		hostname := ExtractHostname(target)
		if hostname == "" {
			hostname = ExtractHostname(sourceURL)
		}
		identity := sourceURL + "|" + kind + "|" + id + "|" + string(payload)
		model := ExtractionModel{
			SourceNodeID: sourceNodeID, SessionID: sessionID,
			Hash:   computeExtractionHash(SourceJSTangle, identity, method, ""),
			Source: uint8(SourceJSTangle), Hostname: hostname, URL: target, Method: method,
			SourceURL: nullString(sourceURL), RecordKind: nullString(kind),
			Confidence: nullString(provenance.Confidence), Extractor: nullString(provenance.Extractor),
			ModulePath: nullString(provenance.ModulePath), TemplateJSON: nullString(string(payload)),
			SchemaVersion: 2, CreatedAt: now,
		}
		if provenance.Start != nil && provenance.Start.Line > 0 {
			model.SourceLine = sql.NullInt64{Int64: int64(provenance.Start.Line), Valid: true}
		}
		models = append(models, model)
	}
	for i := range result.GraphQLOperations {
		fact := &result.GraphQLOperations[i]
		target := ""
		if fact.Endpoint != nil {
			target = fact.Endpoint.Rendered
		}
		appendRecord(fact.Kind, fact.ID, target, "GRAPHQL", fact.Provenance, fact)
	}
	for i := range result.WebSockets {
		fact := &result.WebSockets[i]
		appendRecord(fact.Kind, fact.ID, fact.URL.Rendered, "WS", fact.Provenance, fact)
	}
	for i := range result.EventSources {
		fact := &result.EventSources[i]
		appendRecord(fact.Kind, fact.ID, fact.URL.Rendered, "SSE", fact.Provenance, fact)
	}
	for i := range result.ClientRoutes {
		fact := &result.ClientRoutes[i]
		appendRecord(fact.Kind, fact.ID, fact.Path.Rendered, "ROUTE", fact.Provenance, fact)
	}
	for i := range result.BrowserFlows {
		fact := &result.BrowserFlows[i]
		appendRecord(fact.Kind, fact.ID, sourceURL, "FLOW", fact.Provenance, fact)
	}
	return r.insertInBatches(context.Background(), models, 100)
}

func sourceArtifactHash(sessionID int64, generatedURL, sourcePath, contentSHA256 string) string {
	identity := fmt.Sprintf("source-artifact|%d|%s|%s|%s", sessionID, generatedURL, sourcePath, contentSHA256)
	return computeExtractionHash(SourceJSTangle, identity, "SOURCE", "")
}

// StoreJSTangleSourceArtifact persists one bounded source-map sourcesContent
// entry. The caller validates source-map limits and normalizes SourcePath;
// this method remains content-addressed and never writes that path to disk.
func (r *ExtractionRepository) StoreJSTangleSourceArtifact(model *JSTangleSourceArtifactModel) error {
	if model == nil || model.SessionID == 0 || model.GeneratedURL == "" ||
		model.SourcePath == "" || model.ContentSHA256 == "" {
		return nil
	}
	if model.Hash == "" {
		model.Hash = sourceArtifactHash(model.SessionID, model.GeneratedURL, model.SourcePath, model.ContentSHA256)
	}
	if model.CreatedAt == 0 {
		model.CreatedAt = time.Now().Unix()
	}
	_, err := r.db.NewInsert().Model(model).On("CONFLICT DO NOTHING").Exec(context.Background())
	return err
}

// GetJSTangleSourceArtifacts returns recovered original sources for one session.
// A zero session ID intentionally selects all sessions for offline inspection.
func (r *ExtractionRepository) GetJSTangleSourceArtifacts(sessionID int64) ([]JSTangleSourceArtifactModel, error) {
	models := make([]JSTangleSourceArtifactModel, 0)
	query := r.db.NewSelect().Model(&models).OrderExpr("created_at ASC, id ASC")
	if sessionID != 0 {
		query = query.Where("session_id = ?", sessionID)
	}
	if err := query.Scan(context.Background()); err != nil {
		return nil, err
	}
	return models, nil
}

func renderFactQuery(fields []jstangle.FieldTemplate) string {
	values := url.Values{}
	for _, field := range fields {
		values.Add(field.Name.Rendered, field.Value.Rendered)
	}
	return values.Encode()
}

// ============ Form Methods ============

// StoreFormRequest stores a pre-built form request.
// For GET: params are in URL. For POST: params are in Body.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) StoreFormRequest(
	sourceNodeID, sessionID int64,
	form *spider.FormRequest,
) error {
	if form == nil || form.URL == nil {
		return nil
	}

	ctx := context.Background()
	urlStr := form.URL.String()
	hash := computeExtractionHash(SourceForm, urlStr, form.Method, form.Body)
	hostname := ParseHostname(form.URL).Hostname

	model := &ExtractionModel{
		SourceNodeID: sourceNodeID,
		SessionID:    sessionID,
		Hash:         hash,
		Source:       uint8(SourceForm),
		Hostname:     hostname,
		URL:          urlStr,
		Method:       form.Method,
		Body:         nullString(form.Body),
		ContentType:  nullString(form.ContentType),
		CreatedAt:    time.Now().Unix(),
	}

	// OnConflict DoNothing - silently ignore duplicates
	_, err := r.db.NewInsert().Model(model).
		On("CONFLICT DO NOTHING").
		Exec(ctx)
	return err
}

// BatchStoreFormRequests stores multiple form requests efficiently.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) BatchStoreFormRequests(
	sourceNodeID, sessionID int64,
	forms []*spider.FormRequest,
) error {
	if len(forms) == 0 {
		return nil
	}

	ctx := context.Background()
	models := make([]ExtractionModel, 0, len(forms))
	now := time.Now().Unix()

	for _, form := range forms {
		if form == nil || form.URL == nil {
			continue
		}
		urlStr := form.URL.String()
		hash := computeExtractionHash(SourceForm, urlStr, form.Method, form.Body)
		hostname := ParseHostname(form.URL).Hostname

		models = append(models, ExtractionModel{
			SourceNodeID: sourceNodeID,
			SessionID:    sessionID,
			Hash:         hash,
			Source:       uint8(SourceForm),
			Hostname:     hostname,
			URL:          urlStr,
			Method:       form.Method,
			Body:         nullString(form.Body),
			ContentType:  nullString(form.ContentType),
			CreatedAt:    now,
		})
	}

	if len(models) == 0 {
		return nil
	}

	// Insert in batches
	return r.insertInBatches(ctx, models, 100)
}

// insertInBatches inserts models in chunks with ON CONFLICT DO NOTHING.
func (r *ExtractionRepository) insertInBatches(ctx context.Context, models []ExtractionModel, batchSize int) error {
	for i := 0; i < len(models); i += batchSize {
		end := i + batchSize
		if end > len(models) {
			end = len(models)
		}
		chunk := models[i:end]
		if _, err := r.db.NewInsert().Model(&chunk).
			On("CONFLICT DO NOTHING").
			Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ============ Query Methods ============

// GetBySession returns all extractions for a session.
func (r *ExtractionRepository) GetBySession(sessionID int64) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("session_id = ?", sessionID).
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetBySource returns extractions filtered by source type.
func (r *ExtractionRepository) GetBySource(
	sessionID int64,
	source ExtractionSource,
) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("session_id = ? AND source = ?", sessionID, uint8(source)).
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetByNode returns all extractions from a specific source node.
func (r *ExtractionRepository) GetByNode(nodeID int64) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("source_node_id = ?", nodeID).
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetForms returns all forms for a session.
func (r *ExtractionRepository) GetForms(sessionID int64) ([]ExtractionModel, error) {
	return r.GetBySource(sessionID, SourceForm)
}

// CountBySource returns counts grouped by source type.
func (r *ExtractionRepository) CountBySource(sessionID int64) (map[ExtractionSource]int64, error) {
	ctx := context.Background()
	type result struct {
		Source uint8 `bun:"source"`
		Count  int64 `bun:"count"`
	}
	var results []result

	err := r.db.NewRaw(`
		SELECT source, COUNT(*) AS count
		FROM extractions
		WHERE session_id = ?
		GROUP BY source
	`, sessionID).Scan(ctx, &results)

	if err != nil {
		return nil, err
	}

	counts := make(map[ExtractionSource]int64)
	for _, res := range results {
		counts[ExtractionSource(res.Source)] = res.Count
	}
	return counts, nil
}

// GetByURLPattern returns extractions matching URL pattern.
func (r *ExtractionRepository) GetByURLPattern(
	sessionID int64,
	pattern string,
) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("session_id = ? AND url LIKE ?", sessionID, "%"+pattern+"%").
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetByMethod returns extractions with specific HTTP method.
func (r *ExtractionRepository) GetByMethod(
	sessionID int64,
	method string,
) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("session_id = ? AND method = ?", sessionID, method).
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetSpiderLinks returns all spider-extracted links for a session.
func (r *ExtractionRepository) GetSpiderLinks(sessionID int64) ([]ExtractionModel, error) {
	return r.GetBySource(sessionID, SourceSpider)
}

// GetJSTangleRequests returns only replay-compatible request rows. Protocol,
// route, and browser-flow metadata are intentionally excluded.
func (r *ExtractionRepository) GetJSTangleRequests(sessionID int64) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("session_id = ? AND source = ?", sessionID, uint8(SourceJSTangle)).
		Where("record_kind IS NULL OR record_kind = '' OR record_kind = 'httpRequest'").
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetJSTangleCapabilityFacts returns the typed non-HTTP records for resume and
// export paths.
func (r *ExtractionRepository) GetJSTangleCapabilityFacts(sessionID int64) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("session_id = ? AND source = ?", sessionID, uint8(SourceJSTangle)).
		Where("record_kind IS NOT NULL AND record_kind != '' AND record_kind != 'httpRequest'").
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// DeleteBySession deletes all extractions for a session.
func (r *ExtractionRepository) DeleteBySession(sessionID int64) error {
	ctx := context.Background()
	_, err := r.db.NewDelete().Model((*ExtractionModel)(nil)).
		Where("session_id = ?", sessionID).
		Exec(ctx)
	return err
}

// DeleteByNode deletes all extractions from a specific node.
func (r *ExtractionRepository) DeleteByNode(nodeID int64) error {
	ctx := context.Background()
	_, err := r.db.NewDelete().Model((*ExtractionModel)(nil)).
		Where("source_node_id = ?", nodeID).
		Exec(ctx)
	return err
}

// ============ Hostname Query Methods ============

// GetByHostname returns all extractions for a specific hostname.
func (r *ExtractionRepository) GetByHostname(hostname string) ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Where("hostname = ?", hostname).
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// GetAll returns all extractions across all sessions.
func (r *ExtractionRepository) GetAll() ([]ExtractionModel, error) {
	ctx := context.Background()
	var extractions []ExtractionModel
	err := r.db.NewSelect().Model(&extractions).
		Order("created_at").
		Scan(ctx)
	return extractions, err
}

// ============ Helper Functions ============

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
