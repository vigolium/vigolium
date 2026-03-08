package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/url"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
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

// ============ JSScan Methods ============

// StoreJSScanRequest stores a jsscan extracted request.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) StoreJSScanRequest(
	sourceNodeID, sessionID int64,
	req *jsscan.ExtractedRequest,
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

	hash := computeExtractionHash(SourceJSScan, finalURL, req.Method, req.Body)
	hostname := ExtractHostname(finalURL)

	model := &ExtractionModel{
		SourceNodeID: sourceNodeID,
		SessionID:    sessionID,
		Hash:         hash,
		Source:       uint8(SourceJSScan),
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

// BatchStoreJSScanRequests stores multiple jsscan requests efficiently.
// Uses hash-based deduplication - duplicates are silently ignored.
func (r *ExtractionRepository) BatchStoreJSScanRequests(
	sourceNodeID, sessionID int64,
	reqs []jsscan.ExtractedRequest,
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

		hash := computeExtractionHash(SourceJSScan, finalURL, req.Method, req.Body)
		hostname := ExtractHostname(finalURL)

		model := ExtractionModel{
			SourceNodeID: sourceNodeID,
			SessionID:    sessionID,
			Hash:         hash,
			Source:       uint8(SourceJSScan),
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

// GetJSScanRequests returns all jsscan-extracted requests for a session.
func (r *ExtractionRepository) GetJSScanRequests(sessionID int64) ([]ExtractionModel, error) {
	return r.GetBySource(sessionID, SourceJSScan)
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
