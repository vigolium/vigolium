package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
)

// Repository provides bun-based database operations
type Repository struct {
	db bun.IDB
}

// decodeStoredJSON best-effort decodes a JSON column previously written by the
// spider (headers, cookies, session stats) into dst. A decode miss leaves dst at
// its zero value: a garbled or empty column is treated as absent rather than
// failing the row read. Centralizes the justification for the dropped unmarshal
// errors at the call sites below.
func decodeStoredJSON(raw string, dst any) {
	if raw == "" {
		return
	}
	_ = json.Unmarshal([]byte(raw), dst)
}

// NewRepository creates a new Repository with the given bun database connection
func NewRepository(db bun.IDB) *Repository {
	return &Repository{db: db}
}

// Session Operations

// CreateSession always creates a new session with auto-increment ID.
// SessionName is optional metadata for grouping sessions when exporting.
func (r *Repository) CreateSession(ctx context.Context, sessionName string, startedAt int64, targetURL, configJSON string) (*SessionModel, error) {
	session := &SessionModel{
		StartedAt: startedAt,
		TargetURL: targetURL,
		Config:    configJSON,
	}
	if sessionName != "" {
		session.SessionName = sql.NullString{String: sessionName, Valid: true}
	}
	if _, err := r.db.NewInsert().Model(session).Exec(ctx); err != nil {
		return nil, err
	}
	return session, nil
}

// GetSessionsByName returns all sessions with matching name (for export grouping).
func (r *Repository) GetSessionsByName(ctx context.Context, name string) ([]SessionModel, error) {
	var sessions []SessionModel
	err := r.db.NewSelect().Model(&sessions).
		Where("session_name = ?", name).
		Order("started_at DESC").
		Scan(ctx)
	return sessions, err
}

// UpdateSessionEndTime updates only the end time and stats of a session
func (r *Repository) UpdateSessionEndTime(ctx context.Context, id int64, endedAt int64, stats string) error {
	_, err := r.db.NewUpdate().Model((*SessionModel)(nil)).
		Set("ended_at = ?", sql.NullInt64{Int64: endedAt, Valid: true}).
		Set("stats = ?", stats).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// GetSessionByName retrieves a session by its name (unique)
func (r *Repository) GetSessionByName(ctx context.Context, name string) (*SessionModel, error) {
	var session SessionModel
	err := r.db.NewSelect().Model(&session).
		Where("session_name = ?", name).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// ListSessions returns all sessions ordered by started_at DESC
func (r *Repository) ListSessions(ctx context.Context) ([]SessionModel, error) {
	var sessions []SessionModel
	err := r.db.NewSelect().Model(&sessions).
		Order("started_at DESC").
		Scan(ctx)
	return sessions, err
}

// Node Operations

// GetNodeByURL retrieves a node by its URL
func (r *Repository) GetNodeByURL(ctx context.Context, urlStr string) (*NodeModel, error) {
	var node NodeModel
	err := r.db.NewSelect().Model(&node).
		Where("url = ?", urlStr).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// GetNodeByID retrieves a node by its database ID
func (r *Repository) GetNodeByID(ctx context.Context, id int64) (*NodeModel, error) {
	var node NodeModel
	err := r.db.NewSelect().Model(&node).
		Where("id = ?", id).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// validSortColumns defines allowed sort columns to prevent SQL injection
var validSortColumns = map[string]string{
	"id":            "id",
	"url":           "url",
	"status_code":   "resp_status",
	"resp_status":   "resp_status",
	"mime_type":     "resp_mime",
	"resp_mime":     "resp_mime",
	"found_by":      "found_by",
	"discovered_at": "discovered_at",
}

// GetNodesPaginated returns paginated nodes with sorting and filtering
func (r *Repository) GetNodesPaginated(ctx context.Context, page, limit int, sort, order string, filters map[string]string) ([]NodeModel, int, error) {
	// Validate and set defaults
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	// Validate sort column
	sortCol, ok := validSortColumns[sort]
	if !ok {
		sortCol = "discovered_at"
	}

	// Validate sort order
	if order != "asc" && order != "ASC" {
		order = "DESC"
	} else {
		order = "ASC"
	}

	// Helper to apply filters to a query
	applyFilters := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("resp_status IS NOT NULL")

		if v, ok := filters["url"]; ok && v != "" {
			q = q.Where("url LIKE ?", "%"+v+"%")
		}

		if v, ok := filters["status"]; ok && v != "" {
			if len(v) == 3 && (v[1] == 'x' || v[1] == 'X') && (v[2] == 'x' || v[2] == 'X') {
				prefix := v[0:1]
				startCode := 0
				switch prefix {
				case "1":
					startCode = 100
				case "2":
					startCode = 200
				case "3":
					startCode = 300
				case "4":
					startCode = 400
				case "5":
					startCode = 500
				}
				q = q.Where("resp_status >= ? AND resp_status < ?", startCode, startCode+100)
			} else {
				q = q.Where("resp_status = ?", v)
			}
		}

		if v, ok := filters["mime"]; ok && v != "" {
			q = q.Where("resp_mime = ?", v)
		}

		if v, ok := filters["found_by"]; ok && v != "" {
			q = q.Where("found_by = ?", v)
		}

		if v, ok := filters["tags"]; ok && v != "" {
			q = q.Where("tags LIKE ?", "%"+v+"%")
		}

		return q
	}

	// Count total
	total, err := applyFilters(r.db.NewSelect().Model((*NodeModel)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Apply pagination and sorting (light query - no body data)
	offset := (page - 1) * limit
	var nodes []NodeModel
	err = applyFilters(r.db.NewSelect().Model(&nodes)).
		ExcludeColumn("resp_body").
		OrderExpr(fmt.Sprintf("%s %s", sortCol, order)).
		Offset(offset).Limit(limit).
		Scan(ctx)

	return nodes, total, err
}

// GetNodesBySessionID returns all nodes for a specific session
func (r *Repository) GetNodesBySessionID(ctx context.Context, sessionDBID int64) ([]NodeModel, error) {
	var nodes []NodeModel
	err := r.db.NewSelect().Model(&nodes).
		Join("JOIN session_nodes AS sn ON sn.node_id = nodes.id").
		Where("sn.session_id = ?", sessionDBID).
		Order("sn.timestamp").
		Scan(ctx)
	return nodes, err
}

// GetNewDiscoveriesBySessionID returns nodes discovered in a specific session
func (r *Repository) GetNewDiscoveriesBySessionID(ctx context.Context, sessionDBID int64) ([]NodeModel, error) {
	var nodes []NodeModel
	err := r.db.NewSelect().Model(&nodes).
		Join("JOIN session_nodes AS sn ON sn.node_id = nodes.id").
		Where("sn.session_id = ? AND sn.action = ?", sessionDBID, "discovered").
		Order("sn.timestamp").
		Scan(ctx)
	return nodes, err
}

// GetNodesSince returns nodes discovered after a timestamp
func (r *Repository) GetNodesSince(ctx context.Context, timestamp int64) ([]NodeModel, error) {
	var nodes []NodeModel
	err := r.db.NewSelect().Model(&nodes).
		Where("discovered_at > ?", timestamp).
		Order("discovered_at").
		Scan(ctx)
	return nodes, err
}

// GetFileNodesWithFingerprintAttrsBySessionID returns file nodes with fingerprint attributes
// for a specific session.
func (r *Repository) GetFileNodesWithFingerprintAttrsBySessionID(ctx context.Context, sessionID int64) ([]NodeModel, error) {
	var nodes []NodeModel
	err := r.db.NewSelect().Model(&nodes).
		Join("JOIN session_nodes AS sn ON sn.node_id = nodes.id").
		Where("sn.session_id = ? AND nodes.req_method IS NOT NULL", sessionID).
		Order("nodes.id").
		Scan(ctx)
	return nodes, err
}

// UpdateNodeTags updates the tags for a node
func (r *Repository) UpdateNodeTags(ctx context.Context, nodeID int64, tags string) error {
	_, err := r.db.NewUpdate().Model((*NodeModel)(nil)).
		Set("tags = ?", tags).
		Where("id = ?", nodeID).
		Exec(ctx)
	return err
}

// BatchUpdateSecretFindings updates secret findings for multiple nodes
// identified by URL. Each map entry is a URL → JSON-encoded findings string.
func (r *Repository) BatchUpdateSecretFindings(ctx context.Context, urlFindings map[string]string) error {
	if len(urlFindings) == 0 {
		return nil
	}
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for url, findings := range urlFindings {
			_, err := tx.NewUpdate().Model((*NodeModel)(nil)).
				Set("secret_findings = ?", findings).
				Where("url = ?", url).
				Exec(ctx)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteNodesByIDs deletes nodes and their related records
func (r *Repository) DeleteNodesByIDs(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Delete from session_nodes
		if _, err := tx.NewDelete().Model((*SessionNodeModel)(nil)).
			Where("node_id IN (?)", bun.List(ids)).
			Exec(ctx); err != nil {
			return err
		}

		// Delete the nodes
		if _, err := tx.NewDelete().Model((*NodeModel)(nil)).
			Where("id IN (?)", bun.List(ids)).
			Exec(ctx); err != nil {
			return err
		}

		return nil
	})
}

// CountNodesBySessionID returns the count of nodes for a specific session.
func (r *Repository) CountNodesBySessionID(ctx context.Context, sessionID int64) (int64, error) {
	count, err := r.db.NewSelect().Model((*NodeModel)(nil)).
		Join("JOIN session_nodes AS sn ON sn.node_id = nodes.id").
		Where("sn.session_id = ?", sessionID).
		Count(ctx)
	return int64(count), err
}

// GetLatestDiscoveredAt returns the latest discovered_at timestamp
func (r *Repository) GetLatestDiscoveredAt(ctx context.Context) (sql.NullInt64, error) {
	var result sql.NullInt64
	err := r.db.NewSelect().Model((*NodeModel)(nil)).
		ColumnExpr("MAX(discovered_at)").
		Where("resp_status IS NOT NULL").
		Scan(ctx, &result)
	return result, err
}

// Hash-Based Deduplication Operations

// GetNodeByHash returns an existing node with the same hash (for dedup check).
// Returns nil, nil if no node found.
func (r *Repository) GetNodeByHash(ctx context.Context, hash string) (*NodeModel, error) {
	if hash == "" {
		return nil, nil
	}
	var node NodeModel
	err := r.db.NewSelect().Model(&node).
		Where("hash = ?", hash).
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// Session-Node Operations

// RecordSessionNode records a session-node relationship
func (r *Repository) RecordSessionNode(ctx context.Context, sessionID, nodeID int64, action string, timestamp int64) error {
	model := &SessionNodeModel{
		SessionID: sessionID,
		NodeID:    nodeID,
		Action:    action,
		Timestamp: timestamp,
	}
	_, err := r.db.NewInsert().Model(model).
		On("CONFLICT (session_id, node_id) DO UPDATE").
		Set("action = EXCLUDED.action").
		Set("timestamp = EXCLUDED.timestamp").
		Exec(ctx)
	return err
}

// SessionNodeExists checks if a session-node relationship already exists.
func (r *Repository) SessionNodeExists(ctx context.Context, sessionID, nodeID int64) (bool, error) {
	count, err := r.db.NewSelect().Model((*SessionNodeModel)(nil)).
		Where("session_id = ? AND node_id = ?", sessionID, nodeID).
		Count(ctx)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Session Comparison Operations

// GetNewURLsBetweenSessions returns URLs in session2 not in session1
func (r *Repository) GetNewURLsBetweenSessions(ctx context.Context, sess1ID, sess2ID int64) ([]string, error) {
	var urls []string
	err := r.db.NewRaw(`
		SELECT n.url FROM nodes n
		JOIN session_nodes sn ON n.id = sn.node_id
		WHERE sn.session_id = ? AND n.id NOT IN (
			SELECT node_id FROM session_nodes WHERE session_id = ?
		)
	`, sess2ID, sess1ID).Scan(ctx, &urls)
	return urls, err
}

// GetRemovedURLsBetweenSessions returns URLs in session1 not in session2
func (r *Repository) GetRemovedURLsBetweenSessions(ctx context.Context, sess1ID, sess2ID int64) ([]string, error) {
	var urls []string
	err := r.db.NewRaw(`
		SELECT n.url FROM nodes n
		JOIN session_nodes sn ON n.id = sn.node_id
		WHERE sn.session_id = ? AND n.id NOT IN (
			SELECT node_id FROM session_nodes WHERE session_id = ?
		)
	`, sess1ID, sess2ID).Scan(ctx, &urls)
	return urls, err
}

// CountUnchangedBetweenSessions returns count of unchanged nodes between sessions
func (r *Repository) CountUnchangedBetweenSessions(ctx context.Context, sess1ID, sess2ID int64) (int, error) {
	var count int
	err := r.db.NewRaw(`
		SELECT COUNT(*) FROM session_nodes sn1
		JOIN session_nodes sn2 ON sn1.node_id = sn2.node_id
		WHERE sn1.session_id = ? AND sn2.session_id = ?
	`, sess1ID, sess2ID).Scan(ctx, &count)
	return count, err
}

// Walk Operations

// WalkAllNodes iterates over all nodes in order
func (r *Repository) WalkAllNodes(ctx context.Context, fn func(*NodeModel) error) error {
	var nodes []NodeModel
	err := r.db.NewSelect().Model(&nodes).
		Order("depth", "url").
		Scan(ctx)
	if err != nil {
		return err
	}

	for i := range nodes {
		if err := fn(&nodes[i]); err != nil {
			return err
		}
	}
	return nil
}

// WalkNodesFiltered streams nodes with optional session filter.
// If sessionName is empty, streams all nodes with resp_status.
// Calls fn for each node; return error to stop iteration.
func (r *Repository) WalkNodesFiltered(ctx context.Context, sessionName string, fn func(*NodeModel) error) error {
	var nodes []NodeModel
	var err error

	if sessionName == "" {
		// All nodes with response
		err = r.db.NewSelect().Model(&nodes).
			Where("resp_status IS NOT NULL").
			Order("discovered_at").
			Scan(ctx)
	} else {
		// Nodes from specific session(s) by name
		err = r.db.NewRaw(`
			SELECT DISTINCT n.* FROM nodes n
			JOIN session_nodes sn ON n.id = sn.node_id
			WHERE sn.session_id IN (
				SELECT id FROM sessions WHERE session_name = ?
			)
			AND n.resp_status IS NOT NULL
			ORDER BY n.discovered_at
		`, sessionName).Scan(ctx, &nodes)
	}

	if err != nil {
		return err
	}

	for i := range nodes {
		if err := fn(&nodes[i]); err != nil {
			return err
		}
	}
	return nil
}

// WalkNewNodesBetweenSessions streams nodes in newSessionName that are NOT in oldSessionName.
// Used for comparing sessions (--compare old:new).
func (r *Repository) WalkNewNodesBetweenSessions(ctx context.Context, oldSessionName, newSessionName string, fn func(*NodeModel) error) error {
	var nodes []NodeModel
	err := r.db.NewRaw(`
		SELECT n.* FROM nodes n
		JOIN session_nodes sn ON n.id = sn.node_id
		WHERE sn.session_id IN (SELECT id FROM sessions WHERE session_name = ?)
		AND n.id NOT IN (
			SELECT sn2.node_id FROM session_nodes sn2
			WHERE sn2.session_id IN (SELECT id FROM sessions WHERE session_name = ?)
		)
		AND n.resp_status IS NOT NULL
		ORDER BY n.discovered_at
	`, newSessionName, oldSessionName).Scan(ctx, &nodes)

	if err != nil {
		return err
	}

	for i := range nodes {
		if err := fn(&nodes[i]); err != nil {
			return err
		}
	}
	return nil
}

// Helper functions for converting between NodeModel and DiscoveredNode

// NodeModelToDiscoveredNode converts a NodeModel to a DiscoveredNode
func NodeModelToDiscoveredNode(m *NodeModel) *DiscoveredNode {
	parsedURL, _ := url.Parse(m.URL)
	node := NewDiscoveredNode(parsedURL)
	node.SetID(m.ID)
	node.SetNodeType(NodeType(m.NodeType))

	if m.ReqMethod.Valid {
		headers := make(map[string]string)
		if m.ReqHeaders.Valid {
			decodeStoredJSON(m.ReqHeaders.String, &headers)
		}
		req := &RequestData{
			Method:  m.ReqMethod.String,
			Headers: headers,
			Body:    m.ReqBody,
		}

		respHeadersMap := make(map[string]string)
		if m.RespHeaders.Valid {
			decodeStoredJSON(m.RespHeaders.String, &respHeadersMap)
		}
		resp := &ResponseData{
			StatusCode: int(m.RespStatus.Int64),
			Headers:    respHeadersMap,
			Body:       m.RespBody,
			MIMEType:   m.RespMime.String,
			Location:   m.RespLocation.String,
			Title:      m.RespTitle.String,
		}

		// Read ContentLength from dedicated column (body is often not saved)
		if m.RespContentLength.Valid {
			resp.ContentLength = m.RespContentLength.Int64
		}

		// Read Words and Lines from dedicated columns
		if m.RespWords.Valid {
			resp.Words = m.RespWords.Int64
		}
		if m.RespLines.Valid {
			resp.Lines = m.RespLines.Int64
		}

		// Load fingerprint attributes
		if m.FingerprintAttrs.Valid {
			var fpMap map[uint8]uint32
			if err := json.Unmarshal([]byte(m.FingerprintAttrs.String), &fpMap); err == nil {
				resp.FingerprintAttrs = fpMap
			}
		}

		meta := &DiscoveryMetadata{
			FoundBy: m.FoundBy.String,
			Depth:   uint16(m.Depth.Int64),
		}
		if m.DiscoveredAt.Valid {
			meta.Timestamp = time.Unix(m.DiscoveredAt.Int64, 0)
		}

		node.SetData(req, resp, meta)
	}

	// Load cached tags
	if m.Tags.Valid {
		var tags []string
		if err := json.Unmarshal([]byte(m.Tags.String), &tags); err == nil {
			node.SetTags(tags)
		}
	}

	// Load secret findings
	if m.SecretFindings.Valid {
		var findings []SecretFinding
		if err := json.Unmarshal([]byte(m.SecretFindings.String), &findings); err == nil {
			node.SetSecretFindings(findings)
		}
	}

	return node
}

// NodeModelToDiscoveredNodeLight converts a NodeModel to a DiscoveredNode without body data
func NodeModelToDiscoveredNodeLight(m *NodeModel) *DiscoveredNode {
	parsedURL, _ := url.Parse(m.URL)
	node := NewDiscoveredNode(parsedURL)
	node.SetID(m.ID)
	node.SetNodeType(NodeType(m.NodeType))

	if m.ReqMethod.Valid {
		headers := make(map[string]string)
		if m.ReqHeaders.Valid {
			decodeStoredJSON(m.ReqHeaders.String, &headers)
		}
		req := &RequestData{
			Method:  m.ReqMethod.String,
			Headers: headers,
			Body:    m.ReqBody,
		}

		respHeadersMap := make(map[string]string)
		if m.RespHeaders.Valid {
			decodeStoredJSON(m.RespHeaders.String, &respHeadersMap)
		}
		resp := &ResponseData{
			StatusCode: int(m.RespStatus.Int64),
			Headers:    respHeadersMap,
			MIMEType:   m.RespMime.String,
			Location:   m.RespLocation.String,
			Title:      m.RespTitle.String,
		}

		// Parse Content-Length from headers
		if clStr, ok := respHeadersMap["Content-Length"]; ok {
			if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil {
				resp.ContentLength = cl
			}
		}

		// Read Words and Lines from dedicated columns
		if m.RespWords.Valid {
			resp.Words = m.RespWords.Int64
		}
		if m.RespLines.Valid {
			resp.Lines = m.RespLines.Int64
		}

		meta := &DiscoveryMetadata{
			FoundBy: m.FoundBy.String,
			Depth:   uint16(m.Depth.Int64),
		}
		if m.DiscoveredAt.Valid {
			meta.Timestamp = time.Unix(m.DiscoveredAt.Int64, 0)
		}

		node.SetData(req, resp, meta)
	}

	// Load cached tags
	if m.Tags.Valid {
		var tags []string
		if err := json.Unmarshal([]byte(m.Tags.String), &tags); err == nil {
			node.SetTags(tags)
		}
	}

	// Load secret findings
	if m.SecretFindings.Valid {
		var findings []SecretFinding
		if err := json.Unmarshal([]byte(m.SecretFindings.String), &findings); err == nil {
			node.SetSecretFindings(findings)
		}
	}

	return node
}

// extractPath extracts the path (and query) from a URL string for spam filtering.
func extractPath(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	path := u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return path
}

// NodeModelsToDiscoveredNodes converts a slice of NodeModels to DiscoveredNodes.
// Filters out nodes with spam URLs during conversion.
func NodeModelsToDiscoveredNodes(models []NodeModel) []*DiscoveredNode {
	nodes := make([]*DiscoveredNode, 0, len(models))
	for i := range models {
		if linkfinder.IsSpamURL(extractPath(models[i].URL)) {
			continue
		}
		nodes = append(nodes, NodeModelToDiscoveredNode(&models[i]))
	}
	return nodes
}

// NodeModelsToDiscoveredNodesLight converts a slice of NodeModels to DiscoveredNodes without body data.
// Filters out nodes with spam URLs during conversion.
func NodeModelsToDiscoveredNodesLight(models []NodeModel) []*DiscoveredNode {
	nodes := make([]*DiscoveredNode, 0, len(models))
	for i := range models {
		if linkfinder.IsSpamURL(extractPath(models[i].URL)) {
			continue
		}
		nodes = append(nodes, NodeModelToDiscoveredNodeLight(&models[i]))
	}
	return nodes
}

// BuildNodeModelFromResult creates a NodeModel from a Result for insertion.
// If saveResponseBody is false, response body will not be stored.
func BuildNodeModelFromResult(resultURL *url.URL, depth int, nodeType NodeType, result *Result, maxBodySize int64, saveResponseBody bool) *NodeModel {
	node := &NodeModel{
		URL:      resultURL.String(),
		Depth:    sql.NullInt64{Int64: int64(depth), Valid: true},
		NodeType: int(nodeType),
	}

	// Trailing slash indicates directory (e.g., /admin/ vs /admin)
	isTrailingSlash := strings.HasSuffix(resultURL.Path, "/") && resultURL.Path != "/"
	isLeaf := result.Request != nil && result.Response != nil

	if isLeaf {
		// Determine final node type for leaf
		if isTrailingSlash {
			node.NodeType = int(NodeTypeDirectory)
		} else {
			node.NodeType = int(NodeTypeFile)
		}

		node.ReqMethod = sql.NullString{String: result.Request.Method, Valid: true}
		reqHeadersJSON, _ := json.Marshal(result.Request.Headers)
		node.ReqHeaders = sql.NullString{String: string(reqHeadersJSON), Valid: true}
		node.ReqBody = truncateBody(result.Request.Body, maxBodySize)

		node.RespStatus = sql.NullInt64{Int64: int64(result.Response.StatusCode), Valid: true}
		node.RespContentLength = sql.NullInt64{Int64: result.Response.ContentLength, Valid: true}
		respHeadersJSON, _ := json.Marshal(result.Response.Headers)
		node.RespHeaders = sql.NullString{String: string(respHeadersJSON), Valid: true}
		if saveResponseBody {
			node.RespBody = truncateBody(result.Response.Body, maxBodySize)
		}
		node.RespMime = sql.NullString{String: result.Response.MIMEType, Valid: true}
		node.RespLocation = sql.NullString{String: result.Response.Location, Valid: result.Response.Location != ""}
		node.RespTitle = sql.NullString{String: result.Response.Title, Valid: result.Response.Title != ""}
		node.RespWords = sql.NullInt64{Int64: result.Response.Words, Valid: result.Response.Words > 0}
		node.RespLines = sql.NullInt64{Int64: result.Response.Lines, Valid: result.Response.Lines > 0}

		if result.Metadata != nil {
			node.FoundBy = sql.NullString{String: result.Metadata.FoundBy, Valid: true}
			node.DiscoveredAt = sql.NullInt64{Int64: result.Metadata.Timestamp.Unix(), Valid: true}
		}

		// Store fingerprint attributes
		if result.FingerprintAttrs != nil {
			fpJSON, _ := json.Marshal(result.FingerprintAttrs)
			node.FingerprintAttrs = sql.NullString{String: string(fpJSON), Valid: true}
		}

		// Store tags
		if len(result.Tags) > 0 {
			tagsBytes, _ := json.Marshal(result.Tags)
			node.Tags = sql.NullString{String: string(tagsBytes), Valid: true}
		}

		// Store secret findings
		if len(result.SecretFindings) > 0 {
			findingsBytes, _ := json.Marshal(result.SecretFindings)
			node.SecretFindings = sql.NullString{String: string(findingsBytes), Valid: true}
		}
	}

	return node
}

// truncateBody truncates body if larger than maxBodySize
func truncateBody(body []byte, maxBodySize int64) []byte {
	if maxBodySize > 0 && int64(len(body)) > maxBodySize {
		return body[:maxBodySize]
	}
	return body
}

// SessionModelToSession converts a SessionModel to a Session domain object
func SessionModelToSession(m *SessionModel) *Session {
	sess := &Session{
		DBID:      m.ID,
		StartedAt: time.Unix(m.StartedAt, 0),
		TargetURL: m.TargetURL,
		Config:    m.Config,
	}
	if m.SessionName.Valid {
		sess.Name = m.SessionName.String
	}
	if m.EndedAt.Valid {
		sess.EndedAt = time.Unix(m.EndedAt.Int64, 0)
	}

	decodeStoredJSON(m.Stats, &sess.Stats)

	return sess
}

// SessionModelsToSessions converts a slice of SessionModels to Sessions
func SessionModelsToSessions(models []SessionModel) []*Session {
	sessions := make([]*Session, len(models))
	for i := range models {
		sessions[i] = SessionModelToSession(&models[i])
	}
	return sessions
}
