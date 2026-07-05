package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jsscan/linkfinder"
)

// SiteMap implements Storage using database backend with bun
type SiteMap struct {
	driver         DatabaseDriver
	bunDB          *bun.DB
	repo           *Repository
	extractionRepo *ExtractionRepository
	observedRepo   *ObservedRepository
	config         *StorageConfig
	tempPath       string     // Set if ephemeral mode (SQLite only)
	mu             sync.Mutex // Mutex for serializing writes
	ephemeral      bool

	// Session tracking
	sessionName string // User-provided name for grouping (unique when set)
	sessionDBID int64  // Database primary key of the session
	hostname    string // Extracted from TargetURL for session grouping
}

// OpenSiteMapDSN opens an existing database for querying without creating a new session.
// Supports both SQLite file paths and PostgreSQL URIs.
// Use this for read-only operations like querying past sessions.
func OpenSiteMapDSN(dsn string) (*SiteMap, error) {
	if dsn == "" {
		return nil, fmt.Errorf("database path or URI required")
	}

	// Parse DSN to determine driver type
	storageCfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid database config: %w", err)
	}

	cfg := &storageCfg.Database

	// For SQLite, check if file exists
	if cfg.Driver == DriverSQLite {
		if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("database file not found: %s", cfg.FilePath)
		}
	}

	driver := NewDriver(cfg.Driver)
	dsnStr := driver.BuildDSN(cfg)
	bunDB, err := driver.Open(dsnStr)
	if err != nil {
		return nil, err
	}

	if err := driver.ConfigurePool(bunDB, cfg); err != nil {
		_ = bunDB.Close()
		return nil, err
	}

	// Run migrations if needed
	if err := migrateSchema(context.Background(), bunDB); err != nil {
		_ = bunDB.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	s := &SiteMap{
		driver:         driver,
		bunDB:          bunDB,
		repo:           NewRepository(bunDB),
		extractionRepo: NewExtractionRepository(bunDB),
		observedRepo:   NewObservedRepository(bunDB),
		config:         storageCfg,
		ephemeral:      false,
	}

	return s, nil
}

// NewSiteMap creates a new sitemap storage with configurable database backend
func NewSiteMap(cfg *StorageConfig) (*SiteMap, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	driver := NewDriver(cfg.Database.Driver)
	var tempPath string

	// Handle ephemeral SQLite mode
	if cfg.IsEphemeral() {
		f, err := os.CreateTemp("", "sitemap-*.db")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		tempPath = f.Name()
		cfg.Database.FilePath = tempPath
		_ = f.Close()
	}

	// Ensure parent directory exists for SQLite file paths
	if cfg.Database.Driver == DriverSQLite && cfg.Database.FilePath != "" {
		if dir := filepath.Dir(cfg.Database.FilePath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
			}
		}
	}

	dsn := driver.BuildDSN(&cfg.Database)
	bunDB, err := driver.Open(dsn)
	if err != nil {
		return nil, err
	}

	if err := driver.ConfigurePool(bunDB, &cfg.Database); err != nil {
		_ = bunDB.Close()
		return nil, err
	}

	// Initialize schema
	if err := migrateSchema(context.Background(), bunDB); err != nil {
		_ = bunDB.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	s := &SiteMap{
		driver:         driver,
		bunDB:          bunDB,
		repo:           NewRepository(bunDB),
		extractionRepo: NewExtractionRepository(bunDB),
		observedRepo:   NewObservedRepository(bunDB),
		config:         cfg,
		tempPath:       tempPath,
		ephemeral:      cfg.IsEphemeral(),
		sessionName:    cfg.SessionName,
		hostname:       ExtractHostname(cfg.TargetURL),
	}

	// Get or create session (handles multi-process with same session name)
	if err := s.ensureSession(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("failed to ensure session: %w", err)
	}

	return s, nil
}

// migrateSchema creates or migrates the database schema using explicit DDL
func migrateSchema(ctx context.Context, db *bun.DB) error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_name TEXT,
			started_at INTEGER NOT NULL,
			ended_at INTEGER,
			target_url TEXT,
			config TEXT,
			stats TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL,
			depth INTEGER,
			node_type INTEGER NOT NULL,
			req_method TEXT,
			req_headers TEXT,
			req_body BLOB,
			resp_status INTEGER,
			resp_content_length INTEGER,
			resp_headers TEXT,
			resp_body BLOB,
			resp_mime TEXT,
			resp_location TEXT,
			resp_title TEXT,
			resp_words INTEGER,
			resp_lines INTEGER,
			found_by TEXT,
			discovered_at INTEGER,
			fingerprint_attrs TEXT,
			tags TEXT,
			kingfisher_findings TEXT,
			first_seen_session INTEGER,
			last_seen_session INTEGER,
			hash TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS session_nodes (
			session_id INTEGER NOT NULL,
			node_id INTEGER NOT NULL,
			action TEXT NOT NULL,
			timestamp INTEGER NOT NULL,
			PRIMARY KEY (session_id, node_id)
		)`,
		`CREATE TABLE IF NOT EXISTS extractions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_node_id INTEGER NOT NULL,
			session_id INTEGER NOT NULL,
			hash TEXT,
			source INTEGER NOT NULL,
			source_sub INTEGER DEFAULT 0,
			hostname TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT DEFAULT 'GET',
			body TEXT,
			content_type TEXT,
			headers TEXT,
			cookies TEXT,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS observed (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			type INTEGER NOT NULL,
			value TEXT NOT NULL,
			frequency INTEGER NOT NULL DEFAULT 1,
			updated_at INTEGER NOT NULL
		)`,
	}

	for _, ddl := range tables {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_sessions_name ON sessions(session_name)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_hash ON nodes(hash)",
		"CREATE INDEX IF NOT EXISTS idx_session_nodes_timestamp ON session_nodes(timestamp)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_ext_hash ON extractions(hash)",
		"CREATE INDEX IF NOT EXISTS idx_ext_hostname ON extractions(hostname)",
		"CREATE INDEX IF NOT EXISTS idx_obs_hostname ON observed(hostname)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_hostname_type_value ON observed(hostname, type, value)",
	}

	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// ensureSession creates a new session with unique ID.
// SessionName is optional metadata for grouping when exporting.
func (s *SiteMap) ensureSession() error {
	configJSON, _ := json.Marshal(map[string]any{
		"target_url":    s.config.TargetURL,
		"max_body_size": s.config.MaxBodySize,
	})

	ctx := context.Background()
	session, err := s.repo.CreateSession(
		ctx,
		s.sessionName,
		time.Now().Unix(),
		s.config.TargetURL,
		string(configJSON),
	)
	if err != nil {
		return err
	}

	s.sessionDBID = session.ID
	return nil
}

// BatchUpdateKingfisherFindings updates kingfisher findings for nodes identified by URL.
func (s *SiteMap) BatchUpdateKingfisherFindings(urlFindings map[string]string) error {
	ctx := context.Background()
	return s.repo.BatchUpdateKingfisherFindings(ctx, urlFindings)
}

// Close ends the session and releases resources
func (s *SiteMap) Close() error {
	ctx := context.Background()

	// Update session with end time and stats
	stats := s.computeStats()
	statsJSON, _ := json.Marshal(stats)
	_ = s.repo.UpdateSessionEndTime(ctx, s.sessionDBID, time.Now().Unix(), string(statsJSON))

	// Checkpoint WAL before closing for SQLite crash recovery
	if s.config != nil && s.config.Database.Driver == DriverSQLite {
		_, _ = s.bunDB.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}

	// Close database
	if err := s.bunDB.Close(); err != nil {
		return err
	}

	// Clean up temp files if ephemeral
	if s.tempPath != "" && s.driver != nil {
		_ = s.driver.CleanupFiles(s.tempPath)
	}

	return nil
}

// computeStats calculates session statistics
func (s *SiteMap) computeStats() SessionStats {
	ctx := context.Background()
	count, _ := s.repo.CountNodesBySessionID(ctx, s.sessionDBID)
	return SessionStats{
		URLsFound: int(count),
	}
}

// SessionName returns the user-provided session name for grouping
func (s *SiteMap) SessionName() string {
	return s.sessionName
}

// SessionDBID returns the current session's database ID for foreign key references.
func (s *SiteMap) SessionDBID() int64 {
	return s.sessionDBID
}

// Extractions returns the extraction repository for storing spider/jsscan/form extractions.
func (s *SiteMap) Extractions() *ExtractionRepository {
	return s.extractionRepo
}

// Observed returns the observed data repository for storing discovered filenames/extensions/paths.
func (s *SiteMap) Observed() *ObservedRepository {
	return s.observedRepo
}

// Hostname returns the hostname associated with this sitemap.
func (s *SiteMap) Hostname() string {
	return s.hostname
}

// Store adds or updates a result
func (s *SiteMap) Store(result *Result) error {
	if result == nil || result.URL == nil {
		return fmt.Errorf("invalid result: nil result or URL")
	}

	// Serialize writes to avoid database locks
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()

	// Calculate hash FIRST (primary dedup mechanism)
	var nodeHash string
	if result.Response != nil && result.Request != nil {
		serverHeader := ""
		if result.Response.Headers != nil {
			serverHeader = result.Response.Headers["Server"]
		}
		nodeHash = dedup.BuildNodeHash(
			result.URL.Scheme,
			result.URL.Host,
			result.Request.Method,
			result.Response.StatusCode,
			serverHeader,
			// Escaped (wire) path: keeps a path-normalization bypass distinct
			// ("/%23/../x" vs "/x", or the decoded "/#/../x" whose "#" would
			// otherwise strip to "/"), matching the request actually sent.
			result.URL.EscapedPath(),
			result.URL.RawQuery,
			result.Request.Body,
		)

		// Hash-based dedup check: if hash exists, determine correct action
		existingNode, _ := s.repo.GetNodeByHash(ctx, nodeHash)
		if existingNode != nil {
			// Check if this session already recorded this node
			exists, err := s.repo.SessionNodeExists(ctx, s.sessionDBID, existingNode.ID)
			if err != nil {
				return fmt.Errorf("failed to check session-node existence: %w", err)
			}

			if exists {
				// Within-session duplicate: skip
				return nil
			}

			// Node from previous session
			return s.repo.RecordSessionNode(ctx, s.sessionDBID, existingNode.ID, string(NodeActionUpdated), time.Now().Unix())
		}
	}

	// No existing hash match -> create new node
	return s.bunDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		repo := NewRepository(tx)

		// Build single node model (flat storage)
		depth := pathDepth(result.URL.Path)
		nodeModel := BuildNodeModelFromResult(result.URL, depth, NodeTypeFile, result, s.config.MaxBodySize, s.config.SaveResponseBody)
		if nodeHash != "" {
			nodeModel.Hash = sql.NullString{String: nodeHash, Valid: true}
		}
		nodeModel.FirstSeenSession = sql.NullInt64{Int64: s.sessionDBID, Valid: true}
		nodeModel.LastSeenSession = sql.NullInt64{Int64: s.sessionDBID, Valid: true}

		if _, err := tx.NewInsert().Model(nodeModel).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert node: %w", err)
		}

		// Record session-node relationship with "discovered" action
		if err := repo.RecordSessionNode(ctx, s.sessionDBID, nodeModel.ID, string(NodeActionDiscovered), time.Now().Unix()); err != nil {
			return fmt.Errorf("failed to record session-node: %w", err)
		}

		return nil
	})
}

// Get retrieves a node by URL
func (s *SiteMap) Get(u *url.URL) (*DiscoveredNode, error) {
	if u == nil {
		return nil, fmt.Errorf("invalid URL: nil")
	}

	ctx := context.Background()
	model, err := s.repo.GetNodeByURL(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("node not found: %s", u.String())
	}

	return NodeModelToDiscoveredNode(model), nil
}

// Count returns the total number of discovered URLs for the current session.
func (s *SiteMap) Count() int {
	ctx := context.Background()
	count, _ := s.repo.CountNodesBySessionID(ctx, s.sessionDBID)
	return int(count)
}

// GetLatestRecordAt returns timestamp of most recently discovered record
func (s *SiteMap) GetLatestRecordAt() *time.Time {
	ctx := context.Background()
	timestamp, err := s.repo.GetLatestDiscoveredAt(ctx)
	if err != nil || !timestamp.Valid {
		return nil
	}
	t := time.Unix(timestamp.Int64, 0)
	return &t
}

// WalkFiles traverses all file nodes (non-directory URLs)
func (s *SiteMap) WalkFiles(fn NodeCallback) error {
	ctx := context.Background()
	return s.repo.WalkAllNodes(ctx, func(m *NodeModel) error {
		if linkfinder.IsSpamURL(extractPath(m.URL)) {
			return nil
		}
		nt := NodeType(m.NodeType)
		if nt == NodeTypeFile {
			return fn(NodeModelToDiscoveredNode(m))
		}
		return nil
	})
}

// WalkDirectories traverses all directory nodes (URLs ending with /)
func (s *SiteMap) WalkDirectories(fn NodeCallback) error {
	ctx := context.Background()
	return s.repo.WalkAllNodes(ctx, func(m *NodeModel) error {
		if linkfinder.IsSpamURL(extractPath(m.URL)) {
			return nil
		}
		nt := NodeType(m.NodeType)
		if nt == NodeTypeDirectory {
			return fn(NodeModelToDiscoveredNode(m))
		}
		return nil
	})
}

// StreamAllResults streams all results through callback.
func (s *SiteMap) StreamAllResults(fn NodeCallback) error {
	ctx := context.Background()
	return s.repo.WalkNodesFiltered(ctx, "", func(m *NodeModel) error {
		if linkfinder.IsSpamURL(extractPath(m.URL)) {
			return nil
		}
		return fn(NodeModelToDiscoveredNode(m))
	})
}

// StreamResultsBySessionName streams results for a session through callback.
func (s *SiteMap) StreamResultsBySessionName(sessionName string, fn NodeCallback) error {
	ctx := context.Background()
	return s.repo.WalkNodesFiltered(ctx, sessionName, func(m *NodeModel) error {
		if linkfinder.IsSpamURL(extractPath(m.URL)) {
			return nil
		}
		return fn(NodeModelToDiscoveredNode(m))
	})
}

// StreamNewNodesSince streams nodes in newSession not in oldSession.
func (s *SiteMap) StreamNewNodesSince(oldSessionName, newSessionName string, fn NodeCallback) error {
	ctx := context.Background()
	return s.repo.WalkNewNodesBetweenSessions(ctx, oldSessionName, newSessionName, func(m *NodeModel) error {
		if linkfinder.IsSpamURL(extractPath(m.URL)) {
			return nil
		}
		return fn(NodeModelToDiscoveredNode(m))
	})
}

// GetNewDiscoveries returns URLs discovered in this session that weren't seen before
func (s *SiteMap) GetNewDiscoveries() ([]*DiscoveredNode, error) {
	ctx := context.Background()
	models, err := s.repo.GetNewDiscoveriesBySessionID(ctx, s.sessionDBID)
	if err != nil {
		return nil, err
	}
	return NodeModelsToDiscoveredNodes(models), nil
}

// ListSessions returns all sessions in the database
func (s *SiteMap) ListSessions() ([]*Session, error) {
	ctx := context.Background()
	models, err := s.repo.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	return SessionModelsToSessions(models), nil
}

// CompareSessions returns the differences between two sessions by name
func (s *SiteMap) CompareSessions(session1Name, session2Name string) (*SessionDiff, error) {
	ctx := context.Background()
	diff := &SessionDiff{
		Session1ID: session1Name,
		Session2ID: session2Name,
	}

	sess1, err := s.repo.GetSessionByName(ctx, session1Name)
	if err != nil {
		return nil, fmt.Errorf("session1 not found: %s", session1Name)
	}
	sess2, err := s.repo.GetSessionByName(ctx, session2Name)
	if err != nil {
		return nil, fmt.Errorf("session2 not found: %s", session2Name)
	}

	diff.NewURLs, err = s.repo.GetNewURLsBetweenSessions(ctx, sess1.ID, sess2.ID)
	if err != nil {
		return nil, err
	}

	diff.RemovedURLs, err = s.repo.GetRemovedURLsBetweenSessions(ctx, sess1.ID, sess2.ID)
	if err != nil {
		return nil, err
	}

	diff.UnchangedCnt, err = s.repo.CountUnchangedBetweenSessions(ctx, sess1.ID, sess2.ID)
	if err != nil {
		return nil, err
	}

	return diff, nil
}

// TagAnalyzerFunc defines a function that analyzes a node and returns tags.
type TagAnalyzerFunc func(node *DiscoveredNode) []string

// UpdateNodeTagsByURL updates the cached tags for a single node identified by URL.
func (s *SiteMap) UpdateNodeTagsByURL(urlStr string, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	model, err := s.repo.GetNodeByURL(ctx, urlStr)
	if err != nil {
		return fmt.Errorf("node not found: %s", urlStr)
	}

	var tagsJSON string
	if len(tags) == 0 {
		tagsJSON = "[]"
	} else {
		tagsBytes, _ := json.Marshal(tags)
		tagsJSON = string(tagsBytes)
	}

	return s.repo.UpdateNodeTags(ctx, model.ID, tagsJSON)
}

// RecomputeTags re-analyzes all nodes in a session and updates cached tags in the database.
func (s *SiteMap) RecomputeTags(sessionName string, analyzeFunc TagAnalyzerFunc) error {
	ctx := context.Background()
	session, err := s.repo.GetSessionByName(ctx, sessionName)
	if err != nil {
		return fmt.Errorf("session not found: %s", sessionName)
	}

	models, err := s.repo.GetNodesBySessionID(ctx, session.ID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.bunDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		repo := NewRepository(tx)

		for i := range models {
			if linkfinder.IsSpamURL(extractPath(models[i].URL)) {
				continue
			}
			node := NodeModelToDiscoveredNode(&models[i])
			tags := analyzeFunc(node)

			var tagsJSON string
			if len(tags) == 0 {
				tagsJSON = "[]"
			} else {
				tagsBytes, _ := json.Marshal(tags)
				tagsJSON = string(tagsBytes)
			}

			if err := repo.UpdateNodeTags(ctx, models[i].ID, tagsJSON); err != nil {
				return fmt.Errorf("failed to update tags for node %d: %w", models[i].ID, err)
			}
		}

		return nil
	})
}

// NodeWithID pairs a DiscoveredNode with its database ID for anomaly filtering
type NodeWithID struct {
	ID   int64
	Node *DiscoveredNode
}

// GetFileNodesWithIDs returns all file nodes with their database IDs for the current session.
func (s *SiteMap) GetFileNodesWithIDs() ([]NodeWithID, error) {
	ctx := context.Background()
	models, err := s.repo.GetFileNodesWithFingerprintAttrsBySessionID(ctx, s.sessionDBID)
	if err != nil {
		return nil, fmt.Errorf("failed to query file nodes: %w", err)
	}

	result := make([]NodeWithID, 0, len(models))
	for i := range models {
		if linkfinder.IsSpamURL(extractPath(models[i].URL)) {
			continue
		}
		result = append(result, NodeWithID{
			ID:   models[i].ID,
			Node: NodeModelToDiscoveredNode(&models[i]),
		})
	}

	return result, nil
}

// DeleteNodesByIDs deletes multiple nodes in a single transaction.
func (s *SiteMap) DeleteNodesByIDs(nodeIDs []int64) error {
	if len(nodeIDs) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	return s.repo.DeleteNodesByIDs(ctx, nodeIDs)
}

// GetSessionByName returns the session with a specific name (unique)
func (s *SiteMap) GetSessionByName(name string) (*Session, error) {
	ctx := context.Background()
	model, err := s.repo.GetSessionByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return SessionModelToSession(model), nil
}

// pathDepth returns the depth of a URL path (number of segments).
func pathDepth(p string) int {
	if p == "" || p == "/" {
		return 0
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}
