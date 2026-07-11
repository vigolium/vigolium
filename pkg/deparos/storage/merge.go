package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// MergeStats tracks merge operation statistics
type MergeStats struct {
	SessionsMerged        int
	SessionsSkipped       int
	NodesMerged           int
	NodesDeduped          int
	NodesUpdated          int
	SessionNodesMerged    int
	ExtractionsMerged     int
	SourceArtifactsMerged int
	ObservedMerged        int
}

// DBMerger handles database merging operations
type DBMerger struct {
	dst       *bun.DB
	batchSize int
	verbose   bool

	// ID mappings (cleared for each source DB)
	sessionMap map[int64]int64 // srcSessionDBID -> dstSessionDBID
	nodeMap    map[int64]int64 // srcNodeID -> dstNodeID
}

// NewDBMerger creates a new merger for the destination database
func NewDBMerger(dstPath string, batchSize int, verbose bool) (*DBMerger, error) {
	// Open destination database with WAL mode
	dsn := fmt.Sprintf("%s?_journal=WAL&_timeout=5000&_sync=NORMAL", dstPath)

	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open destination database: %w", err)
	}

	db := bun.NewDB(sqldb, sqlitedialect.New())
	if verbose {
		db.AddQueryHook(bundebug{})
	}

	// Configure connection pool
	sqldb.SetMaxOpenConns(1) // SQLite only supports one writer
	sqldb.SetMaxIdleConns(1)

	// Run migrations to ensure schema exists
	ctx := context.Background()
	if err := migrateSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return &DBMerger{
		dst:        db,
		batchSize:  batchSize,
		verbose:    verbose,
		sessionMap: make(map[int64]int64),
		nodeMap:    make(map[int64]int64),
	}, nil
}

// bundebug is a minimal query hook for verbose logging (no-op for now).
type bundebug struct{}

func (bundebug) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

func (bundebug) AfterQuery(ctx context.Context, event *bun.QueryEvent) {}

// Close closes the destination database
func (m *DBMerger) Close() error {
	return m.dst.Close()
}

// MergeFrom merges a single source database into the destination
func (m *DBMerger) MergeFrom(srcPath string) (*MergeStats, error) {
	stats := &MergeStats{}
	ctx := context.Background()

	// Attach source database
	attachSQL := fmt.Sprintf("ATTACH DATABASE '%s' AS src", srcPath)
	if _, err := m.dst.ExecContext(ctx, attachSQL); err != nil {
		return nil, fmt.Errorf("attach database %s: %w", srcPath, err)
	}
	defer m.dst.ExecContext(ctx, "DETACH DATABASE src") //nolint:errcheck

	// Clear ID mappings for this source
	m.sessionMap = make(map[int64]int64)
	m.nodeMap = make(map[int64]int64)

	// Merge in dependency order
	if err := m.mergeSessions(ctx, stats); err != nil {
		return stats, fmt.Errorf("merge sessions: %w", err)
	}

	if err := m.mergeNodes(ctx, stats); err != nil {
		return stats, fmt.Errorf("merge nodes: %w", err)
	}

	if err := m.mergeSessionNodes(ctx, stats); err != nil {
		return stats, fmt.Errorf("merge session_nodes: %w", err)
	}

	if err := m.mergeExtractions(ctx, stats); err != nil {
		return stats, fmt.Errorf("merge extractions: %w", err)
	}

	if err := m.mergeJSTangleSourceArtifacts(ctx, stats); err != nil {
		return stats, fmt.Errorf("merge jstangle source artifacts: %w", err)
	}

	if err := m.mergeObserved(ctx, stats); err != nil {
		return stats, fmt.Errorf("merge observed: %w", err)
	}

	return stats, nil
}

// mergeSessions merges sessions from source to destination
// New schema: sessions use session_name as unique identifier (NULL for anonymous)
func (m *DBMerger) mergeSessions(ctx context.Context, stats *MergeStats) error {
	// Get all sessions from source
	var srcSessions []struct {
		ID          int64          `bun:"id"`
		SessionName sql.NullString `bun:"session_name"`
		StartedAt   int64          `bun:"started_at"`
		EndedAt     sql.NullInt64  `bun:"ended_at"`
		TargetURL   string         `bun:"target_url"`
		Config      string         `bun:"config"`
		Stats       string         `bun:"stats"`
	}

	err := m.dst.NewRaw(`
		SELECT id, session_name, started_at, ended_at, target_url, config, stats
		FROM src.sessions
	`).Scan(ctx, &srcSessions)
	if err != nil {
		return err
	}

	for _, src := range srcSessions {
		var dstID int64

		if src.SessionName.Valid && src.SessionName.String != "" {
			// Named session: use UPSERT with session_name as key
			err := m.dst.NewRaw(`
				INSERT INTO sessions (session_name, started_at, ended_at, target_url, config, stats)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT(session_name) DO UPDATE SET
					ended_at = COALESCE(sessions.ended_at, EXCLUDED.ended_at),
					target_url = COALESCE(NULLIF(sessions.target_url, ''), EXCLUDED.target_url),
					config = COALESCE(NULLIF(sessions.config, ''), EXCLUDED.config),
					stats = COALESCE(NULLIF(sessions.stats, ''), EXCLUDED.stats)
				RETURNING id
			`, src.SessionName, src.StartedAt, src.EndedAt, src.TargetURL, src.Config, src.Stats).Scan(ctx, &dstID)

			if err != nil {
				return fmt.Errorf("upsert session %s: %w", src.SessionName.String, err)
			}
		} else {
			// Anonymous session: always create new (NULL session_name)
			err := m.dst.NewRaw(`
				INSERT INTO sessions (session_name, started_at, ended_at, target_url, config, stats)
				VALUES (NULL, ?, ?, ?, ?, ?)
				RETURNING id
			`, src.StartedAt, src.EndedAt, src.TargetURL, src.Config, src.Stats).Scan(ctx, &dstID)

			if err != nil {
				return fmt.Errorf("insert anonymous session: %w", err)
			}
		}

		stats.SessionsMerged++
		m.sessionMap[src.ID] = dstID
	}

	return nil
}

// mergeNodes merges nodes from source to destination using hash-based deduplication.
// Deduplication is enforced by UNIQUE INDEX on hash column via ON CONFLICT.
func (m *DBMerger) mergeNodes(ctx context.Context, stats *MergeStats) error {
	// Get all nodes ordered by id
	var srcNodes []NodeModel
	err := m.dst.NewRaw(`
		SELECT * FROM src.nodes ORDER BY id ASC
	`).Scan(ctx, &srcNodes)
	if err != nil {
		return err
	}

	for _, src := range srcNodes {
		// Remap session IDs
		var dstFirstSeenSession, dstLastSeenSession any
		if src.FirstSeenSession.Valid {
			if mapped, ok := m.sessionMap[src.FirstSeenSession.Int64]; ok {
				dstFirstSeenSession = mapped
			}
		}
		if src.LastSeenSession.Valid {
			if mapped, ok := m.sessionMap[src.LastSeenSession.Int64]; ok {
				dstLastSeenSession = mapped
			}
		}

		// INSERT with ON CONFLICT(hash) DO NOTHING
		// RETURNING id returns NULL when conflict occurs
		var dstID sql.NullInt64
		err := m.dst.NewRaw(`
			INSERT INTO nodes (
				url, depth, node_type,
				req_method, req_headers, req_body,
				resp_status, resp_headers, resp_body, resp_mime, resp_location, resp_title,
				found_by, discovered_at,
				fingerprint_attrs, tags, secret_findings, hash, first_seen_session, last_seen_session
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(hash) DO NOTHING
			RETURNING id
		`,
			src.URL, src.Depth, src.NodeType,
			src.ReqMethod, src.ReqHeaders, src.ReqBody,
			src.RespStatus, src.RespHeaders, src.RespBody, src.RespMime, src.RespLocation, src.RespTitle,
			src.FoundBy, src.DiscoveredAt,
			src.FingerprintAttrs, src.Tags, src.SecretFindings, src.Hash, dstFirstSeenSession, dstLastSeenSession,
		).Scan(ctx, &dstID)

		if err != nil {
			return fmt.Errorf("insert node %s: %w", src.URL, err)
		}

		if dstID.Valid {
			// Insert succeeded - new node
			m.nodeMap[src.ID] = dstID.Int64
			stats.NodesMerged++
		} else {
			// Conflict - node already exists, lookup ID for mapping
			var existingID int64
			_ = m.dst.NewRaw(`SELECT id FROM nodes WHERE hash = ?`, src.Hash).Scan(ctx, &existingID)
			if existingID > 0 {
				m.nodeMap[src.ID] = existingID
			}
			stats.NodesDeduped++
		}
	}

	return nil
}

// mergeSessionNodes merges session-node relationships
func (m *DBMerger) mergeSessionNodes(ctx context.Context, stats *MergeStats) error {
	var srcSessionNodes []struct {
		SessionID int64  `bun:"session_id"`
		NodeID    int64  `bun:"node_id"`
		Action    string `bun:"action"`
		Timestamp int64  `bun:"timestamp"`
	}

	err := m.dst.NewRaw(`SELECT session_id, node_id, action, timestamp FROM src.session_nodes`).Scan(ctx, &srcSessionNodes)
	if err != nil {
		return err
	}

	for _, src := range srcSessionNodes {
		dstSessionID, ok1 := m.sessionMap[src.SessionID]
		dstNodeID, ok2 := m.nodeMap[src.NodeID]

		if !ok1 || !ok2 {
			continue // Skip if mapping not found
		}

		if _, err := m.dst.ExecContext(ctx, `
			INSERT INTO session_nodes (session_id, node_id, action, timestamp)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(session_id, node_id) DO UPDATE SET
				action = EXCLUDED.action,
				timestamp = EXCLUDED.timestamp
		`, dstSessionID, dstNodeID, src.Action, src.Timestamp); err != nil {
			return err
		}
		stats.SessionNodesMerged++
	}

	return nil
}

// mergeExtractions merges extractions (spider links, jstangle, forms)
func (m *DBMerger) mergeExtractions(ctx context.Context, stats *MergeStats) error {
	var srcExtractions []ExtractionModel

	err := m.dst.NewRaw(`SELECT * FROM src.extractions`).Scan(ctx, &srcExtractions)
	if err != nil {
		return err
	}

	for _, src := range srcExtractions {
		dstSourceNodeID, ok1 := m.nodeMap[src.SourceNodeID]
		dstSessionID, ok2 := m.sessionMap[src.SessionID]

		if !ok1 || !ok2 {
			continue
		}

		// INSERT OR IGNORE based on hash unique constraint
		res, err := m.dst.ExecContext(ctx, `
			INSERT OR IGNORE INTO extractions (
				source_node_id, session_id, hash, source, source_sub,
				hostname, url, method, body, content_type, headers, cookies,
				source_url, record_kind, confidence, extractor, module_path,
				source_line, template_json, schema_version, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, dstSourceNodeID, dstSessionID, src.Hash, src.Source, src.SourceSub,
			src.Hostname, src.URL, src.Method, src.Body, src.ContentType,
			src.Headers, src.Cookies, src.SourceURL, src.RecordKind, src.Confidence,
			src.Extractor, src.ModulePath, src.SourceLine, src.TemplateJSON,
			src.SchemaVersion, src.CreatedAt)

		if err != nil {
			return err
		}
		if rowsAffected, _ := res.RowsAffected(); rowsAffected > 0 {
			stats.ExtractionsMerged++
		}
	}

	return nil
}

// mergeJSTangleSourceArtifacts retains recovered source-map content when worker
// databases are combined. Older source databases legitimately lack the
// additive table and are treated as having no artifacts.
func (m *DBMerger) mergeJSTangleSourceArtifacts(ctx context.Context, stats *MergeStats) error {
	var tableCount int
	if err := m.dst.NewRaw(`SELECT COUNT(*) FROM src.sqlite_master WHERE type = 'table' AND name = 'jstangle_source_artifacts'`).Scan(ctx, &tableCount); err != nil {
		return err
	}
	if tableCount == 0 {
		return nil
	}

	var artifacts []JSTangleSourceArtifactModel
	if err := m.dst.NewRaw(`SELECT * FROM src.jstangle_source_artifacts`).Scan(ctx, &artifacts); err != nil {
		return err
	}
	for _, artifact := range artifacts {
		dstSessionID, sessionOK := m.sessionMap[artifact.SessionID]
		dstSourceNodeID, nodeOK := m.nodeMap[artifact.SourceNodeID]
		if !sessionOK || !nodeOK {
			continue
		}
		hash := sourceArtifactHash(dstSessionID, artifact.GeneratedURL, artifact.SourcePath, artifact.ContentSHA256)
		res, err := m.dst.ExecContext(ctx, `
			INSERT OR IGNORE INTO jstangle_source_artifacts (
				source_node_id, session_id, hash, generated_url, virtual_url,
				source_path, language, content_sha256, content, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, dstSourceNodeID, dstSessionID, hash, artifact.GeneratedURL, artifact.VirtualURL,
			artifact.SourcePath, artifact.Language, artifact.ContentSHA256, artifact.Content, artifact.CreatedAt)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			stats.SourceArtifactsMerged++
		}
	}
	return nil
}

// mergeObserved merges observed data with MAX frequency logic
func (m *DBMerger) mergeObserved(ctx context.Context, stats *MergeStats) error {
	var srcObserved []ObservedModel

	err := m.dst.NewRaw(`SELECT * FROM src.observed`).Scan(ctx, &srcObserved)
	if err != nil {
		return err
	}

	for _, src := range srcObserved {
		if _, err := m.dst.ExecContext(ctx, `
			INSERT INTO observed (hostname, type, value, frequency, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(hostname, type, value) DO UPDATE SET
				frequency = MAX(EXCLUDED.frequency, observed.frequency),
				updated_at = MAX(EXCLUDED.updated_at, observed.updated_at)
		`, src.Hostname, src.Type, src.Value, src.Frequency, src.UpdatedAt); err != nil {
			return err
		}
		stats.ObservedMerged++
	}

	return nil
}
