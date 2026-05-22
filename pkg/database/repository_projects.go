package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
)

// --- User CRUD ---

// CreateUser inserts a new user.
func (r *Repository) CreateUser(ctx context.Context, user *User) error {
	if user == nil {
		return fmt.Errorf("invalid User")
	}
	if _, err := r.db.NewInsert().Model(user).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}
	return nil
}

// GetUserByUUID retrieves a user by UUID.
func (r *Repository) GetUserByUUID(ctx context.Context, uuid string) (*User, error) {
	user := &User{}
	err := r.db.NewSelect().Model(user).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ListUsers returns all users.
func (r *Repository) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	err := r.db.NewSelect().Model(&users).Order("created_at ASC").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	return users, nil
}

// UpsertUser inserts a new user or updates name/email if the UUID already exists.
// Returns the user's UUID.
func (r *Repository) UpsertUser(ctx context.Context, user *User) error {
	if user == nil || user.UUID == "" {
		return fmt.Errorf("invalid User: UUID is required")
	}
	q := r.db.NewInsert().Model(user).
		On("CONFLICT (uuid) DO UPDATE").
		Set("name = EXCLUDED.name").
		Set("email = EXCLUDED.email").
		Set("updated_at = CURRENT_TIMESTAMP")
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("failed to upsert user: %w", err)
	}
	return nil
}

// --- Project CRUD ---

// CreateProject inserts a new project.
func (r *Repository) CreateProject(ctx context.Context, project *Project) error {
	if project == nil {
		return fmt.Errorf("invalid Project")
	}
	if _, err := r.db.NewInsert().Model(project).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert project: %w", err)
	}
	return nil
}

// GetProjectByUUID retrieves a project by UUID.
func (r *Repository) GetProjectByUUID(ctx context.Context, uuid string) (*Project, error) {
	project := &Project{}
	err := r.db.NewSelect().Model(project).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return project, nil
}

// GetProjectByName retrieves a project by name. Returns an error if zero or
// multiple projects match (names are not guaranteed to be unique).
func (r *Repository) GetProjectByName(ctx context.Context, name string) (*Project, error) {
	var projects []*Project
	err := r.db.NewSelect().Model(&projects).Where("name = ?", name).Limit(2).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query project by name: %w", err)
	}
	switch len(projects) {
	case 0:
		return nil, fmt.Errorf("no project found with name %q", name)
	case 1:
		return projects[0], nil
	default:
		return nil, fmt.Errorf("multiple projects (%d) found with name %q; use --project-uuid to specify by UUID", len(projects), name)
	}
}

// ListProjects returns projects, optionally filtered by owner.
func (r *Repository) ListProjects(ctx context.Context, ownerUUID string) ([]*Project, error) {
	var projects []*Project
	q := r.db.NewSelect().Model(&projects).Order("created_at ASC")
	if ownerUUID != "" {
		q = q.Where("owner_uuid = ?", ownerUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	return projects, nil
}

// UpdateProject updates an existing project.
func (r *Repository) UpdateProject(ctx context.Context, project *Project) error {
	if project == nil {
		return fmt.Errorf("invalid Project")
	}
	if _, err := r.db.NewUpdate().Model(project).WherePK().Exec(ctx); err != nil {
		return fmt.Errorf("failed to update project: %w", err)
	}
	return nil
}

// ReassignProjectData moves all data owned by sourceUUID to targetUUID.
// This should be called before deleting a project so its records are not orphaned.
func (r *Repository) ReassignProjectData(ctx context.Context, sourceUUID, targetUUID string) error {
	tables := []string{"scans", "http_records", "findings", "scopes", "oast_interactions", "scan_logs"}
	for _, table := range tables {
		_, err := r.db.ExecContext(ctx,
			fmt.Sprintf("UPDATE %s SET project_uuid = ? WHERE project_uuid = ?", table),
			targetUUID, sourceUUID)
		if err != nil {
			return fmt.Errorf("failed to reassign %s: %w", table, err)
		}
	}
	return nil
}

// DeleteProject deletes a project by UUID.
func (r *Repository) DeleteProject(ctx context.Context, uuid string) error {
	_, err := r.db.NewDelete().Model((*Project)(nil)).Where("uuid = ?", uuid).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	return nil
}

// PurgeProjectData deletes every row tied to projectUUID across all per-project
// tables. finding_records has no project_uuid, so it's pruned via a subquery on
// findings.id before the findings rows themselves are removed. Runs in a single
// transaction so a partial failure leaves the project intact.
func (r *Repository) PurgeProjectData(ctx context.Context, projectUUID string) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().
			TableExpr("finding_records").
			Where("finding_id IN (SELECT id FROM findings WHERE project_uuid = ?)", projectUUID).
			Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		tables := []string{
			"findings",
			"http_records",
			"scans",
			"scopes",
			"oast_interactions",
			"agentic_scans",
			"authentication_hostnames",
			"scan_logs",
		}
		for _, table := range tables {
			if _, err := tx.ExecContext(ctx,
				fmt.Sprintf("DELETE FROM %s WHERE project_uuid = ?", table),
				projectUUID); err != nil {
				return fmt.Errorf("failed to purge %s: %w", table, err)
			}
		}
		return nil
	})
}

// ProjectStatsRow holds per-project aggregated counts used by GetAllProjectsStats.
type ProjectStatsRow struct {
	ProjectUUID      string `bun:"project_uuid"`
	HTTPRecords      int64  `bun:"http_records"`
	HTTP2xx          int64  `bun:"http_2xx"`
	HTTP3xx          int64  `bun:"http_3xx"`
	HTTP4xx          int64  `bun:"http_4xx"`
	HTTP5xx          int64  `bun:"http_5xx"`
	Findings         int64  `bun:"findings"`
	Critical         int64  `bun:"critical"`
	High             int64  `bun:"high"`
	Medium           int64  `bun:"medium"`
	Low              int64  `bun:"low"`
	Info             int64  `bun:"info"`
	Scans            int64  `bun:"scans"`
	AgenticScans     int64  `bun:"agentic_scans"`
	OASTInteractions int64  `bun:"oast_interactions"`
}

// GetProjectStats returns aggregated stats for a single project.
func (r *Repository) GetProjectStats(ctx context.Context, projectUUID string) (*ProjectStatsRow, error) {
	stats := &ProjectStatsRow{ProjectUUID: projectUUID}

	// HTTP records with status breakdown
	type httpRow struct {
		Total   int64 `bun:"total"`
		HTTP2xx int64 `bun:"http_2xx"`
		HTTP3xx int64 `bun:"http_3xx"`
		HTTP4xx int64 `bun:"http_4xx"`
		HTTP5xx int64 `bun:"http_5xx"`
	}
	var hr httpRow
	err := r.db.NewSelect().Model((*HTTPRecord)(nil)).
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS http_2xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS http_3xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS http_4xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS http_5xx").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &hr)
	if err != nil {
		return nil, fmt.Errorf("http record stats: %w", err)
	}
	stats.HTTPRecords = hr.Total
	stats.HTTP2xx = hr.HTTP2xx
	stats.HTTP3xx = hr.HTTP3xx
	stats.HTTP4xx = hr.HTTP4xx
	stats.HTTP5xx = hr.HTTP5xx

	// Findings with severity breakdown
	type findingRow struct {
		Total    int64 `bun:"total"`
		Critical int64 `bun:"critical"`
		High     int64 `bun:"high"`
		Medium   int64 `bun:"medium"`
		Low      int64 `bun:"low"`
		Info     int64 `bun:"info"`
	}
	var fr findingRow
	err = r.db.NewSelect().Model((*Finding)(nil)).
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical").
		ColumnExpr("SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high").
		ColumnExpr("SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium").
		ColumnExpr("SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low").
		ColumnExpr("SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS info").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &fr)
	if err != nil {
		return nil, fmt.Errorf("finding stats: %w", err)
	}
	stats.Findings = fr.Total
	stats.Critical = fr.Critical
	stats.High = fr.High
	stats.Medium = fr.Medium
	stats.Low = fr.Low
	stats.Info = fr.Info

	// Scans
	scanCount, err := r.db.NewSelect().Model((*Scan)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan count: %w", err)
	}
	stats.Scans = int64(scanCount)

	// Agent runs
	agentCount, err := r.db.NewSelect().Model((*AgenticScan)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent run count: %w", err)
	}
	stats.AgenticScans = int64(agentCount)

	// OAST interactions
	oastCount, err := r.db.NewSelect().Model((*OASTInteraction)(nil)).Where("project_uuid = ?", projectUUID).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("oast count: %w", err)
	}
	stats.OASTInteractions = int64(oastCount)

	return stats, nil
}

// GetAllProjectsStats returns aggregated stats for all projects in bulk.
// Uses GROUP BY to avoid N+1 queries when listing projects.
func (r *Repository) GetAllProjectsStats(ctx context.Context) (map[string]*ProjectStatsRow, error) {
	result := make(map[string]*ProjectStatsRow)

	// HTTP records with status breakdown
	type httpGroupRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Total       int64  `bun:"total"`
		HTTP2xx     int64  `bun:"http_2xx"`
		HTTP3xx     int64  `bun:"http_3xx"`
		HTTP4xx     int64  `bun:"http_4xx"`
		HTTP5xx     int64  `bun:"http_5xx"`
	}
	var httpRows []httpGroupRow
	err := r.db.NewSelect().Model((*HTTPRecord)(nil)).
		Column("project_uuid").
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS http_2xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS http_3xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS http_4xx").
		ColumnExpr("SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS http_5xx").
		Group("project_uuid").
		Scan(ctx, &httpRows)
	if err != nil {
		return nil, fmt.Errorf("http record stats: %w", err)
	}
	for _, row := range httpRows {
		s := getOrCreate(result, row.ProjectUUID)
		s.HTTPRecords = row.Total
		s.HTTP2xx = row.HTTP2xx
		s.HTTP3xx = row.HTTP3xx
		s.HTTP4xx = row.HTTP4xx
		s.HTTP5xx = row.HTTP5xx
	}

	// Findings with severity breakdown
	type findingGroupRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Total       int64  `bun:"total"`
		Critical    int64  `bun:"critical"`
		High        int64  `bun:"high"`
		Medium      int64  `bun:"medium"`
		Low         int64  `bun:"low"`
		Info        int64  `bun:"info"`
	}
	var findingRows []findingGroupRow
	err = r.db.NewSelect().Model((*Finding)(nil)).
		Column("project_uuid").
		ColumnExpr("COUNT(*) AS total").
		ColumnExpr("SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical").
		ColumnExpr("SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high").
		ColumnExpr("SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium").
		ColumnExpr("SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low").
		ColumnExpr("SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS info").
		Group("project_uuid").
		Scan(ctx, &findingRows)
	if err != nil {
		return nil, fmt.Errorf("finding stats: %w", err)
	}
	for _, row := range findingRows {
		s := getOrCreate(result, row.ProjectUUID)
		s.Findings = row.Total
		s.Critical = row.Critical
		s.High = row.High
		s.Medium = row.Medium
		s.Low = row.Low
		s.Info = row.Info
	}

	// Simple counts: scans, agentic_scans, oast_interactions
	type countRow struct {
		ProjectUUID string `bun:"project_uuid"`
		Count       int64  `bun:"count"`
	}

	tables := []struct {
		model interface{}
		field string
	}{
		{(*Scan)(nil), "scans"},
		{(*AgenticScan)(nil), "agentic_scans"},
		{(*OASTInteraction)(nil), "oast_interactions"},
	}

	for _, t := range tables {
		var rows []countRow
		err = r.db.NewSelect().
			TableExpr("(?) AS sub",
				r.db.NewSelect().Model(t.model).
					Column("project_uuid").
					ColumnExpr("COUNT(*) AS count").
					Group("project_uuid"),
			).Scan(ctx, &rows)
		if err != nil {
			return nil, fmt.Errorf("%s stats: %w", t.field, err)
		}
		for _, row := range rows {
			s := getOrCreate(result, row.ProjectUUID)
			switch t.field {
			case "scans":
				s.Scans = row.Count
			case "agentic_scans":
				s.AgenticScans = row.Count
			case "oast_interactions":
				s.OASTInteractions = row.Count
			}
		}
	}

	return result, nil
}

// getOrCreate returns an existing ProjectStatsRow for the UUID or creates a new one.
func getOrCreate(m map[string]*ProjectStatsRow, uuid string) *ProjectStatsRow {
	if s, ok := m[uuid]; ok {
		return s
	}
	s := &ProjectStatsRow{ProjectUUID: uuid}
	m[uuid] = s
	return s
}
