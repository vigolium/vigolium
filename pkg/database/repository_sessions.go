package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// SaveSessionHostname upserts a single session hostname record.
// Conflict key: (project_uuid, hostname, session_name).
func (r *Repository) SaveSessionHostname(ctx context.Context, sh *SessionHostname) error {
	if sh == nil {
		return fmt.Errorf("invalid SessionHostname")
	}
	sh.ProjectUUID = defaultProjectUUID(sh.ProjectUUID)
	now := time.Now()
	sh.CreatedAt = now
	sh.UpdatedAt = now

	_, err := r.db.NewInsert().Model(sh).
		On("CONFLICT (project_uuid, hostname, session_name) DO UPDATE").
		Set("scan_uuid = EXCLUDED.scan_uuid").
		Set("session_role = EXCLUDED.session_role").
		Set("position = EXCLUDED.position").
		Set("session_token = EXCLUDED.session_token").
		Set("headers = EXCLUDED.headers").
		Set("login_url = EXCLUDED.login_url").
		Set("login_method = EXCLUDED.login_method").
		Set("login_content_type = EXCLUDED.login_content_type").
		Set("login_body = EXCLUDED.login_body").
		Set("login_request = EXCLUDED.login_request").
		Set("login_response = EXCLUDED.login_response").
		Set("extract_rules = EXCLUDED.extract_rules").
		Set("source = EXCLUDED.source").
		Set("hydrated_at = EXCLUDED.hydrated_at").
		Set("updated_at = CURRENT_TIMESTAMP").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to upsert session hostname: %w", err)
	}
	return nil
}

// SaveSessionHostnames batch-upserts session hostname records in a transaction.
func (r *Repository) SaveSessionHostnames(ctx context.Context, rows []*SessionHostname) error {
	if len(rows) == 0 {
		return nil
	}
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, sh := range rows {
			sh.ProjectUUID = defaultProjectUUID(sh.ProjectUUID)
			now := time.Now()
			sh.CreatedAt = now
			sh.UpdatedAt = now

			_, err := tx.NewInsert().Model(sh).
				On("CONFLICT (project_uuid, hostname, session_name) DO UPDATE").
				Set("scan_uuid = EXCLUDED.scan_uuid").
				Set("session_role = EXCLUDED.session_role").
				Set("position = EXCLUDED.position").
				Set("session_token = EXCLUDED.session_token").
				Set("headers = EXCLUDED.headers").
				Set("login_url = EXCLUDED.login_url").
				Set("login_method = EXCLUDED.login_method").
				Set("login_content_type = EXCLUDED.login_content_type").
				Set("login_body = EXCLUDED.login_body").
				Set("login_request = EXCLUDED.login_request").
				Set("login_response = EXCLUDED.login_response").
				Set("extract_rules = EXCLUDED.extract_rules").
				Set("source = EXCLUDED.source").
				Set("hydrated_at = EXCLUDED.hydrated_at").
				Set("updated_at = CURRENT_TIMESTAMP").
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to upsert session hostname %q: %w", sh.SessionName, err)
			}
		}
		return nil
	})
}

// GetSessionHostnamesByHostname returns session hostnames for a project+hostname, ordered by position.
func (r *Repository) GetSessionHostnamesByHostname(ctx context.Context, projectUUID, hostname string) ([]*SessionHostname, error) {
	var rows []*SessionHostname
	err := r.db.NewSelect().
		Model(&rows).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", hostname).
		Order("position ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session hostnames: %w", err)
	}
	return rows, nil
}

// GetSessionHostnamesByProject returns all session hostnames for a project, ordered by hostname then position.
func (r *Repository) GetSessionHostnamesByProject(ctx context.Context, projectUUID string) ([]*SessionHostname, error) {
	var rows []*SessionHostname
	err := r.db.NewSelect().
		Model(&rows).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Order("hostname ASC", "position ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session hostnames by project: %w", err)
	}
	return rows, nil
}

// GetSessionHostnamesByScan returns session hostnames for a project+scan, ordered by hostname then position.
func (r *Repository) GetSessionHostnamesByScan(ctx context.Context, projectUUID, scanUUID string) ([]*SessionHostname, error) {
	var rows []*SessionHostname
	err := r.db.NewSelect().
		Model(&rows).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("scan_uuid = ?", scanUUID).
		Order("hostname ASC", "position ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session hostnames by scan: %w", err)
	}
	return rows, nil
}

// DeleteSessionHostname deletes a single session hostname by ID.
func (r *Repository) DeleteSessionHostname(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().
		Model((*SessionHostname)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session hostname: %w", err)
	}
	return nil
}

// DeleteSessionHostnamesByHostname deletes all session hostnames for a project+hostname.
func (r *Repository) DeleteSessionHostnamesByHostname(ctx context.Context, projectUUID, hostname string) error {
	_, err := r.db.NewDelete().
		Model((*SessionHostname)(nil)).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", hostname).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session hostnames: %w", err)
	}
	return nil
}
