package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// SaveAuthenticationHostname upserts a single session hostname record.
// Conflict key: (project_uuid, hostname, session_name).
func (r *Repository) SaveAuthenticationHostname(ctx context.Context, sh *AuthenticationHostname) error {
	if sh == nil {
		return fmt.Errorf("invalid AuthenticationHostname")
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

// SaveAuthenticationHostnames batch-upserts session hostname records in a transaction.
func (r *Repository) SaveAuthenticationHostnames(ctx context.Context, rows []*AuthenticationHostname) error {
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

// GetAuthenticationHostnamesByHostname returns session hostnames for a project+hostname, ordered by position.
func (r *Repository) GetAuthenticationHostnamesByHostname(ctx context.Context, projectUUID, hostname string) ([]*AuthenticationHostname, error) {
	var rows []*AuthenticationHostname
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

// GetAuthenticationHostnamesByProject returns all session hostnames for a project, ordered by hostname then position.
func (r *Repository) GetAuthenticationHostnamesByProject(ctx context.Context, projectUUID string) ([]*AuthenticationHostname, error) {
	var rows []*AuthenticationHostname
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

// GetAuthenticationHostnamesByScan returns session hostnames for a project+scan, ordered by hostname then position.
func (r *Repository) GetAuthenticationHostnamesByScan(ctx context.Context, projectUUID, scanUUID string) ([]*AuthenticationHostname, error) {
	var rows []*AuthenticationHostname
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

// DeleteAuthenticationHostname deletes a single session hostname by ID.
func (r *Repository) DeleteAuthenticationHostname(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().
		Model((*AuthenticationHostname)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session hostname: %w", err)
	}
	return nil
}

// DeleteAuthenticationHostnamesByHostname deletes all session hostnames for a project+hostname.
func (r *Repository) DeleteAuthenticationHostnamesByHostname(ctx context.Context, projectUUID, hostname string) error {
	_, err := r.db.NewDelete().
		Model((*AuthenticationHostname)(nil)).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", hostname).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session hostnames: %w", err)
	}
	return nil
}
