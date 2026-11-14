package database

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// OASTSession is an interactsh registration a scan kept open after it
// finished (oast.keep_session), so callbacks that arrive late — a blind XSS
// rendered by an admin next week, a queued job, a second-order injection — are
// still collected by `vigolium oast poll` or the server's periodic poller and
// correlated through oast_payloads.
//
// The key material (secret_key, private_key, token) is what lets a later
// process resume the session; it never leaves the store: exports and the
// generic DB API redact it (RedactedOASTSessionColumns).
type OASTSession struct {
	bun.BaseModel `bun:"table:oast_sessions,alias:os" json:"-"`

	ID            int64      `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID   string     `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID      string     `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	ServerURL     string     `bun:"server_url,notnull" json:"server_url"`
	CorrelationID string     `bun:"correlation_id,notnull" json:"correlation_id"`
	SecretKey     string     `bun:"secret_key,nullzero" json:"-"`
	PrivateKey    string     `bun:"private_key,nullzero" json:"-"`
	PublicKey     string     `bun:"public_key,nullzero" json:"-"`
	Token         string     `bun:"token,nullzero" json:"-"`
	CreatedAt     time.Time  `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	LastPolledAt  *time.Time `bun:"last_polled_at,nullzero" json:"last_polled_at,omitempty"`
	ClosedAt      *time.Time `bun:"closed_at,nullzero" json:"closed_at,omitempty"`
}

// RedactedOASTSessionColumns are the oast_sessions columns that hold session
// key material; exports blank them.
var RedactedOASTSessionColumns = []string{"secret_key", "private_key", "public_key", "token"}

// SaveOASTSession stores a kept session. A session already stored for the
// same (project, correlation id) is left as it is.
func (r *Repository) SaveOASTSession(ctx context.Context, s *OASTSession) error {
	if s == nil || s.CorrelationID == "" {
		return nil
	}
	s.ProjectUUID = defaultProjectUUID(s.ProjectUUID)
	if _, err := r.db.NewInsert().Model(s).
		On("CONFLICT (project_uuid, correlation_id) DO NOTHING").
		Exec(ctx); err != nil {
		return fmt.Errorf("save oast session: %w", err)
	}
	return nil
}

// ListOpenOASTSessions returns the sessions not yet closed, oldest first. An
// empty projectUUID lists every project's (the server's poller); a non-empty
// scanUUID narrows to one scan's.
func (r *Repository) ListOpenOASTSessions(ctx context.Context, projectUUID, scanUUID string) ([]*OASTSession, error) {
	var out []*OASTSession
	q := r.db.NewSelect().Model(&out).Where("closed_at IS NULL").OrderExpr("id ASC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if scanUUID != "" {
		q = q.Where("scan_uuid = ?", scanUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("list oast sessions: %w", err)
	}
	return out, nil
}

// MarkOASTSessionPolled records a completed poll of the session.
func (r *Repository) MarkOASTSessionPolled(ctx context.Context, id int64, at time.Time) error {
	_, err := r.db.NewUpdate().Model((*OASTSession)(nil)).Set("last_polled_at = ?", at).Where("id = ?", id).Exec(ctx)
	return err
}

// CloseOASTSession marks the session closed (deregistered or abandoned) and
// drops its key material, which is no use once closed.
func (r *Repository) CloseOASTSession(ctx context.Context, id int64, at time.Time) error {
	_, err := r.db.NewUpdate().Model((*OASTSession)(nil)).
		Set("closed_at = ?", at).
		Set("secret_key = NULL").Set("private_key = NULL").Set("public_key = NULL").Set("token = NULL").
		Where("id = ?", id).Exec(ctx)
	return err
}

// GetOASTPayload returns the stored payload context for one nonce, or nil
// when none is stored. A non-empty projectUUID restricts the lookup.
func (r *Repository) GetOASTPayload(ctx context.Context, projectUUID, nonce string) (*OASTPayload, error) {
	rows, err := r.GetOASTPayloadsByNonce(ctx, projectUUID, []string{nonce})
	if err != nil {
		return nil, err
	}
	return rows[nonce], nil
}

// RedactOASTSessionKeys blanks the session key material in this store (for an
// exported copy). Missing table is not an error.
func (db *DB) RedactOASTSessionKeys(ctx context.Context) error {
	if !db.tableExists(ctx, "oast_sessions") {
		return nil
	}
	_, err := db.ExecContext(ctx,
		"UPDATE oast_sessions SET secret_key = NULL, private_key = NULL, public_key = NULL, token = NULL")
	return err
}
