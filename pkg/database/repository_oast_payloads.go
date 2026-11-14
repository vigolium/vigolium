package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
)

// SaveOASTPayloads stores the payload contexts of planted OAST payloads in one
// insert. A nonce that is already stored is left as it is: nonces are minted
// unique, so a conflict can only be the same payload written twice.
func (r *Repository) SaveOASTPayloads(ctx context.Context, payloads []*OASTPayload) error {
	rows := make([]*OASTPayload, 0, len(payloads))
	for _, p := range payloads {
		if p == nil || strings.TrimSpace(p.Nonce) == "" {
			continue
		}
		p.ProjectUUID = defaultProjectUUID(p.ProjectUUID)
		rows = append(rows, p)
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := r.db.NewInsert().Model(&rows).On("CONFLICT (nonce) DO NOTHING").Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert OAST payloads: %w", err)
	}
	return nil
}

// SetOASTPayloadValues records the literal values planted (see
// oast.Service.RecordPayload) on already stored payload rows, nonce → value,
// in one transaction.
func (r *Repository) SetOASTPayloadValues(ctx context.Context, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for nonce, payload := range values {
			if nonce == "" {
				continue
			}
			if _, err := tx.NewUpdate().Model((*OASTPayload)(nil)).
				Set("payload = ?", payload).
				Where("nonce = ?", nonce).
				Exec(ctx); err != nil {
				return fmt.Errorf("failed to update OAST payload: %w", err)
			}
		}
		return nil
	})
}

// oastPayloadLookupChunk bounds the IN list of one lookup query, well under
// SQLite's bound-parameter limit.
const oastPayloadLookupChunk = 500

// GetOASTPayloadsByNonce returns the stored payload contexts for the given
// nonces, keyed by nonce. Nonces with no stored row are absent from the map.
// A non-empty projectUUID restricts the lookup to that project; an empty one
// (a stateless database) searches every row.
func (r *Repository) GetOASTPayloadsByNonce(ctx context.Context, projectUUID string, nonces []string) (map[string]*OASTPayload, error) {
	out := make(map[string]*OASTPayload)
	seen := make(map[string]struct{}, len(nonces))
	uniq := make([]string, 0, len(nonces))
	for _, n := range nonces {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		uniq = append(uniq, n)
	}
	for start := 0; start < len(uniq); start += oastPayloadLookupChunk {
		end := min(start+oastPayloadLookupChunk, len(uniq))
		var rows []*OASTPayload
		q := r.db.NewSelect().Model(&rows).Where("nonce IN (?)", bun.List(uniq[start:end]))
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		if err := q.Scan(ctx); err != nil {
			return nil, fmt.Errorf("failed to query OAST payloads: %w", err)
		}
		for _, row := range rows {
			out[row.Nonce] = row
		}
	}
	return out, nil
}

// ListOASTInteractionsByUniqueIDs returns the stored callbacks whose unique_id
// is one of ids (raw_response is not loaded). A non-empty projectUUID restricts
// the lookup to that project. `oast ingest` uses it to skip callbacks it
// already stored and to know the strongest protocol each nonce already saw.
func (r *Repository) ListOASTInteractionsByUniqueIDs(ctx context.Context, projectUUID string, ids []string) ([]*OASTInteraction, error) {
	var out []*OASTInteraction
	for start := 0; start < len(ids); start += oastPayloadLookupChunk {
		end := min(start+oastPayloadLookupChunk, len(ids))
		var rows []*OASTInteraction
		q := r.db.NewSelect().Model(&rows).
			Column("id", "project_uuid", "scan_uuid", "unique_id", "protocol", "raw_request", "remote_address").
			Where("unique_id IN (?)", bun.List(ids[start:end]))
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		if err := q.Scan(ctx); err != nil {
			return nil, fmt.Errorf("failed to query OAST interactions: %w", err)
		}
		out = append(out, rows...)
	}
	return out, nil
}
