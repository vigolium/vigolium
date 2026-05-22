package database

import (
	"context"
	"fmt"
)

// SaveOASTInteraction stores an OAST interaction record.
func (r *Repository) SaveOASTInteraction(ctx context.Context, interaction *OASTInteraction) error {
	if interaction == nil {
		return fmt.Errorf("invalid OASTInteraction")
	}
	interaction.ProjectUUID = defaultProjectUUID(interaction.ProjectUUID)
	if _, err := r.db.NewInsert().Model(interaction).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert OAST interaction: %w", err)
	}
	return nil
}

// GetOASTInteractionsByScan retrieves OAST interactions for a specific scan.
func (r *Repository) GetOASTInteractionsByScan(ctx context.Context, scanUUID string) ([]*OASTInteraction, error) {
	var interactions []*OASTInteraction
	err := r.db.NewSelect().
		Model(&interactions).
		Where("scan_uuid = ?", scanUUID).
		Order("interacted_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query OAST interactions: %w", err)
	}
	return interactions, nil
}

// GetOASTInteractionByID retrieves a single OAST interaction by its numeric ID.
func (r *Repository) GetOASTInteractionByID(ctx context.Context, id int64) (*OASTInteraction, error) {
	interaction := &OASTInteraction{}
	err := r.db.NewSelect().
		Model(interaction).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return interaction, nil
}

// ListOASTInteractions returns a paginated, filtered list of OAST interactions.
// Heavy columns (raw_request, raw_response) are excluded for list performance.
func (r *Repository) ListOASTInteractions(ctx context.Context, projectUUID, scanUUID, protocol, moduleID, search string, limit, offset int) ([]*OASTInteraction, int64, error) {
	var interactions []*OASTInteraction
	q := r.db.NewSelect().
		Model(&interactions).
		ExcludeColumn("raw_request", "raw_response").
		Order("interacted_at DESC")

	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if scanUUID != "" {
		q = q.Where("scan_uuid = ?", scanUUID)
	}
	if protocol != "" {
		q = q.Where("protocol = ?", protocol)
	}
	if moduleID != "" {
		q = q.Where("module_id = ?", moduleID)
	}
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("(target_url LIKE ? OR parameter_name LIKE ? OR unique_id LIKE ?)", like, like, like)
	}

	q = q.Limit(limit).Offset(offset)

	total, err := q.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query OAST interactions: %w", err)
	}
	return interactions, int64(total), nil
}

// DeleteOASTInteraction deletes an OAST interaction by its numeric ID.
func (r *Repository) DeleteOASTInteraction(ctx context.Context, id int64) error {
	_, err := r.db.NewDelete().
		Model((*OASTInteraction)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete OAST interaction: %w", err)
	}
	return nil
}
