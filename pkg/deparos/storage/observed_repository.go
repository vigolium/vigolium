package storage

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// ObservedRepository provides database operations for observed data.
type ObservedRepository struct {
	db bun.IDB
}

// NewObservedRepository creates a new observed repository.
func NewObservedRepository(db bun.IDB) *ObservedRepository {
	return &ObservedRepository{db: db}
}

// BatchUpsertObserved inserts or updates observed items using MAX frequency on conflict.
// This is the core method for persisting observed data at session end.
func (r *ObservedRepository) BatchUpsertObserved(
	hostname string,
	obsType ObservedType,
	items map[string]int, // value -> frequency
) error {
	if len(items) == 0 {
		return nil
	}

	ctx := context.Background()
	now := time.Now().Unix()

	// Batch upsert with MAX frequency logic
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for value, freq := range items {
			// Use raw SQL for MAX frequency UPSERT (works for both SQLite and PostgreSQL)
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO observed (hostname, type, value, frequency, updated_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(hostname, type, value) DO UPDATE SET
					frequency = MAX(EXCLUDED.frequency, observed.frequency),
					updated_at = EXCLUDED.updated_at
			`, hostname, uint8(obsType), value, freq, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetByHostname returns all observed items for a hostname.
func (r *ObservedRepository) GetByHostname(hostname string) ([]ObservedModel, error) {
	ctx := context.Background()
	var items []ObservedModel
	err := r.db.NewSelect().Model(&items).
		Where("hostname = ?", hostname).
		Scan(ctx)
	return items, err
}

// GetByHostnameAndType returns observed items of a specific type for a hostname.
func (r *ObservedRepository) GetByHostnameAndType(hostname string, obsType ObservedType) ([]ObservedModel, error) {
	ctx := context.Background()
	var items []ObservedModel
	err := r.db.NewSelect().Model(&items).
		Where("hostname = ? AND type = ?", hostname, uint8(obsType)).
		Scan(ctx)
	return items, err
}

// CountByHostname returns the count of observed items for a hostname.
func (r *ObservedRepository) CountByHostname(hostname string) (int64, error) {
	ctx := context.Background()
	count, err := r.db.NewSelect().Model((*ObservedModel)(nil)).
		Where("hostname = ?", hostname).
		Count(ctx)
	return int64(count), err
}

// DeleteByHostname deletes all observed items for a hostname.
func (r *ObservedRepository) DeleteByHostname(hostname string) error {
	ctx := context.Background()
	_, err := r.db.NewDelete().Model((*ObservedModel)(nil)).
		Where("hostname = ?", hostname).
		Exec(ctx)
	return err
}

// GetAllWithMinFreq returns all observed items with minimum frequency.
func (r *ObservedRepository) GetAllWithMinFreq(minFreq int) ([]ObservedModel, error) {
	ctx := context.Background()
	var items []ObservedModel
	err := r.db.NewSelect().Model(&items).
		Where("frequency >= ?", minFreq).
		Order("hostname ASC", "type ASC", "frequency DESC").
		Scan(ctx)
	return items, err
}

// GetAllByTypeWithMinFreq returns all observed items of a type with minimum frequency.
func (r *ObservedRepository) GetAllByTypeWithMinFreq(obsType ObservedType, minFreq int) ([]ObservedModel, error) {
	ctx := context.Background()
	var items []ObservedModel
	err := r.db.NewSelect().Model(&items).
		Where("type = ? AND frequency >= ?", uint8(obsType), minFreq).
		Order("hostname ASC", "frequency DESC").
		Scan(ctx)
	return items, err
}
