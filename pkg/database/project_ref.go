package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrProjectNotFound: no project matches a reference.
var ErrProjectNotFound = errors.New("project not found")

// ErrProjectRefAmbiguous: a name or UUID prefix matches more than one project.
var ErrProjectRefAmbiguous = errors.New("project reference is ambiguous")

// ResolveProjectRef finds the project a user-typed reference names, in order:
// an exact UUID, an exact name, then a unique UUID prefix of at least
// MinUUIDPrefix characters. A miss wraps ErrProjectNotFound; a name or
// prefix shared by several projects wraps ErrProjectRefAmbiguous.
func (r *Repository) ResolveProjectRef(ctx context.Context, ref string) (*Project, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("empty project reference: %w", ErrProjectNotFound)
	}
	var byUUID []*Project
	if err := r.db.NewSelect().Model(&byUUID).Where("uuid = ?", ref).Limit(1).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up project %q: %w", ref, err)
	}
	if len(byUUID) == 1 {
		return byUUID[0], nil
	}

	var byName []*Project
	if err := r.db.NewSelect().Model(&byName).Where("name = ?", ref).Limit(2).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up project %q: %w", ref, err)
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 2:
		return nil, fmt.Errorf("several projects are named %q; use the UUID: %w", ref, ErrProjectRefAmbiguous)
	}

	if len(ref) >= MinUUIDPrefix {
		full, _, err := r.ResolveUUIDPrefix(ctx, "projects", "", strings.ToLower(ref))
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return nil, fmt.Errorf("look up project %q: %w", ref, err)
		case full == "":
			return nil, fmt.Errorf("UUID prefix %q matches several projects; type more of it: %w", ref, ErrProjectRefAmbiguous)
		default:
			return r.GetProjectByUUID(ctx, full)
		}
	}
	return nil, fmt.Errorf("no project matches %q (a UUID, a name, or a unique UUID prefix of %d+ characters): %w",
		ref, MinUUIDPrefix, ErrProjectNotFound)
}
