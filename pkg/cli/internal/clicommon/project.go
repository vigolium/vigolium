package clicommon

import (
	"context"
	"fmt"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	resolvedProjectUUID string
	resolveProjectOnce  sync.Once
	resolveProjectErr   error
)

// ResolveProjectUUID returns the effective project UUID, resolved once per
// process. Resolution order:
//  1. projectUUID (from --project-uuid / VIGOLIUM_PROJECT[_UUID])
//  2. projectName (DB lookup, opening the database via getDB)
//  3. ~/.vigolium/active-project file (set by `vigolium project use`)
//  4. database.DefaultProjectUUID
//
// getDB is supplied by the caller so this package needs no knowledge of the
// CLI's global flag state.
func ResolveProjectUUID(getDB func() (*database.DB, error), projectUUID, projectName string) (string, error) {
	resolveProjectOnce.Do(func() {
		switch {
		case projectUUID != "":
			resolvedProjectUUID = projectUUID
		case projectName != "":
			db, err := getDB()
			if err != nil {
				resolveProjectErr = fmt.Errorf("failed to open database for project name lookup: %w", err)
				return
			}
			repo := database.NewRepository(db)
			project, err := repo.GetProjectByName(context.Background(), projectName)
			if err != nil {
				resolveProjectErr = err
				return
			}
			resolvedProjectUUID = project.UUID
		default:
			if persisted, err := config.ReadActiveProject(); err == nil && persisted != "" {
				resolvedProjectUUID = persisted
			} else {
				resolvedProjectUUID = database.DefaultProjectUUID
			}
		}
	})
	return resolvedProjectUUID, resolveProjectErr
}
