package clicommon

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	resolvedProjectUUID string
	// resolvedProject is the row read while resolving, when one was.
	resolvedProject    *database.Project
	resolveProjectOnce sync.Once
	resolveProjectErr  error
	resolveProjectDone bool
	// resolvedProjectBranch records which step of the resolution order produced
	// resolvedProjectUUID (see ProjectResolutionBranch).
	resolvedProjectBranch ProjectBranch
)

// ProjectBranch names the step of the resolution order that produced the
// project UUID. The CLI maps BranchSelection onto "flag" or "env" (it alone
// knows whether the selection came from a flag or VIGOLIUM_PROJECT_*).
type ProjectBranch string

const (
	// BranchSelection: an explicit --project-uuid/--project-name (or the env
	// fallback folded into them), or a PinProjectUUID.
	BranchSelection ProjectBranch = "selection"
	// BranchActiveFile: ~/.vigolium/active-project, written by `project use`.
	// It is global to the user, so two shells (or two agents) share it.
	BranchActiveFile ProjectBranch = "active_file"
	// BranchDefault: nothing selected a project; database.DefaultProjectUUID.
	BranchDefault ProjectBranch = "default"
)

// ProjectResolutionBranch reports which step resolved this process's project,
// and whether resolution has run (successfully) at all.
func ProjectResolutionBranch() (ProjectBranch, bool) {
	if !resolveProjectDone || resolveProjectErr != nil {
		return "", false
	}
	return resolvedProjectBranch, true
}

// ResolvedProjectUUID returns the UUID this process already resolved, and
// whether there is one to return. False means resolution has not run, or ran
// and failed — in both cases the caller must not present a UUID as this read's
// scope, because the next call could still produce a different one.
//
// Distinct from ResolveProjectUUID: this never resolves, so it is safe on a
// path (an envelope, a follow-up command) that must not open a database or
// touch the active-project file as a side effect of describing a read.
func ResolvedProjectUUID() (string, bool) {
	if !resolveProjectDone || resolveProjectErr != nil {
		return "", false
	}
	return resolvedProjectUUID, resolvedProjectUUID != ""
}

// ResolveOption tunes ResolveProjectUUID.
type ResolveOption func(*resolveOptions)

type resolveOptions struct{ verify bool }

// VerifyProjectExists makes ResolveProjectUUID check the resolved project
// against the store getDB opens (and resolve a --project-uuid that is a name
// or a unique UUID prefix). Off for a source with no project registry (a
// standalone export, a scratch database), where every project is "missing".
func VerifyProjectExists(on bool) ResolveOption {
	return func(o *resolveOptions) { o.verify = on }
}

// ResolveProjectUUID returns the effective project UUID, resolved once per
// process. Resolution order:
//  1. projectUUID (from --project-uuid / VIGOLIUM_PROJECT_UUID)
//  2. projectName (DB lookup, opening the database via getDB; from
//     --project-name / VIGOLIUM_PROJECT_NAME)
//  3. ~/.vigolium/active-project file (set by `vigolium project use`)
//  4. database.DefaultProjectUUID
//
// With VerifyProjectExists(true), a project other than the default must exist:
// a missing one is a project_not_found error (exit 1) instead of a scope that
// silently matches nothing and writes into a project nothing lists. The
// --project-uuid value is then a reference: an exact UUID, an exact name, or a
// unique UUID prefix of 8+ characters. When the database cannot be opened the
// check is skipped; a command that needs the store fails on its own open.
//
// getDB is supplied by the caller so this package needs no knowledge of the
// CLI's global flag state.
func ResolveProjectUUID(getDB func() (*database.DB, error), projectUUID, projectName string, opts ...ResolveOption) (string, error) {
	var o resolveOptions
	for _, opt := range opts {
		opt(&o)
	}
	resolveProjectOnce.Do(func() {
		resolveProjectDone = true
		switch {
		case projectUUID != "":
			resolvedProjectUUID = projectUUID
			resolvedProjectBranch = BranchSelection
			if o.verify {
				resolvedProjectUUID, resolveProjectErr = verifyProjectRef(getDB, projectUUID, "--project-uuid")
			}
		case projectName != "":
			db, err := getDB()
			if err != nil {
				resolveProjectErr = fmt.Errorf("failed to open database for project name lookup: %w", err)
				return
			}
			repo := database.NewRepository(db)
			project, err := repo.GetProjectByName(context.Background(), projectName)
			if err != nil {
				var nameErr *database.ProjectNameError
				if errors.As(err, &nameErr) && nameErr.Code() == apicontract.CodeProjectNotFound {
					err = CLIError{Err: err, Code: apicontract.CodeProjectNotFound, Hint: ProjectNotFoundHint}
				}
				resolveProjectErr = err
				return
			}
			resolvedProject = project
			resolvedProjectUUID = project.UUID
			resolvedProjectBranch = BranchSelection
		default:
			if persisted, err := config.ReadActiveProject(); err == nil && persisted != "" {
				resolvedProjectUUID = persisted
				resolvedProjectBranch = BranchActiveFile
				if o.verify {
					resolvedProjectUUID, resolveProjectErr = verifyProjectRef(getDB, persisted, "the active project (~/.vigolium/active-project, set by `vigolium project use`)")
				}
			} else {
				resolvedProjectUUID = database.DefaultProjectUUID
				resolvedProjectBranch = BranchDefault
			}
		}
	})
	return resolvedProjectUUID, resolveProjectErr
}

// ProjectNotFoundHint is the next step every project_not_found error names.
const ProjectNotFoundHint = "list them with `vigolium project list`; create one with `vigolium project create <name>`"

// LookupProjectRef resolves ref — a UUID, an exact name, or a unique UUID
// prefix — to the project it names. A miss is project_not_found
// (IsProjectNotFound) and an ambiguous ref a usage error, both prefixed with
// source when it is set; any other lookup error is returned unchanged.
func LookupProjectRef(ctx context.Context, repo *database.Repository, ref, source string) (*database.Project, error) {
	p, err := repo.ResolveProjectRef(ctx, ref)
	if source != "" {
		source += ": "
	}
	switch {
	case err == nil:
		return p, nil
	case errors.Is(err, database.ErrProjectRefAmbiguous):
		return nil, UsageErrorf("%s%w", source, err)
	case errors.Is(err, database.ErrProjectNotFound):
		return nil, CLIError{
			Err:  fmt.Errorf("%sproject %q not found", source, ref),
			Code: apicontract.CodeProjectNotFound,
			Hint: ProjectNotFoundHint,
		}
	}
	return nil, err
}

// IsProjectNotFound reports whether err is LookupProjectRef's miss.
func IsProjectNotFound(err error) bool {
	var cliErr CLIError
	return errors.As(err, &cliErr) && cliErr.Code == apicontract.CodeProjectNotFound
}

// ResolvedProject is the project row the resolution read while verifying the
// selection, nil when it read none (the default project, an unverified
// selection, or a store that could not answer).
func ResolvedProject() *database.Project {
	if !resolveProjectDone || resolveProjectErr != nil {
		return nil
	}
	return resolvedProject
}

// verifyProjectRef resolves ref to an existing project's UUID. The default
// project always passes; so does any ref when the store cannot be opened or
// cannot answer (an old or foreign file without a projects table).
func verifyProjectRef(getDB func() (*database.DB, error), ref, source string) (string, error) {
	if ref == database.DefaultProjectUUID {
		return ref, nil
	}
	db, err := getDB()
	if err != nil {
		return ref, nil
	}
	p, err := LookupProjectRef(context.Background(), database.NewRepository(db), ref, source)
	switch {
	case err == nil:
		resolvedProject = p
		return p.UUID, nil
	case IsProjectNotFound(err), errors.Is(err, database.ErrProjectRefAmbiguous):
		return ref, err
	}
	return ref, nil
}

// ResetProjectResolutionForTest clears the once-per-process resolution so a
// test can drive a different project selection in the same binary. Resolution
// is memoized in a sync.Once, which is right for a CLI process that resolves
// one project and exits, and useless for a test table where every row means a
// different selection — without this, row two silently asserts row one's answer.
//
// Test-only. Production code pins with PinProjectUUID instead.
func ResetProjectResolutionForTest() {
	resolveProjectOnce = sync.Once{}
	resolvedProjectUUID = ""
	resolvedProject = nil
	resolveProjectErr = nil
	resolveProjectDone = false
	resolvedProjectBranch = ""
}

// PinProjectUUID authoritatively fixes the resolved project UUID and seals the
// resolution so every later ResolveProjectUUID call returns it, regardless of
// call ordering. This exists for --resume, which learns the run's project only
// after startup: mutating the CLI's global flags is not enough because the first
// ResolveProjectUUID call caches its result in a sync.Once. Call it during
// single-threaded startup (before any concurrent resolver use).
func PinProjectUUID(projectUUID string) {
	// Spend the Once so a subsequent ResolveProjectUUID does not overwrite the
	// pin; if it already fired, the Do is a no-op and the direct assignment below
	// still wins.
	resolveProjectOnce.Do(func() {})
	resolvedProjectUUID = projectUUID
	resolvedProject = nil
	resolvedProjectBranch = BranchSelection
	resolveProjectErr = nil
	resolveProjectDone = true
}
