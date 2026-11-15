package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// --dry-run on the commands that change state and lacked one. Each reports
// through the mutation envelope's dry_run field (changed is then always
// false) what it would have done, and writes nothing: no database row, no
// config edit, no file, and no request.
var (
	dbResetDryRun       bool
	projectDeleteDryRun bool
	moduleToggleDryRun  bool
	findingLoadDryRun   bool
	findingMarkDryRun   bool
	importDryRun        bool
	ingestDryRun        bool
	skillsInstallDryRun bool
	scopeSetDryRun      bool
	sessionLoadDryRun   bool
)

func init() {
	for _, r := range []struct {
		cmd  *cobra.Command
		v    *bool
		help string
	}{
		{dbResetCmd, &dbResetDryRun, "Show which database files would be deleted and recreated, without touching them"},
		{projectDeleteCmd, &projectDeleteDryRun, "Show the project and what it holds, without deleting anything"},
		{moduleEnableCmd, &moduleToggleDryRun, "Show which modules would be enabled, without editing the config"},
		{moduleDisableCmd, &moduleToggleDryRun, "Show which modules would be disabled, without editing the config"},
		{findingLoadCmd, &findingLoadDryRun, "Parse the input and report how many findings it holds, without storing them"},
		{findingMarkCmd, &findingMarkDryRun, "Show which findings would change status, without writing"},
		{importCmd, &importDryRun, "Import into a throwaway database and report what would land, leaving the real one untouched (no report, no upload)"},
		{ingestCmd, &ingestDryRun, "Parse the input and report how many requests it yields, without sending or storing any"},
		{skillsInstallCmd, &skillsInstallDryRun, "Show which skills would be installed or skipped, without writing files"},
		{scopeSetCmd, &scopeSetDryRun, "Show the rule's old and new value, without editing the config"},
		{sessionLoadCmd, &sessionLoadDryRun, "Parse the sessions (or raw login request) and report them, without logging in or saving"},
	} {
		r.cmd.Flags().BoolVar(r.v, "dry-run", false, r.help)
	}
}

// previewDBReset names the file a reset would delete, and how many of it and
// its WAL/SHM companions exist (files_removed: what a real run would remove),
// without touching them.
func previewDBReset(cmd *cobra.Command) error {
	_, dbPath, err := resetDatabasePath()
	if err != nil {
		return err
	}
	view := dbResetView{Path: dbPath}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, statErr := os.Stat(dbPath + suffix); statErr == nil {
			view.FilesRemoved++
		}
	}
	if globalJSON {
		return emitMutation(cmd, "", mutationResult{Action: "reset", DryRun: true, Items: []dbResetView{view}}, withDBPath(dbPath))
	}
	fmt.Printf("%s Dry run: would delete and recreate %s (%d file(s) present)\n", terminal.InfoSymbol(), terminal.Cyan(dbPath), view.FilesRemoved)
	return nil
}

// previewProjectDelete reports the project a delete would remove and what it
// holds, without deleting anything.
func previewProjectDelete(cmd *cobra.Command, project *database.Project, stats *database.ProjectStatsRow, configDir string, keepConfig bool) error {
	row := projectDeleteView{projectMutationView: newProjectMutationView(project)}
	if stats != nil {
		row.HTTPRecords, row.Findings, row.Scans = stats.HTTPRecords, stats.Findings, stats.Scans
		row.AgenticScans, row.OASTInteractions = stats.AgenticScans, stats.OASTInteractions
	}
	if !keepConfig {
		if _, err := os.Stat(configDir); err == nil {
			row.ConfigRemoved = true
		}
	}
	if globalJSON {
		return emitMutation(cmd, "", mutationResult{
			Action: "delete", DryRun: true, Items: []projectDeleteView{row},
			Extra: map[string]any{"found": true},
		}, withProjectUUID(project.UUID), withDBPath(resolvedReadDBPath()))
	}
	fmt.Printf("%s Dry run: would delete project %s (%s); nothing was deleted\n", terminal.InfoSymbol(), project.Name, project.UUID)
	return nil
}

// sessionLoadDryRunView is one session `auth load --dry-run` parsed.
type sessionLoadDryRunView struct {
	Name     string `json:"name"`
	Role     string `json:"role,omitempty"`
	Host     string `json:"host"`
	LoginURL string `json:"login_url,omitempty"`
	Method   string `json:"method,omitempty"`
	// Headers names the static headers (never their values).
	Headers []string `json:"headers"`
}

// previewSessionLoad reports the parsed sessions without logging in (which
// sends a request) or saving them.
func previewSessionLoad(cmd *cobra.Command, sessions []*authentication.Session) error {
	items := make([]sessionLoadDryRunView, 0, len(sessions))
	for _, s := range sessions {
		v := sessionLoadDryRunView{Name: s.Name, Role: string(s.Role), Host: sessionLoadHost, Headers: sortedHeaderNames(s.Headers)}
		if v.Headers == nil {
			v.Headers = []string{}
		}
		if s.Login != nil {
			v.LoginURL, v.Method = s.Login.URL, s.Login.Method
		}
		items = append(items, v)
	}
	return emitSessionLoadDryRun(cmd, items)
}

// previewRawSessionLoad reports the raw login request without sending it.
func previewRawSessionLoad(cmd *cobra.Command, method, loginURL string) error {
	name := sessionLoadName
	if name == "" {
		name = "auto-discovered"
	}
	host := sessionLoadHost
	if host == "" {
		if u, err := url.Parse(loginURL); err == nil {
			host = u.Host
		}
	}
	return emitSessionLoadDryRun(cmd, []sessionLoadDryRunView{{Name: name, Host: host, LoginURL: loginURL, Method: method, Headers: []string{}}})
}

func emitSessionLoadDryRun(cmd *cobra.Command, items []sessionLoadDryRunView) error {
	if globalJSON {
		return emitMutation(cmd, "", mutationResult{Action: "load", DryRun: true, Items: items})
	}
	for _, v := range items {
		login := "static headers"
		if v.LoginURL != "" {
			login = v.Method + " " + v.LoginURL
		}
		fmt.Printf("%s Dry run: session %s for %s (%s); not logged in, not saved\n", terminal.InfoSymbol(), v.Name, v.Host, login)
	}
	return nil
}

// dryRunScratchRepo opens a throwaway database with the schema and default
// rows, for a dry run that performs the real write against a copy nobody
// keeps. cleanup closes and removes it.
func dryRunScratchRepo(ctx context.Context, label string) (*database.Repository, func(), error) {
	db, dir, err := newTempDB(label)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	}
	if err := db.EnsureSchemaReady(ctx); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("dry run: create scratch schema: %w", err)
	}
	if err := db.SeedDefaults(ctx); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("dry run: seed scratch database: %w", err)
	}
	return database.NewRepository(db), cleanup, nil
}

// ingestDryRunItems counts the requests an `ingest --dry-run` parsed, over
// every source.
var ingestDryRunItems int64

// drainIngestDryRun reads every item the input yields (parsing only: no
// fetch, no store) and counts them, preloaded ones included.
func drainIngestDryRun(src source.InputSource, preloaded int) error {
	ingestDryRunItems += int64(preloaded)
	ctx := context.Background()
	for {
		item, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("dry run: read input: %w", err)
		}
		if item != nil {
			ingestDryRunItems++
		}
	}
}

// previewSkillInstall is installSkillBundle without the writes: Installed
// says whether a real run would install (or, with --force, reinstall).
func previewSkillInstall(b bundledSkill, dest string, force bool, _, _ string, _ time.Time) (skillInstallOutcome, error) {
	_, digest, err := bundleContents(b)
	if err != nil {
		return skillInstallOutcome{}, err
	}
	prev := inspectSkillInstall(dest, digest)
	return skillInstallOutcome{
		Status:    prev.Status,
		Version:   prev.Version,
		Installed: prev.Status == skillStatusMissing || force,
	}, nil
}
