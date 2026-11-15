package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// resolveProjectUUID returns the effective project UUID, resolved once per
// process from the --project-uuid / --project-name global flags. See
// clicommon.ResolveProjectUUID for the full resolution order. The existence
// check reads through a read handle, so a command that never writes (config
// get, a --dry-run) does not migrate the store to check a project.
func resolveProjectUUID() (string, error) {
	return clicommon.ResolveProjectUUID(projectVerifyDB, globalProjectUUID, globalProjectName,
		clicommon.VerifyProjectExists(projectExistenceCheckApplies()))
}

func projectVerifyDB() (*database.DB, error) {
	return getDBFor(clicommon.IntentRead)
}

// resolveProjectRefArg resolves a project named on the command line (a UUID,
// an exact name, or a unique 8+ character UUID prefix) to an existing
// project's UUID: project_not_found (exit 1) when none matches, a usage error
// when the reference is ambiguous. The default project always resolves.
func resolveProjectRefArg(ctx context.Context, ref string) (string, error) {
	if ref == database.DefaultProjectUUID {
		return ref, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := getDB()
	if err != nil {
		return "", fmt.Errorf("open the database to look up project %q: %w", ref, err)
	}
	p, err := clicommon.LookupProjectRef(ctx, database.NewRepository(db), ref, "")
	if err != nil {
		return "", err
	}
	return p.UUID, nil
}

// projectExistenceCheckApplies reports whether the selected project can be
// checked against the store: not for a standalone source (-S, --glob-db, a
// VIGOLIUM_DB_PATH pin) or a --db-isolate scratch database, which carry no
// project registry of their own.
func projectExistenceCheckApplies() bool {
	return !statelessReadRequested() && !globalDBIsolate
}

// openProjectRepo opens the database, ensures the schema exists and seeds the
// default rows, returning a repository over it.
//
// database.NewDB only opens the connection — it does not create tables. The
// project subcommands are routinely the FIRST command to touch a brand-new
// --db file (creating a project is step one of a clean install or a DB reset),
// so unlike most read paths they cannot assume some earlier command already
// bootstrapped it. Without this, `project create --db <new file>` failed with
// "no such table: projects" and a fresh install could only be worked around by
// cloning an already-populated database.
//
// CreateSchema and SeedDefaults are paired here for the same reason every other
// first-touch site pairs them (cmd_import.go, cmd_init.go, init.go): schema
// alone leaves no default user and no default project row, so the new project's
// OwnerUUID would dangle and resolveProjectUUID's default fallback would point
// at a project that does not exist.
func openProjectRepo(ctx context.Context) (*database.Repository, error) {
	// Write intent makes the schema ready as part of the open.
	db, err := getDBFor(clicommon.IntentWrite)
	if err != nil {
		return nil, err
	}
	if err := db.SeedDefaults(ctx); err != nil {
		return nil, fmt.Errorf("failed to seed default data: %w", err)
	}
	return database.NewRepository(db), nil
}

// checkProjectReadonly returns an error if VIGOLIUM_PROJECT_READONLY is set,
// preventing mutating project operations from the CLI.
func checkProjectReadonly() error {
	if os.Getenv("VIGOLIUM_PROJECT_READONLY") == "true" {
		return fmt.Errorf("project management is disabled (VIGOLIUM_PROJECT_READONLY=true)")
	}
	return nil
}

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects for multi-tenant data isolation",
	Long:  "Create, list, and manage projects. Each project isolates scan data, findings, and configuration.",
}

var projectCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new project",
	Long:  "Create a new project with the given name. Use --description to add free-form notes and --project-uuid to pin a specific UUID instead of generating a fresh one (must be a valid UUID and not already used).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkProjectReadonly(); err != nil {
			return err
		}
		defer syncLogger()
		defer closeDatabaseOnExit()

		ctx := context.Background()
		repo, err := openProjectRepo(ctx)
		if err != nil {
			return err
		}

		projectUUID := uuid.New().String()
		// Honor --project-uuid only when explicitly set on the command line, so
		// an exported VIGOLIUM_PROJECT_UUID (meant to scope ops to an existing
		// project) doesn't silently dictate the new project's UUID.
		if cmd.Flags().Changed("project-uuid") && globalProjectUUID != "" {
			if _, parseErr := uuid.Parse(globalProjectUUID); parseErr != nil {
				return usageErrorf("--project-uuid value %q is not a valid UUID: %w", globalProjectUUID, parseErr)
			}
			existing, lookupErr := repo.GetProjectByUUID(ctx, globalProjectUUID)
			if lookupErr == nil && existing != nil {
				return fmt.Errorf("project with UUID %s already exists (name: %q)", globalProjectUUID, existing.Name)
			}
			if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
				return fmt.Errorf("failed to check for existing project: %w", lookupErr)
			}
			projectUUID = globalProjectUUID
		}
		name := args[0]
		desc, _ := cmd.Flags().GetString("description")

		project := &database.Project{
			UUID:        projectUUID,
			Name:        name,
			Description: desc,
			OwnerUUID:   database.DefaultUserUUID,
		}

		if err := repo.CreateProject(ctx, project); err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}

		// Create project config directory
		configDir := config.ProjectConfigDir(projectUUID)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create project config directory: %w", err)
		}

		if globalJSON {
			return emitMutation(cmd, "", mutationResult{
				Changed: true,
				Action:  "create",
				Items:   []projectMutationView{newProjectMutationView(project)},
				Query:   []string{"--project-uuid", projectUUID, "project", "config", "--json"},
			}, withProjectUUID(projectUUID), withDBPath(resolvedReadDBPath()))
		}

		fmt.Printf("%s Created project %s\n", terminal.SuccessSymbol(), terminal.BoldGreen(name))
		fmt.Printf("  UUID: %s\n", terminal.Cyan(projectUUID))
		fmt.Printf("  Config: %s\n", terminal.Cyan(config.ContractPath(config.ProjectConfigPath(projectUUID))))
		return nil
	},
}

// projectMutationView is the -j row for a project a mutation touched.
type projectMutationView struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ConfigPath  string `json:"config_path"`
}

func newProjectMutationView(p *database.Project) projectMutationView {
	return projectMutationView{
		UUID:        p.UUID,
		Name:        p.Name,
		Description: p.Description,
		ConfigPath:  config.ContractPath(config.ProjectConfigPath(p.UUID)),
	}
}

// withProjectUUID names the project a project command acted on. Not
// withProjectScope: that states a read filter (project_scoped), and these
// commands do not filter anything.
func withProjectUUID(projectUUID string) envOpt {
	return func(e *agentEnvelope) { e.ProjectUUID = projectUUID }
}

var projectListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all projects",
	Long:    "Print every project stored in the database, marking the active one (resolved from --project-uuid, $VIGOLIUM_PROJECT_UUID, or the default). Pass -j/--json for machine-readable output, or run interactively to launch the picker.",
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()
		defer closeDatabaseOnExit()

		ctx := context.Background()
		repo, err := openProjectRepo(ctx)
		if err != nil {
			return err
		}

		projects, err := repo.ListProjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}

		if active, tuiErr := tui.Active(projectLsTUI, projectLsNoTUI, globalJSON); tuiErr != nil {
			return tuiErr
		} else if active {
			if len(projects) == 0 {
				fmt.Println("No projects found.")
				return nil
			}
			activeUUID, _ := resolveProjectUUID()
			return pickProjectLsTUI(projects, activeUUID)
		}

		if globalJSON {
			active, _ := resolveProjectUUID()
			out := make([]projectListView, 0, len(projects))
			for _, p := range projects {
				out = append(out, projectListView{
					UUID:          p.UUID,
					Name:          p.Name,
					Description:   p.Description,
					OwnerUUID:     p.OwnerUUID,
					DefaultTarget: p.DefaultTarget,
					Active:        p.UUID == active,
					CreatedAt:     p.CreatedAt.Format("2006-01-02T15:04:05Z"),
					UpdatedAt:     p.UpdatedAt.Format("2006-01-02T15:04:05Z"),
				})
			}
			// The global -j: the local --json this command used to define shadowed
			// it (`project list -j` failed) and printed a bare array.
			return emitRead(cmd, "", out, int64(len(out)), 0, len(out), withDBPath(resolvedReadDBPath()))
		}

		if len(projects) == 0 {
			fmt.Println("No projects found.")
			return nil
		}

		// The marker is decoration: a stale active-project file must not stop
		// the one command that lists what to switch to.
		active, _ := resolveProjectUUID()

		tbl := terminal.NewTable("", "UUID", "NAME", "DESCRIPTION", "DEFAULT TARGET")
		for _, p := range projects {
			marker := ""
			if p.UUID == active {
				marker = terminal.BoldGreen("*")
			}
			tbl.AddRow(marker, p.UUID, p.Name, p.Description, p.DefaultTarget)
		}
		tbl.Print()
		return nil
	},
}

var projectUseCmd = &cobra.Command{
	Use:   "use <project>",
	Short: "Set the active project (the global ~/.vigolium/active-project file)",
	Long: "Make <project> (a UUID, an exact name, or a unique 8+ char UUID prefix) the active project: it is written to ~/.vigolium/active-project, which every later command " +
		"without --project-uuid / $VIGOLIUM_PROJECT_UUID resolves to. That file is global to the user, so a " +
		"parallel shell or agent should pin --project-uuid or $VIGOLIUM_PROJECT_UUID instead.\n\n" +
		"When stdout is not a terminal it also prints `export VIGOLIUM_PROJECT_UUID=<uuid>`, so\n" +
		"  eval \"$(vigolium project use <uuid>)\"\n" +
		"pins the current shell. With -j it prints the result document instead (no export line).\n\n" +
		"--print-env pins one shell only: it prints the export line and writes no file, so other shells keep their project:\n" +
		"  eval \"$(vigolium project use <project> --print-env)\"\n\n" +
		"An unknown UUID is an error (not_found) unless --create is given, which creates the project with that " +
		"UUID (--name and --description customize it).",
	Args: cobra.ExactArgs(1),
	RunE: runProjectUse,
}

func runProjectUse(cmd *cobra.Command, args []string) error {
	// Every activation, not just an auto-create: switching the active project
	// re-scopes every unpinned command, which is the management action the
	// read-only switch exists to forbid. --print-env switches nothing.
	if printEnv, _ := cmd.Flags().GetBool("print-env"); !printEnv {
		if err := checkProjectReadonly(); err != nil {
			return err
		}
	}
	defer syncLogger()
	defer closeDatabaseOnExit()

	projectUUID := strings.TrimSpace(args[0])
	create, _ := cmd.Flags().GetBool("create")
	printEnv, _ := cmd.Flags().GetBool("print-env")
	if create {
		if _, parseErr := uuid.Parse(projectUUID); parseErr != nil {
			return usageErrorf("--create needs a valid UUID, got %q: %w", projectUUID, parseErr)
		}
		if printEnv {
			return usageErrorf("--print-env pins a shell to an existing project; create it first with `vigolium project create <name>`")
		}
	}

	ctx := context.Background()
	repo, err := openProjectRepo(ctx)
	if err != nil {
		return err
	}

	created := false
	// A UUID, an exact name or a unique UUID prefix, like every other project
	// reference.
	project, err := clicommon.LookupProjectRef(ctx, repo, projectUUID, "")
	if err != nil {
		// Never auto-created without --create: a typo'd UUID used to mint a
		// fresh, empty project and point every later command at it, which an
		// agent cannot tell apart from a project with no findings yet.
		if !create || !clicommon.IsProjectNotFound(err) {
			return err
		}
		project, err = autoCreateProject(ctx, repo, cmd, projectUUID)
		if err != nil {
			return err
		}
		created = true
		fmt.Fprintf(os.Stderr, "%s Created project %s (%s)\n",
			terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), project.UUID)
	}

	if printEnv {
		return printProjectEnv(cmd, project)
	}

	previous, _ := config.ReadActiveProject()
	if err := config.WriteActiveProject(project.UUID); err != nil {
		return fmt.Errorf("failed to persist active project: %w", err)
	}
	activeChanged := previous != project.UUID

	if globalJSON {
		action := "activate"
		switch {
		case created:
			action = "create"
		case !activeChanged:
			action = "noop"
		}
		return emitMutation(cmd, "", mutationResult{
			Changed: created || activeChanged,
			Action:  action,
			Items:   []projectMutationView{newProjectMutationView(project)},
			Extra: map[string]any{
				"created":          created,
				"previous_project": previous,
				"activated_scope":  "global",
				"active_file":      config.ContractPath(config.ActiveProjectFilePath()),
				"env":              map[string]string{"VIGOLIUM_PROJECT_UUID": project.UUID},
			},
			Query: []string{"--project-uuid", project.UUID, "finding", "--json"},
		}, withProjectUUID(project.UUID), withDBPath(resolvedReadDBPath()))
	}

	// The export line is for `eval "$(vigolium project use X)"`, whose stdout
	// is a pipe. On a terminal nobody evals it, so it is only noise there.
	if !terminal.IsTerminal() {
		fmt.Printf("export VIGOLIUM_PROJECT_UUID=%s\n", project.UUID)
	}
	// Info goes to stderr so eval doesn't capture it.
	fmt.Fprintf(os.Stderr, "%s Active project: %s (%s)\n",
		terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), project.UUID)
	fmt.Fprintf(os.Stderr, "  Saved to %s — picked up by every command that does not pin --project-uuid / $VIGOLIUM_PROJECT_UUID.\n",
		terminal.Cyan(config.ContractPath(config.ActiveProjectFilePath())))
	if terminal.IsTerminal() {
		fmt.Fprintf(os.Stderr, "  To pin this shell instead: %s\n",
			terminal.Gray(fmt.Sprintf("export VIGOLIUM_PROJECT_UUID=%s", project.UUID)))
	}
	return nil
}

// autoCreateProject creates a new project with the given UUID (`project use
// --create`), honoring VIGOLIUM_PROJECT_READONLY and the --name / --description
// flags.
func autoCreateProject(ctx context.Context, repo *database.Repository, cmd *cobra.Command, projectUUID string) (*database.Project, error) {
	if err := checkProjectReadonly(); err != nil {
		return nil, err
	}
	if _, parseErr := uuid.Parse(projectUUID); parseErr != nil {
		return nil, usageErrorf("%q is not a valid UUID: %w", projectUUID, parseErr)
	}

	name, _ := cmd.Flags().GetString("name")
	desc, _ := cmd.Flags().GetString("description")
	if name == "" {
		name = fmt.Sprintf("Project %s", projectUUID[:8])
	}

	project := &database.Project{
		UUID:        projectUUID,
		Name:        name,
		Description: desc,
		OwnerUUID:   database.DefaultUserUUID,
	}
	if err := repo.CreateProject(ctx, project); err != nil {
		return nil, fmt.Errorf("failed to auto-create project: %w", err)
	}

	configDir := config.ProjectConfigDir(projectUUID)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create project config directory: %w", err)
	}
	return project, nil
}

var projectDeleteCmd = &cobra.Command{
	Use:     "delete <project-uuid>",
	Short:   "Delete a project and every record tied to it",
	Long:    "Permanently delete a project along with its scans, HTTP records, findings, scopes, OAST interactions, agentic scans, authentication hostnames, and scan logs. The default project cannot be deleted. Prompts for confirmation unless --force is set; pass --keep-config to retain the project's config directory on disk.",
	Aliases: []string{"rm", "remove"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkProjectReadonly(); err != nil {
			return err
		}
		defer syncLogger()
		defer closeDatabaseOnExit()

		projectUUID := strings.TrimSpace(args[0])
		if projectUUID == "" {
			return usageErrorf("project UUID is required")
		}
		if projectUUID == database.DefaultProjectUUID {
			return usageErrorf("cannot delete the default project (%s)", database.DefaultProjectUUID)
		}

		ctx := context.Background()
		repo, err := openProjectRepo(ctx)
		if err != nil {
			return err
		}

		project, err := repo.GetProjectByUUID(ctx, projectUUID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("failed to look up project: %w", err)
			}
			// Idempotent: the state the caller asked for — no such project —
			// already holds. A cleanup step that runs twice must not fail the
			// second time.
			fmt.Fprintf(os.Stderr, "%s Project %s not found; nothing deleted.\n", terminal.InfoSymbol(), projectUUID)
			if globalJSON {
				return emitMutation(cmd, "", mutationResult{
					Action: "noop",
					Extra:  map[string]any{"found": false},
				}, withProjectUUID(projectUUID), withDBPath(resolvedReadDBPath()))
			}
			return nil
		}

		stats, statsErr := repo.GetProjectStats(ctx, projectUUID)
		if statsErr != nil {
			fmt.Fprintf(os.Stderr, "%s Could not load project stats: %s\n", terminal.WarningSymbol(), statsErr)
		}

		// The preview is prose about what is about to happen: stderr, so stdout
		// carries only the result (the -j document, or the final line).
		fmt.Fprintf(os.Stderr, "%s About to permanently delete project %s (%s)\n",
			terminal.WarningSymbol(), terminal.BoldGreen(project.Name), terminal.Cyan(projectUUID))
		if stats != nil {
			fmt.Fprintf(os.Stderr, "  HTTP records:    %d\n", stats.HTTPRecords)
			fmt.Fprintf(os.Stderr, "  Findings:        %d\n", stats.Findings)
			fmt.Fprintf(os.Stderr, "  Scans:           %d\n", stats.Scans)
			fmt.Fprintf(os.Stderr, "  Agentic scans:   %d\n", stats.AgenticScans)
			fmt.Fprintf(os.Stderr, "  OAST events:     %d\n", stats.OASTInteractions)
		}

		keepConfig, _ := cmd.Flags().GetBool("keep-config")
		configDir := config.ProjectConfigDir(projectUUID)
		configRemoved := false
		if !keepConfig {
			if _, statErr := os.Stat(configDir); statErr == nil {
				fmt.Fprintf(os.Stderr, "  Config dir:      %s (will be removed)\n", terminal.Cyan(config.ContractPath(configDir)))
			}
		}

		if projectDeleteDryRun {
			return previewProjectDelete(cmd, project, stats, configDir, keepConfig)
		}
		if done, confErr := handleConfirmation(fmt.Sprintf(
			"deleting project %s and purging all of its scan data", projectUUID)); done {
			if confErr == nil && globalJSON {
				// Declined at the prompt: one document saying nothing changed.
				return emitMutation(cmd, "", mutationResult{
					Action: "noop",
					Extra:  map[string]any{"found": true, "aborted": true},
				}, withProjectUUID(projectUUID), withDBPath(resolvedReadDBPath()))
			}
			return confErr
		}

		if err := repo.PurgeProjectData(ctx, projectUUID); err != nil {
			return fmt.Errorf("failed to purge project data: %w", err)
		}
		if err := repo.DeleteProject(ctx, projectUUID); err != nil {
			return fmt.Errorf("failed to delete project: %w", err)
		}

		if !keepConfig {
			if _, statErr := os.Stat(configDir); statErr == nil {
				if err := os.RemoveAll(configDir); err != nil {
					fmt.Fprintf(os.Stderr, "%s Failed to remove project config dir %s: %s\n",
						terminal.WarningSymbol(), config.ContractPath(configDir), err)
				} else {
					configRemoved = true
				}
			}
		}

		// If the deleted project was the persisted active one, drop the marker
		// so future commands fall back to the default project.
		activeCleared := false
		if persisted, perr := config.ReadActiveProject(); perr == nil && persisted == projectUUID {
			if rmErr := os.Remove(config.ActiveProjectFilePath()); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "%s Failed to clear active-project marker: %s\n", terminal.WarningSymbol(), rmErr)
			} else {
				activeCleared = true
				fmt.Fprintf(os.Stderr, "%s Active project marker cleared (was %s)\n", terminal.InfoSymbol(), projectUUID)
			}
		}

		if globalJSON {
			row := projectDeleteView{
				projectMutationView: newProjectMutationView(project),
				ConfigRemoved:       configRemoved,
				ActiveCleared:       activeCleared,
			}
			if stats != nil {
				row.HTTPRecords, row.Findings, row.Scans = stats.HTTPRecords, stats.Findings, stats.Scans
				row.AgenticScans, row.OASTInteractions = stats.AgenticScans, stats.OASTInteractions
			}
			return emitMutation(cmd, "", mutationResult{
				Changed: true,
				Action:  "delete",
				Items:   []projectDeleteView{row},
				Extra:   map[string]any{"found": true},
			}, withProjectUUID(projectUUID), withDBPath(resolvedReadDBPath()))
		}

		fmt.Printf("%s Deleted project %s (%s)\n",
			terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), projectUUID)
		return nil
	},
}

// projectDeleteView is the -j row for a deleted project: what it held when it
// was purged, and what else the delete cleaned up.
type projectDeleteView struct {
	projectMutationView
	HTTPRecords      int64 `json:"http_records"`
	Findings         int64 `json:"findings"`
	Scans            int64 `json:"scans"`
	AgenticScans     int64 `json:"agentic_scans"`
	OASTInteractions int64 `json:"oast_interactions"`
	ConfigRemoved    bool  `json:"config_removed"`
	ActiveCleared    bool  `json:"active_project_cleared"`
}

var projectConfigCmd = &cobra.Command{
	Use:   "config [uuid]",
	Short: "Show or edit a project's config file path",
	Long:  "Print the path to the per-project config file (~/.vigolium/projects/<uuid>/vigolium-configs.yaml). Without a UUID, uses the active project. The file uses the same YAML overlay format as scanning profiles.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()

		var projectUUID string
		var err error
		if len(args) > 0 {
			projectUUID, err = resolveProjectRefArg(cmd.Context(), args[0])
		} else {
			projectUUID, err = resolveProjectUUID()
		}
		if err != nil {
			return err
		}

		configPath := config.ProjectConfigPath(projectUUID)
		_, statErr := os.Stat(configPath)
		exists := statErr == nil

		if globalJSON {
			return emitObject(cmd, ".", projectConfigView{
				ProjectUUID: projectUUID,
				Path:        config.ContractPath(configPath),
				Exists:      exists,
			}, withProjectUUID(projectUUID))
		}

		if os.IsNotExist(statErr) {
			fmt.Printf("No project config file exists yet.\n")
			fmt.Printf("Create one at: %s\n", terminal.Cyan(config.ContractPath(configPath)))
			fmt.Printf("\nThis file uses the same format as scanning profiles (partial YAML overlay).\n")
			return nil
		}

		fmt.Printf("Project config: %s\n", terminal.Cyan(config.ContractPath(configPath)))
		return nil
	},
}

// projectConfigView is `project config -j`: where the overlay lives and
// whether it exists yet.
type projectConfigView struct {
	ProjectUUID string `json:"project_uuid"`
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
}

func init() {
	rootCmd.AddCommand(projectCmd)

	projectCreateCmd.Flags().String("description", "", "Project description")
	projectUseCmd.Flags().Bool("create", false, "Create the project with this UUID when it does not exist (otherwise an unknown UUID is a not_found error)")
	projectUseCmd.Flags().String("name", "", "Name for a project created by --create (default: \"Project <short-uuid>\")")
	projectUseCmd.Flags().String("description", "", "Description for a project created by --create")
	projectUseCmd.Flags().Bool("print-env", false, "Print the export VIGOLIUM_PROJECT_UUID=<uuid> line for eval and write no file: pins this shell only")
	projectDeleteCmd.Flags().Bool("keep-config", false, "Keep the project's config directory (~/.vigolium/projects/<uuid>) on disk")
	tui.AddFlags(projectListCmd, &projectLsTUI, &projectLsNoTUI)
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectConfigCmd)
}

// projectListView is one `project list -j` row.
type projectListView struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	OwnerUUID     string `json:"owner_uuid,omitempty"`
	DefaultTarget string `json:"default_target,omitempty"`
	Active        bool   `json:"active"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// printProjectEnv is `project use --print-env`: the export line for eval, and
// nothing written. Under -j the document says so (activated_scope "shell").
func printProjectEnv(cmd *cobra.Command, project *database.Project) error {
	if globalJSON {
		return emitMutation(cmd, "", mutationResult{
			Changed: false,
			Action:  "noop",
			Items:   []projectMutationView{newProjectMutationView(project)},
			Extra: map[string]any{
				"created":         false,
				"activated_scope": "shell",
				"env":             map[string]string{"VIGOLIUM_PROJECT_UUID": project.UUID},
			},
			Query: []string{"--project-uuid", project.UUID, "finding", "--json"},
		}, withProjectUUID(project.UUID))
	}
	fmt.Printf("export VIGOLIUM_PROJECT_UUID=%s\n", project.UUID)
	fmt.Fprintf(os.Stderr, "%s Project %s (%s) for this shell only; %s is unchanged.\n",
		terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), project.UUID,
		config.ContractPath(config.ActiveProjectFilePath()))
	return nil
}
