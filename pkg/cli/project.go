package cli

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
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
// clicommon.ResolveProjectUUID for the full resolution order.
func resolveProjectUUID() (string, error) {
	return clicommon.ResolveProjectUUID(getDB, globalProjectUUID, globalProjectName)
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

		db, err := getDB()
		if err != nil {
			return err
		}
		repo := database.NewRepository(db)
		ctx := context.Background()

		projectUUID := uuid.New().String()
		// Honor --project-uuid only when explicitly set on the command line, so
		// an exported VIGOLIUM_PROJECT_UUID (meant to scope ops to an existing
		// project) doesn't silently dictate the new project's UUID.
		if cmd.Flags().Changed("project-uuid") && globalProjectUUID != "" {
			if _, parseErr := uuid.Parse(globalProjectUUID); parseErr != nil {
				return fmt.Errorf("--project-uuid value %q is not a valid UUID: %w", globalProjectUUID, parseErr)
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

		fmt.Printf("%s Created project %s\n", terminal.SuccessSymbol(), terminal.BoldGreen(name))
		fmt.Printf("  UUID: %s\n", terminal.Cyan(projectUUID))
		fmt.Printf("  Config: %s\n", terminal.Cyan(config.ContractPath(config.ProjectConfigPath(projectUUID))))
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all projects",
	Long:    "Print every project stored in the database, marking the active one (resolved from --project-uuid, $VIGOLIUM_PROJECT_UUID, or the default). Pass --json for machine-readable output, or run interactively to launch the picker.",
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()
		defer closeDatabaseOnExit()

		db, err := getDB()
		if err != nil {
			return err
		}
		repo := database.NewRepository(db)
		ctx := context.Background()

		projects, err := repo.ListProjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}

		jsonOutput, _ := cmd.Flags().GetBool("json")

		if active, tuiErr := tui.Active(projectLsTUI, projectLsNoTUI, jsonOutput); tuiErr != nil {
			return tuiErr
		} else if active {
			if len(projects) == 0 {
				fmt.Println("No projects found.")
				return nil
			}
			activeUUID, _ := resolveProjectUUID()
			return pickProjectLsTUI(projects, activeUUID)
		}

		if jsonOutput {
			active, _ := resolveProjectUUID()
			type projectJSON struct {
				UUID          string `json:"uuid"`
				Name          string `json:"name"`
				Description   string `json:"description,omitempty"`
				OwnerUUID     string `json:"owner_uuid,omitempty"`
				DefaultTarget string `json:"default_target,omitempty"`
				Active        bool   `json:"active"`
				CreatedAt     string `json:"created_at"`
				UpdatedAt     string `json:"updated_at"`
			}
			out := make([]projectJSON, 0, len(projects))
			for _, p := range projects {
				out = append(out, projectJSON{
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
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}

		if len(projects) == 0 {
			fmt.Println("No projects found.")
			return nil
		}

		active, err := resolveProjectUUID()
		if err != nil {
			return err
		}

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
	Use:   "use [uuid]",
	Short: "Print the shell export command to set the active project",
	Long:  "Prints an export command you can eval to set VIGOLIUM_PROJECT_UUID.\nUsage: eval $(vigolium project use <uuid>)\n\nIf the project does not exist, it is auto-created using the given UUID. Pass --name and --description to customize the new project.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()
		defer closeDatabaseOnExit()

		projectUUID := args[0]

		db, err := getDB()
		if err != nil {
			return err
		}
		repo := database.NewRepository(db)
		ctx := context.Background()

		project, err := repo.GetProjectByUUID(ctx, projectUUID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("failed to look up project: %w", err)
			}
			project, err = autoCreateProject(ctx, repo, cmd, projectUUID)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s Auto-created project %s (%s)\n",
				terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), project.UUID)
		}

		if err := config.WriteActiveProject(project.UUID); err != nil {
			return fmt.Errorf("failed to persist active project: %w", err)
		}

		// Print export command (user evals this)
		fmt.Printf("export VIGOLIUM_PROJECT_UUID=%s\n", project.UUID)
		// Print info to stderr so eval doesn't capture it
		fmt.Fprintf(os.Stderr, "%s Active project: %s (%s)\n",
			terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), project.UUID)
		fmt.Fprintf(os.Stderr, "  Saved to %s — picked up automatically by future commands.\n",
			terminal.Cyan(config.ContractPath(config.ActiveProjectFilePath())))
		return nil
	},
}

// autoCreateProject creates a new project with the given UUID, honoring
// VIGOLIUM_PROJECT_READONLY and the --name / --description flags.
func autoCreateProject(ctx context.Context, repo *database.Repository, cmd *cobra.Command, projectUUID string) (*database.Project, error) {
	if err := checkProjectReadonly(); err != nil {
		return nil, err
	}
	if _, parseErr := uuid.Parse(projectUUID); parseErr != nil {
		return nil, fmt.Errorf("project not found and %q is not a valid UUID: %w", projectUUID, parseErr)
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
			return fmt.Errorf("project UUID is required")
		}
		if projectUUID == database.DefaultProjectUUID {
			return fmt.Errorf("cannot delete the default project (%s)", database.DefaultProjectUUID)
		}

		db, err := getDB()
		if err != nil {
			return err
		}
		repo := database.NewRepository(db)
		ctx := context.Background()

		project, err := repo.GetProjectByUUID(ctx, projectUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("project %s not found", projectUUID)
			}
			return fmt.Errorf("failed to look up project: %w", err)
		}

		stats, statsErr := repo.GetProjectStats(ctx, projectUUID)
		if statsErr != nil {
			fmt.Fprintf(os.Stderr, "%s Could not load project stats: %s\n", terminal.WarningSymbol(), statsErr)
		}

		fmt.Printf("%s About to permanently delete project %s (%s)\n",
			terminal.WarningSymbol(), terminal.BoldGreen(project.Name), terminal.Cyan(projectUUID))
		if stats != nil {
			fmt.Printf("  HTTP records:    %d\n", stats.HTTPRecords)
			fmt.Printf("  Findings:        %d\n", stats.Findings)
			fmt.Printf("  Scans:           %d\n", stats.Scans)
			fmt.Printf("  Agentic scans:   %d\n", stats.AgenticScans)
			fmt.Printf("  OAST events:     %d\n", stats.OASTInteractions)
		}

		keepConfig, _ := cmd.Flags().GetBool("keep-config")
		configDir := config.ProjectConfigDir(projectUUID)
		if !keepConfig {
			if _, statErr := os.Stat(configDir); statErr == nil {
				fmt.Printf("  Config dir:      %s (will be removed)\n", terminal.Cyan(config.ContractPath(configDir)))
			}
		}

		if !globalForce {
			fmt.Print("\nProceed? (type 'yes' to confirm): ")
			reader := bufio.NewReader(os.Stdin)
			response, readErr := reader.ReadString('\n')
			if readErr != nil {
				return fmt.Errorf("failed to read input: %w", readErr)
			}
			if strings.TrimSpace(strings.ToLower(response)) != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		if err := repo.PurgeProjectData(ctx, projectUUID); err != nil {
			return fmt.Errorf("failed to purge project data: %w", err)
		}
		if err := repo.DeleteProject(ctx, projectUUID); err != nil {
			return fmt.Errorf("failed to delete project: %w", err)
		}

		if !keepConfig {
			if err := os.RemoveAll(configDir); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to remove project config dir %s: %s\n",
					terminal.WarningSymbol(), config.ContractPath(configDir), err)
			}
		}

		// If the deleted project was the persisted active one, drop the marker
		// so future commands fall back to the default project.
		if persisted, perr := config.ReadActiveProject(); perr == nil && persisted == projectUUID {
			if rmErr := os.Remove(config.ActiveProjectFilePath()); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "%s Failed to clear active-project marker: %s\n", terminal.WarningSymbol(), rmErr)
			} else {
				fmt.Fprintf(os.Stderr, "%s Active project marker cleared (was %s)\n", terminal.InfoSymbol(), projectUUID)
			}
		}

		fmt.Printf("%s Deleted project %s (%s)\n",
			terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), projectUUID)
		return nil
	},
}

var projectConfigCmd = &cobra.Command{
	Use:   "config [uuid]",
	Short: "Show or edit a project's config file path",
	Long:  "Print the path to the per-project config file (~/.vigolium/projects/<uuid>/vigolium-configs.yaml). Without a UUID, uses the active project. The file uses the same YAML overlay format as scanning profiles.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()

		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		if len(args) > 0 {
			projectUUID = args[0]
		}

		configPath := config.ProjectConfigPath(projectUUID)

		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Printf("No project config file exists yet.\n")
			fmt.Printf("Create one at: %s\n", terminal.Cyan(config.ContractPath(configPath)))
			fmt.Printf("\nThis file uses the same format as scanning profiles (partial YAML overlay).\n")
			return nil
		}

		fmt.Printf("Project config: %s\n", terminal.Cyan(config.ContractPath(configPath)))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(projectCmd)

	projectCreateCmd.Flags().String("description", "", "Project description")
	projectUseCmd.Flags().String("name", "", "Name to use when auto-creating a project (default: \"Project <short-uuid>\")")
	projectUseCmd.Flags().String("description", "", "Description to use when auto-creating a project")
	projectListCmd.Flags().Bool("json", false, "Output as JSON")
	projectDeleteCmd.Flags().Bool("keep-config", false, "Keep the project's config directory (~/.vigolium/projects/<uuid>) on disk")
	tui.AddFlags(projectListCmd, &projectLsTUI, &projectLsNoTUI)
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectConfigCmd)
}
