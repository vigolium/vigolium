package cli

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var (
	resolvedProjectUUID string
	resolveProjectOnce  sync.Once
	resolveProjectErr   error
)

// resolveProjectUUID returns the effective project UUID from --project-id,
// --project-name, env vars (VIG_PROJECT_UUID / VIGOLIUM_PROJECT), or the default.
func resolveProjectUUID() (string, error) {
	resolveProjectOnce.Do(func() {
		switch {
		case globalProjectID != "":
			resolvedProjectUUID = globalProjectID
		case globalProjectName != "":
			db, err := getDB()
			if err != nil {
				resolveProjectErr = fmt.Errorf("failed to open database for project name lookup: %w", err)
				return
			}
			repo := database.NewRepository(db)
			project, err := repo.GetProjectByName(context.Background(), globalProjectName)
			if err != nil {
				resolveProjectErr = err
				return
			}
			resolvedProjectUUID = project.UUID
		default:
			resolvedProjectUUID = database.DefaultProjectUUID
		}
	})
	return resolvedProjectUUID, resolveProjectErr
}

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects for multi-tenant data isolation",
}

var projectCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()
		defer closeDatabaseOnExit()

		db, err := getDB()
		if err != nil {
			return err
		}
		repo := database.NewRepository(db)
		ctx := context.Background()

		projectUUID := uuid.New().String()
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
	Use:   "list",
	Short: "List all projects",
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

		if len(projects) == 0 {
			fmt.Println("No projects found.")
			return nil
		}

		active, err := resolveProjectUUID()
		if err != nil {
			return err
		}

		tbl := terminal.NewTable("", "UUID", "NAME", "DESCRIPTION")
		for _, p := range projects {
			marker := ""
			if p.UUID == active {
				marker = terminal.BoldGreen("*")
			}
			tbl.AddRow(marker, p.UUID, p.Name, p.Description)
		}
		tbl.Print()
		return nil
	},
}

var projectUseCmd = &cobra.Command{
	Use:   "use [uuid]",
	Short: "Print the shell export command to set the active project",
	Long:  "Prints an export command you can eval to set VIG_PROJECT_UUID.\nUsage: eval $(vigolium project use <uuid>)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()
		defer closeDatabaseOnExit()

		projectUUID := args[0]

		// Verify project exists
		db, err := getDB()
		if err != nil {
			return err
		}
		repo := database.NewRepository(db)
		ctx := context.Background()

		project, err := repo.GetProjectByUUID(ctx, projectUUID)
		if err != nil {
			return fmt.Errorf("project not found: %w", err)
		}

		// Print export command (user evals this)
		fmt.Printf("export VIG_PROJECT_UUID=%s\n", project.UUID)
		// Print info to stderr so eval doesn't capture it
		fmt.Fprintf(os.Stderr, "%s Active project: %s (%s)\n",
			terminal.SuccessSymbol(), terminal.BoldGreen(project.Name), project.UUID)
		return nil
	},
}

var projectConfigCmd = &cobra.Command{
	Use:   "config [uuid]",
	Short: "Show or edit a project's config file path",
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
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectConfigCmd)
}
