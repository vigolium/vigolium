package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
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
	Example: `  # Create a project
  vigolium project create my-app --description "Main web app"

  # Create with access control in one line
  vigolium project create my-app --allow @acme.com --allow alice@partner.io

  # List projects
  vigolium project ls
  vigolium project ls --json

  # Set active project
  eval $(vigolium project use <uuid>)

  # Add/remove access later
  vigolium project allow <uuid> @newdomain.com user@example.com
  vigolium project remove-access <uuid> @olddomain.com`,
}

var projectCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new project",
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
		name := args[0]
		desc, _ := cmd.Flags().GetString("description")
		allowValues, _ := cmd.Flags().GetStringSlice("allow")

		var domains, emails []string
		for _, v := range allowValues {
			if isEmailDomain(v) {
				domains = append(domains, v)
			} else {
				emails = append(emails, v)
			}
		}

		project := &database.Project{
			UUID:           projectUUID,
			Name:           name,
			Description:    desc,
			OwnerUUID:      database.DefaultUserUUID,
			AllowedDomains: domains,
			AllowedEmails:  emails,
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
		if len(domains) > 0 {
			fmt.Printf("  Allowed domains: %s\n", strings.Join(domains, ", "))
		}
		if len(emails) > 0 {
			fmt.Printf("  Allowed emails:  %s\n", strings.Join(emails, ", "))
		}
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all projects",
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
		if jsonOutput {
			active, _ := resolveProjectUUID()
			type projectJSON struct {
				UUID           string   `json:"uuid"`
				Name           string   `json:"name"`
				Description    string   `json:"description,omitempty"`
				OwnerUUID      string   `json:"owner_uuid,omitempty"`
				AllowedDomains []string `json:"allowed_domains"`
				AllowedEmails  []string `json:"allowed_emails"`
				DefaultTarget  string   `json:"default_target,omitempty"`
				Active         bool     `json:"active"`
				CreatedAt      string   `json:"created_at"`
				UpdatedAt      string   `json:"updated_at"`
			}
			out := make([]projectJSON, 0, len(projects))
			for _, p := range projects {
				domains := p.AllowedDomains
				if domains == nil {
					domains = []string{}
				}
				emails := p.AllowedEmails
				if emails == nil {
					emails = []string{}
				}
				out = append(out, projectJSON{
					UUID:           p.UUID,
					Name:           p.Name,
					Description:    p.Description,
					OwnerUUID:      p.OwnerUUID,
					AllowedDomains: domains,
					AllowedEmails:  emails,
					DefaultTarget:  p.DefaultTarget,
					Active:         p.UUID == active,
					CreatedAt:      p.CreatedAt.Format("2006-01-02T15:04:05Z"),
					UpdatedAt:      p.UpdatedAt.Format("2006-01-02T15:04:05Z"),
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

		tbl := terminal.NewTable("", "UUID", "NAME", "DESCRIPTION", "ALLOWED DOMAINS", "ALLOWED EMAILS")
		for _, p := range projects {
			marker := ""
			if p.UUID == active {
				marker = terminal.BoldGreen("*")
			}
			tbl.AddRow(marker, p.UUID, p.Name, p.Description, truncateList(p.AllowedDomains, 5), truncateList(p.AllowedEmails, 5))
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

// truncateList joins items with ", " and appends "+N more" if the list exceeds max.
func truncateList(items []string, max int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
}

// isEmailDomain returns true if the value is a domain pattern (e.g. "@acme.com"),
// false if it's a full email address (e.g. "alice@acme.com").
func isEmailDomain(v string) bool {
	return strings.HasPrefix(v, "@") && !strings.Contains(v[1:], "@")
}

var projectAllowCmd = &cobra.Command{
	Use:   "allow [project-uuid] [value...]",
	Short: "Add allowed domains or emails to a project",
	Long: `Auto-detects input type and adds to the appropriate access list.

  @acme.com        → added to allowed_domains
  alice@acme.com   → added to allowed_emails

Duplicates are skipped (case-insensitive).`,
	Args: cobra.MinimumNArgs(2),
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

		project, err := repo.GetProjectByUUID(ctx, args[0])
		if err != nil {
			return fmt.Errorf("project not found: %w", err)
		}

		existingDomains := make(map[string]bool)
		for _, d := range project.AllowedDomains {
			existingDomains[strings.ToLower(d)] = true
		}
		existingEmails := make(map[string]bool)
		for _, e := range project.AllowedEmails {
			existingEmails[strings.ToLower(e)] = true
		}

		addedDomains, addedEmails := 0, 0
		for _, v := range args[1:] {
			lower := strings.ToLower(v)
			if isEmailDomain(v) {
				if !existingDomains[lower] {
					project.AllowedDomains = append(project.AllowedDomains, v)
					existingDomains[lower] = true
					addedDomains++
				}
			} else {
				if !existingEmails[lower] {
					project.AllowedEmails = append(project.AllowedEmails, v)
					existingEmails[lower] = true
					addedEmails++
				}
			}
		}

		if addedDomains+addedEmails > 0 {
			if err := repo.UpdateProject(ctx, project); err != nil {
				return fmt.Errorf("failed to update project: %w", err)
			}
		}

		fmt.Printf("%s Added %d domain(s) and %d email(s) to project %s\n",
			terminal.SuccessSymbol(), addedDomains, addedEmails, terminal.BoldGreen(project.Name))
		if len(project.AllowedDomains) > 0 {
			fmt.Printf("  Allowed domains: %s\n", strings.Join(project.AllowedDomains, ", "))
		}
		if len(project.AllowedEmails) > 0 {
			fmt.Printf("  Allowed emails:  %s\n", strings.Join(project.AllowedEmails, ", "))
		}
		return nil
	},
}

var projectRemoveAccessCmd = &cobra.Command{
	Use:   "remove-access [project-uuid] [value...]",
	Short: "Remove domains or emails from a project's access lists",
	Long:  "Removes the given values from both allowed_domains and allowed_emails lists.",
	Args:  cobra.MinimumNArgs(2),
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

		project, err := repo.GetProjectByUUID(ctx, args[0])
		if err != nil {
			return fmt.Errorf("project not found: %w", err)
		}

		toRemove := make(map[string]bool)
		for _, v := range args[1:] {
			toRemove[strings.ToLower(v)] = true
		}

		removed := 0
		newDomains := project.AllowedDomains[:0]
		for _, d := range project.AllowedDomains {
			if toRemove[strings.ToLower(d)] {
				removed++
			} else {
				newDomains = append(newDomains, d)
			}
		}
		project.AllowedDomains = newDomains

		newEmails := project.AllowedEmails[:0]
		for _, e := range project.AllowedEmails {
			if toRemove[strings.ToLower(e)] {
				removed++
			} else {
				newEmails = append(newEmails, e)
			}
		}
		project.AllowedEmails = newEmails

		if removed > 0 {
			if err := repo.UpdateProject(ctx, project); err != nil {
				return fmt.Errorf("failed to update project: %w", err)
			}
		}

		fmt.Printf("%s Removed %d entry/entries from project %s\n",
			terminal.SuccessSymbol(), removed, terminal.BoldGreen(project.Name))
		fmt.Printf("  Allowed domains: %s\n", strings.Join(project.AllowedDomains, ", "))
		fmt.Printf("  Allowed emails:  %s\n", strings.Join(project.AllowedEmails, ", "))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(projectCmd)

	projectCreateCmd.Flags().String("description", "", "Project description")
	projectCreateCmd.Flags().StringSlice("allow", nil, "Allowed domains (@domain.com) or emails (user@domain.com)")
	projectListCmd.Flags().Bool("json", false, "Output as JSON")
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectConfigCmd)
	projectCmd.AddCommand(projectAllowCmd)
	projectCmd.AddCommand(projectRemoveAccessCmd)
}
