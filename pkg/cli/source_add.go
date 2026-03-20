package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/gitutil"
	"github.com/vigolium/vigolium/pkg/toolexec/sourcetools"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var sourceAddOpts struct {
	Hostname  string
	Path      string
	GitURL    string
	Name      string
	Language  string
	Framework string
	RepoType  string
	ScanUUID  string
	Tags      []string
}

var sourceAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Link application source code to a target hostname",
	RunE:  runSourceAdd,
}

var sourceRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Remove a source repo link by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runSourceRm,
}

func init() {
	sourceCmd.AddCommand(sourceAddCmd)
	sourceCmd.AddCommand(sourceRmCmd)

	flags := sourceAddCmd.Flags()
	flags.StringVarP(&sourceAddOpts.Hostname, "hostname", "H", "", "Target hostname (required)")
	flags.StringVarP(&sourceAddOpts.Path, "path", "p", "", "Filesystem path to source root")
	flags.StringVarP(&sourceAddOpts.GitURL, "git", "g", "", "Git URL to clone (e.g. https://github.com/org/repo)")
	flags.StringVarP(&sourceAddOpts.Name, "name", "n", "", "Display name (defaults to directory basename)")
	flags.StringVarP(&sourceAddOpts.Language, "language", "l", "", "Primary programming language")
	flags.StringVarP(&sourceAddOpts.Framework, "framework", "f", "", "Framework (e.g. express, django, spring)")
	flags.StringVar(&sourceAddOpts.RepoType, "repo-type", "", "Repository type: git, folder, or archive (auto-detected)")
	flags.StringVar(&sourceAddOpts.ScanUUID, "scan-uuid", "", "Link to a specific scan UUID")
	flags.StringSliceVar(&sourceAddOpts.Tags, "tag", nil, "Tags (can be specified multiple times)")

	_ = sourceAddCmd.MarkFlagRequired("hostname")
}

func runSourceAdd(cmd *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()

	// Validate mutual exclusivity of --path and --git
	hasPath := cmd.Flags().Changed("path")
	hasGit := cmd.Flags().Changed("git")
	if hasPath && hasGit {
		return fmt.Errorf("--path and --git are mutually exclusive; use one or the other")
	}
	if !hasPath && !hasGit {
		return fmt.Errorf("one of --path or --git is required")
	}

	var absPath string
	repoType := sourceAddOpts.RepoType

	if hasGit {
		// Clone the git repo
		clonedPath, err := cloneGitRepo(sourceAddOpts.GitURL)
		if err != nil {
			return err
		}
		absPath = clonedPath
		if repoType == "" {
			repoType = "git"
		}
	} else {
		// Validate local path
		var err error
		absPath, err = filepath.Abs(sourceAddOpts.Path)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
		info, statErr := os.Stat(absPath)
		if statErr != nil {
			return fmt.Errorf("path does not exist: %w", statErr)
		}
		if !info.IsDir() {
			return fmt.Errorf("path is not a directory: %s", absPath)
		}
		if repoType == "" {
			repoType = "folder"
		}
	}

	// Default name to directory basename
	name := sourceAddOpts.Name
	if name == "" {
		name = filepath.Base(absPath)
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	repo := database.NewRepository(db)
	sr := &database.SourceRepo{
		ProjectUUID: projectUUID,
		Hostname:    sourceAddOpts.Hostname,
		Name:        name,
		RootPath:    absPath,
		RepoType:    repoType,
		Language:    sourceAddOpts.Language,
		Framework:   sourceAddOpts.Framework,
		ScanUUID:    sourceAddOpts.ScanUUID,
		Tags:        sourceAddOpts.Tags,
	}

	if err := repo.CreateSourceRepo(ctx, sr); err != nil {
		return fmt.Errorf("failed to create source repo: %w", err)
	}

	fmt.Printf("%s Source repo linked: %s -> %s (id=%d)\n",
		terminal.SuccessSymbol(),
		terminal.Cyan(sr.Hostname),
		terminal.Gray(sr.RootPath),
		sr.ID)

	// Run third-party tools if enabled
	settings, _ := config.LoadSettings(globalConfig)
	if settings == nil {
		settings = config.DefaultSettings()
	}
	if settings.SourceAware.ThirdPartyIntegration.Enabled {
		fmt.Printf("%s Running third-party security tools ...\n", terminal.InfoSymbol())
		sr.ThirdPartyScanStatus = "running"
		_ = repo.UpdateSourceRepo(ctx, sr)

		toolRunner := sourcetools.New(&settings.SourceAware.ThirdPartyIntegration, repo)
		result, toolErr := toolRunner.RunAll(ctx, sr)
		if toolErr != nil {
			fmt.Printf("%s Third-party scan warning: %v\n", terminal.WarningSymbol(), toolErr)
			sr.ThirdPartyScanStatus = "failed"
		} else {
			sr.ThirdPartyScanStatus = "completed"
		}
		sr.ThirdPartyScanAt = time.Now()
		_ = repo.UpdateSourceRepo(ctx, sr)

		printToolFindings(result)
	}

	return nil
}

// looksLikeGitURL returns true if the value looks like a git URL rather than a local path.
func looksLikeGitURL(s string) bool {
	return gitutil.LooksLikeGitURL(s)
}

// cloneGitRepo clones a git URL into the configured storage directory.
// Returns the absolute path to the cloned directory.
func cloneGitRepo(gitURL string) (string, error) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	storagePath := config.ExpandPath(settings.SourceAware.StoragePath)
	cloneDepth := settings.SourceAware.CloneDepth
	if cloneDepth <= 0 {
		cloneDepth = 1
	}

	clonedPath, err := gitutil.CloneRepo(gitURL, gitutil.CloneOptions{
		StoragePath: storagePath,
		CloneDepth:  cloneDepth,
	})
	if err != nil {
		return "", err
	}

	fmt.Printf("%s Cloned to %s\n", terminal.SuccessSymbol(), terminal.Gray(clonedPath))
	return clonedPath, nil
}

func runSourceRm(_ *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ID: %w", err)
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	repo := database.NewRepository(db)

	// Check existence first
	sr, err := repo.GetSourceRepoByID(ctx, id)
	if err != nil {
		return fmt.Errorf("source repo not found: %w", err)
	}

	if err := repo.DeleteSourceRepo(ctx, id); err != nil {
		return fmt.Errorf("failed to delete source repo: %w", err)
	}

	fmt.Printf("%s Removed source repo: %s -> %s (id=%d)\n",
		terminal.SuccessSymbol(),
		terminal.Cyan(sr.Hostname),
		terminal.Gray(sr.RootPath),
		sr.ID)
	return nil
}
