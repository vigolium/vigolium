package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	sessionLsHost        string
	sessionLsShowSecrets bool
)

var sessionLsCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List session authentication configs",
	Long: "Print every session authentication config stored for the active project. Each row shows hostname, session name, " +
		"role (primary/compare), position, a token fingerprint, and extract rules. Filter to a single host with --host.\n\n" +
		"Session tokens, auth headers, and stored login requests/bodies are redacted by default: they are live credentials, " +
		"and -j output is routinely piped into an agent transcript or a CI log. Pass --show-secrets to print them in plaintext.",
	Args: cobra.NoArgs,
	RunE: runSessionLs,
}

func init() {
	authCmd.AddCommand(sessionLsCmd)
	sessionLsCmd.Flags().StringVar(&sessionLsHost, "host", "", "Filter by hostname")
	sessionLsCmd.Flags().BoolVar(&sessionLsShowSecrets, "show-secrets", false,
		"Reveal session tokens, auth headers, and login request/body values in plaintext instead of [redacted]; prints a warning to stderr")
}

func runSessionLs(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Read intent (declared in commandTraits): no schema DDL on the read path.
	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	var rows []*database.AuthenticationHostname
	if sessionLsHost != "" {
		rows, err = repo.GetAuthenticationHostnamesByHostname(ctx, projectUUID, sessionLsHost)
	} else {
		rows, err = repo.GetAuthenticationHostnamesByProject(ctx, projectUUID)
	}
	if err != nil {
		return fmt.Errorf("failed to list session hostnames: %w", err)
	}

	// The warning goes to stderr in every mode, including -j: stdout is the
	// caller's data channel, and the operator still needs to see that this
	// invocation printed live credentials.
	if sessionLsShowSecrets {
		fmt.Fprintf(os.Stderr, "%s Revealing session tokens and login credentials in plaintext.\n", terminal.WarningSymbol())
	}
	views := newAuthSessionViews(rows, sessionLsShowSecrets)

	if globalJSON {
		env := newMachineEnvelope(cmd, "sessions", views, int64(len(views)), 0, len(views))
		env.DBPath = resolvedReadDBPath()
		env.WithProjectScope(projectUUID)
		env.Redacted = !sessionLsShowSecrets && len(views) > 0
		return writeAgentJSON(env)
	}

	if len(rows) == 0 {
		fmt.Printf("%s No session auth configs found.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("%s %d session auth config(s)\n\n", terminal.InfoSymbol(), len(rows))

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "HOSTNAME", "SESSION NAME", "ROLE", "POS", "TOKEN", "EXTRACT RULES")
	for _, sh := range rows {
		role := sh.SessionRole
		switch role {
		case "primary":
			role = terminal.Green(role)
		case "compare":
			role = terminal.Yellow(role)
		}

		token := sessionTokenPreview(sh.SessionToken, sessionLsShowSecrets)

		extractRules := sh.ExtractRules
		if extractRules == "" {
			extractRules = "-"
		} else if len(extractRules) > 60 {
			extractRules = extractRules[:57] + "..."
		}

		tbl.AddRow(
			terminal.Cyan(sh.Hostname),
			sh.SessionName,
			role,
			fmt.Sprintf("%d", sh.Position),
			terminal.Gray(token),
			terminal.Gray(extractRules),
		)
	}
	tbl.Print()
	fmt.Println()
	return nil
}
