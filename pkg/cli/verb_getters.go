package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// The getters and removers the command groups lacked: each used to fall into
// the group's filter form or an unknown-command error.

// ---- scope add / rm / check ------------------------------------------------

var scopeEditExclude bool

var scopeAddCmd = &cobra.Command{
	Use:   "add <component> <pattern>...",
	Short: "Append patterns to a scope rule's include list (or --exclude list)",
	Long: "Append one or more patterns to scope.<component>.include (or .exclude with --exclude). The same as " +
		"'scope set <component>.include.add <patterns>': validated, written in place, global config or --project overlay.",
	Example: "  vigolium scope add host '*.example.com' example.com\n  vigolium scope add path '/admin/*' --exclude",
	Args:    cobra.MinimumNArgs(2),
	RunE:    func(cmd *cobra.Command, args []string) error { return runScopeListEdit(cmd, args, "add") },
}

var scopeRmCmd = &cobra.Command{
	Use:     "rm <component> <pattern>...",
	Aliases: []string{"remove"},
	Short:   "Remove patterns from a scope rule's include list (or --exclude list)",
	Long: "Remove one or more patterns from scope.<component>.include (or .exclude with --exclude). A pattern the list " +
		"does not hold is ignored (changed false when none was).",
	Example: "  vigolium scope rm host '*.example.com'\n  vigolium scope rm path '/admin/*' --exclude",
	Args:    cobra.MinimumNArgs(2),
	RunE:    func(cmd *cobra.Command, args []string) error { return runScopeListEdit(cmd, args, "remove") },
}

var scopeCheckCmd = &cobra.Command{
	Use:   "check <url>",
	Short: "Say whether a URL is in scope, and which rule and pattern refuse it",
	Long: "Evaluate a URL's host and path against the scope (global config, plus --project's overlay; -t targets " +
		"anchor scope.cli_origin_mode as they do on a scan). Prints in_scope, and for a refused URL the rule " +
		"(scope.host.exclude, scope.path.include, static_file, …) and the pattern responsible. Sends nothing.",
	Example: "  vigolium scope check https://admin.example.com/login -j",
	Args:    cobra.ExactArgs(1),
	RunE:    runScopeCheck,
}

func init() {
	for _, c := range []*cobra.Command{scopeAddCmd, scopeRmCmd} {
		c.Flags().BoolVar(&scopeEditExclude, "exclude", false, "Edit the exclude list instead of the include list")
		c.Flags().StringVar(&scopeSetProject, "project", "", "Write the project's config overlay instead of the global config")
		c.Flags().BoolVar(&scopeSetDryRun, "dry-run", false, "Show the rule's old and new value, without editing the config")
		scopeCmd.AddCommand(c)
	}
	scopeCheckCmd.Flags().StringVar(&scopeSetProject, "project", "", "Apply this project's scope overlay (UUID, name or unique 8+ char UUID prefix)")
	scopeCmd.AddCommand(scopeCheckCmd)

	for _, name := range []string{"scope add", "scope rm"} {
		registerCommandSchema(contract.Command{Name: name, Item: scopeSetView{},
			Description: "The scope rule edited: its value before and after, and which config layer was written."})
	}
	registerCommandSchema(contract.Command{Name: "scope check", Item: scopeCheckView{}, ItemsKind: contract.ItemsObject,
		Description: "Whether a URL is in scope; for a refused one, the rule and the pattern responsible."})
}

// runScopeListEdit turns `scope add|rm <component> <patterns>` into the
// `scope set <component>.<list>.<op> <json list>` it means.
func runScopeListEdit(cmd *cobra.Command, args []string, op string) error {
	component := strings.ToLower(strings.TrimSpace(args[0]))
	list := "include"
	if scopeEditExclude {
		list = "exclude"
	}
	value, err := json.Marshal(args[1:])
	if err != nil {
		return err
	}
	return runScopeSet(cmd, []string{component + "." + list + "." + op, string(value)})
}

// scopeCheckView is the `scope check -j` item.
type scopeCheckView struct {
	URL     string `json:"url"`
	Host    string `json:"host"`
	Path    string `json:"path"`
	InScope bool   `json:"in_scope"`
	Rule    string `json:"rule,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Project string `json:"project_uuid,omitempty"`
}

func runScopeCheck(cmd *cobra.Command, args []string) error {
	raw := strings.TrimSpace(args[0])
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return usageErrorf("%q is not a URL", args[0])
	}
	if scopeSetProject != "" {
		resolved, err := resolveProjectRefArg(cmd.Context(), scopeSetProject)
		if err != nil {
			return err
		}
		scopeSetProject = resolved
	}
	settings, err := config.LoadSettingsWithProject(globalConfig, scopeSetProject)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	m := config.NewScopeMatcher(settings.Scope, globalTargets...)
	rule, pattern := m.RejectDetail(u.Hostname(), path)
	v := scopeCheckView{URL: u.String(), Host: u.Hostname(), Path: path, InScope: rule == "", Rule: rule, Pattern: pattern, Project: scopeSetProject}
	if globalJSON {
		return emitObject(cmd, "", v)
	}
	if v.InScope {
		fmt.Printf("%s %s is in scope\n", terminal.SuccessSymbol(), v.URL)
		return nil
	}
	fmt.Printf("%s %s is out of scope: %s", terminal.WarningSymbol(), v.URL, v.Rule)
	if v.Pattern != "" {
		fmt.Printf(" (%s)", v.Pattern)
	}
	fmt.Println()
	return nil
}

// ---- auth show / rm --------------------------------------------------------

var (
	authVerbHost        string
	authShowShowSecrets bool
	authRmDryRun        bool
)

var authShowCmd = &cobra.Command{
	Use:   "show <session-name>",
	Short: "Show one stored session (tokens and credentials redacted)",
	Long: "Print the stored session(s) with this name in the active project, one row per host. Tokens, auth headers " +
		"and login requests are redacted unless --show-secrets. --host narrows to one host.",
	Example: "  vigolium auth show admin -j\n  vigolium auth show admin --host app.example.com",
	Args:    cobra.ExactArgs(1),
	RunE:    runAuthShow,
}

var authRmCmd = &cobra.Command{
	Use:     "rm <session-name>",
	Aliases: []string{"remove", "delete"},
	Short:   "Delete a stored session",
	Long:    "Delete the stored session(s) with this name in the active project (every host, or --host's only).",
	Example: "  vigolium auth rm admin\n  vigolium auth rm admin --host app.example.com --dry-run -j",
	Args:    cobra.ExactArgs(1),
	RunE:    runAuthRm,
}

func init() {
	authShowCmd.Flags().StringVar(&authVerbHost, "host", "", "Only the session stored for this hostname")
	authShowCmd.Flags().BoolVar(&authShowShowSecrets, "show-secrets", false, "Reveal tokens and credentials in plaintext; prints a warning to stderr")
	authRmCmd.Flags().StringVar(&authVerbHost, "host", "", "Only delete the session stored for this hostname")
	authRmCmd.Flags().BoolVar(&authRmDryRun, "dry-run", false, "Show what would be deleted, without deleting")
	authCmd.AddCommand(authShowCmd, authRmCmd)

	registerCommandSchema(contract.Command{Name: "auth show", Item: authSessionView{}, Extras: authShowExtras{},
		Description: "The stored session rows with that name (one per host), redacted unless --show-secrets."})
	registerCommandSchema(contract.Command{Name: "auth rm", Item: authSessionView{},
		Description: "The session rows deleted (redacted)."})
}

type authShowExtras struct {
	Redacted bool `json:"redacted"`
}

// sessionRowsNamed returns the active project's session rows with name (and
// host, when set).
func sessionRowsNamed(ctx context.Context, name string) (*database.Repository, string, []*database.AuthenticationHostname, error) {
	db, err := getDB()
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to open database: %w", err)
	}
	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return nil, "", nil, err
	}
	var rows []*database.AuthenticationHostname
	if authVerbHost != "" {
		rows, err = repo.GetAuthenticationHostnamesByHostname(ctx, projectUUID, authVerbHost)
	} else {
		rows, err = repo.GetAuthenticationHostnamesByProject(ctx, projectUUID)
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to read sessions: %w", err)
	}
	var out []*database.AuthenticationHostname
	names := map[string]bool{}
	for _, r := range rows {
		names[r.SessionName] = true
		if r.SessionName == name {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		cliErr := clicommon.CLIError{
			Err:  fmt.Errorf("no stored session named %q in this project", name),
			Code: apicontract.CodeNotFound,
			Hint: "list them with: vigolium auth list",
		}
		for n := range names {
			if strings.EqualFold(n, name) {
				cliErr.DidYouMean = n
			}
		}
		return nil, "", nil, cliErr
	}
	return repo, projectUUID, out, nil
}

func runAuthShow(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	_, projectUUID, rows, err := sessionRowsNamed(context.Background(), args[0])
	if err != nil {
		return err
	}
	if authShowShowSecrets {
		fmt.Fprintf(os.Stderr, "%s Revealing session tokens and login credentials in plaintext.\n", terminal.WarningSymbol())
	}
	views := newAuthSessionViews(rows, authShowShowSecrets)
	if globalJSON {
		return emitRead(cmd, "", views, int64(len(views)), 0, len(views),
			withProjectScope(projectUUID), withDBPath(resolvedReadDBPath()), withExtra("redacted", !authShowShowSecrets))
	}
	for _, v := range views {
		fmt.Printf("%s %s @ %s (role %s, position %d)\n", terminal.InfoSymbol(), v.SessionName, v.Hostname, firstNonEmptyString(v.SessionRole, "-"), v.Position)
		if v.HasSessionToken {
			fmt.Printf("  token:   %s (fingerprint %s)\n", firstNonEmptyString(v.SessionToken, "set"), v.SessionTokenFingerprint)
		}
		if len(v.HeaderNames) > 0 {
			fmt.Printf("  headers: %s\n", strings.Join(v.HeaderNames, ", "))
		}
		for k, val := range v.Headers {
			fmt.Printf("  %s: %s\n", k, val)
		}
	}
	return nil
}

func runAuthRm(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	ctx := context.Background()
	repo, projectUUID, rows, err := sessionRowsNamed(ctx, args[0])
	if err != nil {
		return err
	}
	if !authRmDryRun {
		for _, r := range rows {
			if err := repo.DeleteAuthenticationHostname(ctx, r.ID); err != nil {
				return fmt.Errorf("delete session %s@%s: %w", r.SessionName, r.Hostname, err)
			}
		}
	}
	views := newAuthSessionViews(rows, false)
	if globalJSON {
		return emitMutation(cmd, "", mutationResult{Changed: true, Action: "delete", DryRun: authRmDryRun, Items: views},
			withProjectScope(projectUUID), withDBPath(resolvedReadDBPath()))
	}
	verb := "Deleted"
	if authRmDryRun {
		verb = "Dry run: would delete"
	}
	for _, r := range rows {
		fmt.Printf("%s %s session %s @ %s\n", terminal.SuccessSymbol(), verb, r.SessionName, r.Hostname)
	}
	return nil
}

// ---- project current / rename ----------------------------------------------

var projectCurrentCmd = &cobra.Command{
	Use:     "current",
	Short:   "Show the project commands run against, and where that choice came from",
	Example: "  vigolium project current -j",
	Args:    cobra.NoArgs,
	RunE:    runProjectCurrent,
}

var projectRenameCmd = &cobra.Command{
	Use:     "rename <project> <new-name>",
	Short:   "Rename a project",
	Long:    "Rename a project (UUID, exact name, or unique 8+ char UUID prefix). The new name must not belong to another project.",
	Example: "  vigolium project rename acme-old acme",
	Args:    cobra.ExactArgs(2),
	RunE:    runProjectRename,
}

func init() {
	projectCmd.AddCommand(projectCurrentCmd, projectRenameCmd)
	registerCommandSchema(contract.Command{Name: "project current", Item: projectCurrentView{}, ItemsKind: contract.ItemsObject,
		Description: "The project this invocation resolves to, and where the selection came from (flag, env, active_file, default)."})
	registerCommandSchema(contract.Command{Name: "project rename", Item: projectRenameView{},
		Description: "The project renamed, with its previous name."})
}

type projectCurrentView struct {
	UUID   string `json:"uuid"`
	Name   string `json:"name,omitempty"`
	Source string `json:"source"`
}

type projectRenameView struct {
	projectMutationView
	PreviousName string `json:"previous_name"`
}

func runProjectCurrent(cmd *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	v := projectCurrentView{UUID: projectUUID}
	v.Source, _ = currentProjectSource()
	if db, err := getDB(); err == nil {
		if p, err := database.NewRepository(db).GetProjectByUUID(context.Background(), projectUUID); err == nil && p != nil {
			v.Name = p.Name
		}
	}
	if globalJSON {
		return emitObject(cmd, "", v)
	}
	name := v.Name
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Printf("%s (%s) [%s]\n", name, v.UUID, v.Source)
	return nil
}

func runProjectRename(cmd *cobra.Command, args []string) error {
	if err := checkProjectReadonly(); err != nil {
		return err
	}
	defer closeDatabaseOnExit()
	ctx := context.Background()
	newName := strings.TrimSpace(args[1])
	if newName == "" {
		return usageErrorf("the new project name must not be empty")
	}
	projectUUID, err := resolveProjectRefArg(ctx, args[0])
	if err != nil {
		return err
	}
	repo, err := openProjectRepo(ctx)
	if err != nil {
		return err
	}
	project, err := repo.GetProjectByUUID(ctx, projectUUID)
	if err != nil || project == nil {
		return codedErrorf(apicontract.CodeProjectNotFound, "project %q not found", args[0])
	}
	if other, err := repo.GetProjectByName(ctx, newName); err == nil && other != nil && other.UUID != project.UUID {
		return usageErrorf("another project (%s) is already named %q", other.UUID, newName)
	}
	previous := project.Name
	changed := previous != newName
	if changed {
		project.Name = newName
		if err := repo.UpdateProject(ctx, project); err != nil {
			return err
		}
	}
	if globalJSON {
		action := "update"
		if !changed {
			action = "noop"
		}
		return emitMutation(cmd, "", mutationResult{Changed: changed, Action: action,
			Items: []projectRenameView{{projectMutationView: newProjectMutationView(project), PreviousName: previous}}},
			withProjectUUID(project.UUID))
	}
	fmt.Printf("%s Renamed project %s: %s → %s\n", terminal.SuccessSymbol(), project.UUID, previous, newName)
	return nil
}

// ---- module show -----------------------------------------------------------

var moduleShowCmd = &cobra.Command{
	Use:     "show <module-id>",
	Short:   "Show one module: description, confirmation criteria, severity, scope, tags, enabled",
	Example: "  vigolium module show reflected-ssti -j",
	Args:    cobra.ExactArgs(1),
	RunE:    runModuleShow,
}

func init() {
	moduleCmd.AddCommand(moduleShowCmd)
	registerCommandSchema(contract.Command{Name: "module show", Item: moduleJSONEntry{}, ItemsKind: contract.ItemsObject,
		Description: "One module's full description."})
}

func runModuleShow(cmd *cobra.Command, args []string) error {
	id := strings.TrimSpace(args[0])
	matches := findMatchingModules(id, true)
	if len(matches) == 0 {
		matches = findMatchingModules(id, false)
	}
	switch {
	case len(matches) == 0:
		return codedErrorf(apicontract.CodeNotFound, "no module %q (list them with `vigolium module ls`)", id)
	case len(matches) > 1:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.id)
		}
		if len(ids) > 10 {
			ids = append(ids[:10], "…")
		}
		return clicommon.CLIError{Err: fmt.Errorf("%q matches %d modules: %s", id, len(matches), strings.Join(ids, ", ")),
			Hint: "give the exact module ID"}
	}
	entry, ok := moduleEntryByID(matches[0].id)
	if !ok {
		return codedErrorf(apicontract.CodeNotFound, "no module %q", id)
	}
	if globalJSON {
		return emitObject(cmd, "", entry)
	}
	status := terminal.Green("enabled")
	if !entry.Enabled {
		status = terminal.Yellow("disabled")
	}
	fmt.Printf("%s [%s] %s  %s\n", terminal.Cyan(entry.ID), entry.Type, entry.Name, status)
	fmt.Printf("  severity %s, confidence %s, scope %s\n", entry.Severity, entry.Confidence, strings.Join(entry.ScanScope, ", "))
	if len(entry.Tags) > 0 {
		fmt.Printf("  tags: %s\n", strings.Join(entry.Tags, ", "))
	}
	fmt.Printf("\n%s\n", entry.Description)
	if entry.ConfirmationCriteria != "" {
		fmt.Printf("\nConfirmation: %s\n", entry.ConfirmationCriteria)
	}
	return nil
}

// moduleEntryByID builds the module ls -j row for one module.
func moduleEntryByID(id string) (moduleJSONEntry, bool) {
	em := loadEnabledModulesConfig()
	build := newModuleJSONEntry
	for _, m := range modules.GetActiveModules() {
		if m.ID() == id {
			return build(m, "active", em.ActiveEnabled(id)), true
		}
	}
	for _, m := range modules.GetPassiveModules() {
		if m.ID() == id {
			return build(m, "passive", em.PassiveEnabled(id)), true
		}
	}
	return moduleJSONEntry{}, false
}

// ---- finding show ----------------------------------------------------------

var findingShowCmd = &cobra.Command{
	Use:   "show <id|hash-prefix>...",
	Short: "Show findings by id or finding-hash prefix, with their evidence records",
	Long: "Print the named findings in full, with the HTTP records attached to them. A bare integer is a finding id; " +
		"anything else is a finding_hash prefix. Unknown ones are listed and the command exits 1 (finding_not_found).",
	Example: "  vigolium finding show 42 -j\n  vigolium finding show 5a5a5a5a",
	Args:    cobra.MinimumNArgs(1),
	RunE:    runFindingShow,
}

func init() {
	findingCmd.AddCommand(findingShowCmd)
	registerCommandSchema(contract.Command{Name: "finding show", Item: findingViewSchema{}, Extras: findingShowExtras{},
		Description: "The named findings as finding views with their records; not_found lists the selectors that matched nothing."})
}

type findingShowExtras struct {
	NotFound []string `json:"not_found"`
}

func runFindingShow(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	ids, hashes, err := findingSelectors(args)
	if err != nil {
		return err
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	ctx := context.Background()
	findings, notFound, err := database.NewRepository(db).ResolveFindings(ctx, projectUUID, ids, hashes)
	if err != nil {
		var amb *database.AmbiguousFindingHashError
		if errors.As(err, &amb) {
			return usageErrorf("%v", amb)
		}
		return err
	}
	if notFound == nil {
		notFound = []string{}
	}
	if globalJSON {
		views := findingViews(ctx, db, findings, agentViewOptions{redact: jsonRedactOn}, true)
		env := newMachineEnvelope(cmd, kindRead, "", views, int64(len(findings)), 0, len(findings))
		env.WithProjectScope(projectUUID)
		env.DBPath = resolvedReadDBPath()
		env.With("not_found", notFound)
		if err := writeAgentJSON(env); err != nil {
			return err
		}
	} else if len(findings) > 0 {
		if err := displayFindingsMarkdown(ctx, db, findings); err != nil {
			return err
		}
	}
	if len(notFound) > 0 {
		return clicommon.CLIError{
			Err:  fmt.Errorf("%d finding(s) not found in this project: %s", len(notFound), strings.Join(notFound, ", ")),
			Code: apicontract.CodeFindingNotFound,
			Hint: "list findings with: vigolium finding",
		}
	}
	return nil
}

// ---- config get / unset schemas --------------------------------------------
//
// The commands live in pkg/cli/configcmd; their row types are mirrored here,
// where the schema registry is (configcmd cannot import pkg/cli).

type configGetExtras struct {
	ConfigPath string `json:"config_path"`
	Redacted   bool   `json:"redacted"`
}

type configUnsetView struct {
	Key        string `json:"key"`
	Removed    bool   `json:"removed"`
	ConfigPath string `json:"config_path"`
}

func init() {
	registerCommandSchema(contract.Command{Name: "config get", Item: configEntrySchema{}, Extras: configGetExtras{},
		Description: "One configuration key (or every key under a section) with its typed value, default, type and source layer; string credentials redacted unless --show-secrets."})
	registerCommandSchema(contract.Command{Name: "config unset", Item: configUnsetView{},
		Description: "The key removed from the config file (removed false when the file did not set it)."})
}
