package cli

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
	"github.com/vigolium/vigolium/public"
)

// embedSkillsRoot is the directory inside public.StaticFS that holds the
// coding-agent-facing skill bundles.
const embedSkillsRoot = "skills"

// defaultInstallSkill is installed when `skills install` is run without an
// explicit skill name.
const defaultInstallSkill = "vigolium-scanner"

var skillsOpts = &skillsOptions{}

type skillsOptions struct {
	Full     bool
	All      bool
	Agent    string
	Scope    string
	Dir      string
	Refs     []string
	ListRefs bool
	Profile  string
}

// bundledSkill is a parsed skill bundle shipped inside the binary.
type bundledSkill struct {
	Name        string   // directory / frontmatter name (e.g. "vigolium-scanner")
	Description string   // frontmatter description
	EmbedDir    string   // path inside public.StaticFS (e.g. "skills/vigolium-scanner")
	References  []string // reference file paths relative to EmbedDir (e.g. "references/commands.md")
}

// Parent command: vigolium skills [list]
var skillsCmd = &cobra.Command{
	Use:     "skills [subcommand]",
	Aliases: []string{"skill"},
	Short:   "List, inspect, and install bundled coding-agent skills",
	Long: `List and retrieve the skill bundles shipped with this CLI, and install them
into a coding agent's skills directory.

The bundled skills teach an AI coding agent (Claude Code, Codex, or any
agentskills.io-compatible agent) how to drive the vigolium CLI. Because the
content is embedded in the binary, it always matches the installed version —
prefer 'vigolium skills install' over copying stale files by hand.

Running 'vigolium skills' with no subcommand is a shortcut for 'skills list'.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsList(cmd)
	},
}

// Subcommand: vigolium skills list
var skillsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all bundled skills",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsList(cmd)
	},
}

// Subcommand: vigolium skills get <name>...
var skillsGetCmd = &cobra.Command{
	Use:   "get [name...]",
	Short: "Print a skill's full content",
	Long: `Print a skill's SKILL.md to stdout. Pass --full to also include its
reference files, or --all to output every bundled skill.

One reference file: --ref <name> (recipes, recipes.md or references/recipes.md;
repeatable), or the path form <skill>/references/<file>.md. --list-refs lists
the skill's files with their sizes instead of printing them, so an agent can
fetch only the reference it needs.

With -j the content comes back in the envelope instead: one item per skill,
with its markdown in "content" and, under --full, each reference file as
{"path","content"} in "references". With --ref, one item per reference
({name, path, content}); with --list-refs, one item per file
({name, path, bytes, lines}).`,
	Example: `  # The router, then one reference
  vigolium skills get vigolium-scanner
  vigolium skills get vigolium-scanner --ref recipes
  vigolium skills get vigolium-scanner/references/invariants.md
  # What there is to read, with sizes
  vigolium skills get vigolium-scanner --list-refs -j`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsGet(cmd, args)
	},
}

// Subcommand: vigolium skills install [name]...
var skillsInstallCmd = &cobra.Command{
	Use:   "install [name...]",
	Short: "Install skill bundle(s) into a coding agent's skills directory",
	Long: `Copy one or more bundled skills into a coding agent's skills directory so
the agent can auto-trigger on them.

With no name, installs the '` + defaultInstallSkill + `' skill. Pass --all to install
every bundle, or name specific skills.

Destination is chosen from --agent and --scope:

  --agent claude          .claude/skills/   (project)   ~/.claude/skills/   (global)
  --agent codex|agents    .agents/skills/   (project)   ~/.agents/skills/   (global)

Each install writes a .vigolium-skill.json manifest beside SKILL.md (binary
version, commit, bundle sha256, every file's sha256). An existing install is
skipped unless --force is given, and reported as current, stale (another
bundle, or an install without a manifest: run 'skills install --force') or
modified (local edits). --force deletes files the old manifest lists that this
bundle no longer ships; an install without a manifest is moved to
<dir>.bak-<timestamp> first (its SKILL.md renamed SKILL.md.bak so the agent
does not load it). --dir overrides the computed destination entirely.

'vigolium skills ls' shows the state of every install location and
'vigolium doctor --fix' reinstalls stale copies.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsInstall(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(skillsCmd)
	skillsCmd.AddCommand(skillsListCmd, skillsGetCmd, skillsInstallCmd)

	skillsGetCmd.Flags().BoolVar(&skillsOpts.Full, "full", false, "Include reference files, not just SKILL.md")
	skillsGetCmd.Flags().BoolVar(&skillsOpts.All, "all", false, "Output every bundled skill")
	skillsGetCmd.Flags().StringArrayVar(&skillsOpts.Refs, "ref", nil, "Print only this reference file: recipes, recipes.md or references/recipes.md (repeatable)")
	skillsGetCmd.Flags().BoolVar(&skillsOpts.ListRefs, "list-refs", false, "List the skill's files (SKILL.md and references) with byte and line counts instead of printing them")
	skillsGetCmd.Flags().StringVar(&skillsOpts.Profile, "profile", "", "Print a generated profile of vigolium-scanner instead of the bundle: embedded (the safe verb set and the contract pointer, stamped with this build)")
	registerCommandSchema(contract.Command{Name: "skills get", Item: skillGetItem{},
		Variants:    []contract.Variant{{Flag: "--list-refs", Item: skillFileView{}}},
		Description: "One item per skill (its SKILL.md in content, references under --full), per reference with --ref, or per file with --list-refs."})

	skillsInstallCmd.Flags().StringVar(&skillsOpts.Agent, "agent", "claude", "Target coding agent: claude, codex, or agents")
	skillsInstallCmd.Flags().StringVar(&skillsOpts.Scope, "scope", "project", "Install scope: project (current folder) or global (home dir)")
	skillsInstallCmd.Flags().BoolVar(&skillsOpts.All, "all", false, "Install every bundled skill")
	skillsInstallCmd.Flags().StringVar(&skillsOpts.Dir, "dir", "", "Override the destination directory (--agent/--scope are still validated, but do not pick the path)")

	registerCommandSchema(contract.Command{Name: "skills install", Item: skillInstallView{}, Extras: skillInstallExtras{},
		Description: "One item per skill bundle: where it went, the state found (status) and the state left (status_after)."})
}

// loadBundledSkills discovers and parses every skill bundle embedded under
// public.StaticFS/skills. A "bundle" is a directory containing a SKILL.md.
func loadBundledSkills() ([]bundledSkill, error) {
	entries, err := fs.ReadDir(public.StaticFS, embedSkillsRoot)
	if err != nil {
		return nil, fmt.Errorf("read embedded skills: %w", err)
	}

	var out []bundledSkill
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		embedDir := embedSkillsRoot + "/" + e.Name()
		skillMd := embedDir + "/SKILL.md"
		raw, readErr := public.StaticFS.ReadFile(skillMd)
		if readErr != nil {
			continue // not a skill bundle
		}

		// The directory name is the bundle's canonical identity: it's what
		// `install` names the destination dir and what CLI args reference.
		// Only the description is pulled from frontmatter, for display.
		// Bundles are first-party and authored in-tree, so a bundle that
		// skill.Parse rejects is a bug to fix, not to route around — it
		// simply lists without a description.
		desc := ""
		if parsed, perr := skill.Parse(raw, skillMd, embedDir, skill.SourceEmbedded); perr == nil {
			desc = parsed.Description
		}

		out = append(out, bundledSkill{
			Name:        e.Name(),
			Description: desc,
			EmbedDir:    embedDir,
			References:  listBundleReferences(embedDir),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// listBundleReferences returns the reference files under <embedDir>/references,
// as paths relative to embedDir, sorted.
func listBundleReferences(embedDir string) []string {
	refDir := embedDir + "/references"
	entries, err := fs.ReadDir(public.StaticFS, refDir)
	if err != nil {
		return nil
	}
	var refs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		refs = append(refs, "references/"+e.Name())
	}
	sort.Strings(refs)
	return refs
}

// findBundle returns the bundle with the given name (case-insensitive).
func findBundle(skills []bundledSkill, name string) (bundledSkill, bool) {
	for _, s := range skills {
		if strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return bundledSkill{}, false
}

// bundleNames joins bundle names for error messages.
func bundleNames(skills []bundledSkill) string {
	names := make([]string, len(skills))
	for i, s := range skills {
		names[i] = s.Name
	}
	return strings.Join(names, ", ")
}

// resolveNamedTargets maps explicit skill names to bundles, erroring on the
// first unknown name. Shared by get/install.
func resolveNamedTargets(skills []bundledSkill, names []string) ([]bundledSkill, error) {
	targets := make([]bundledSkill, 0, len(names))
	for _, n := range names {
		b, ok := findBundle(skills, n)
		if !ok {
			return nil, usageErrorf("unknown skill %q (available: %s)", n, bundleNames(skills))
		}
		targets = append(targets, b)
	}
	return targets, nil
}

// writeBody writes raw bytes to stdout, appending a newline only when the
// content doesn't already end with one.
func writeBody(data []byte) {
	_, _ = os.Stdout.Write(data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		fmt.Println()
	}
}

func runSkillsList(cmd *cobra.Command) error {
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}

	if globalJSON {
		type jsonEntry struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			EmbedPath   string   `json:"embed_path"`
			References  []string `json:"references"`
		}
		entries := make([]jsonEntry, len(skills))
		for i, s := range skills {
			entries[i] = jsonEntry{s.Name, s.Description, s.EmbedDir, s.References}
		}
		return emitRead(cmd, "skills", entries, int64(len(entries)), 0, len(entries),
			withExtra("installed", scanInstalledSkills(skills)))
	}

	if len(skills) == 0 {
		fmt.Printf("%s No skills to show.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("\n  %s %s bundled skill(s)\n\n",
		terminal.InfoSymbol(), terminal.BoldCyan(fmt.Sprintf("%d", len(skills))))

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "DESCRIPTION", "REFS")
	for _, s := range skills {
		tbl.AddRow(terminal.Cyan(s.Name), s.Description, terminal.Gray(fmt.Sprintf("%d", len(s.References))))
	}
	tbl.Print()
	printInstalledSkills(scanInstalledSkills(skills))

	fmt.Printf("\n%s Read a skill:    %s\n", terminal.InfoSymbol(), terminal.Gray("vigolium skills get "+skills[0].Name+" (then --list-refs, --ref <file>)"))
	fmt.Printf("%s Install a skill: %s\n", terminal.InfoSymbol(), terminal.Gray("vigolium skills install --agent claude --scope project"))
	return nil
}

// printInstalledSkills lists the install locations that hold a bundled skill,
// with their state, and how to refresh a stale one.
func printInstalledSkills(views []skillInstalledView) {
	var found []skillInstalledView
	stale := false
	for _, v := range views {
		if v.Status == skillStatusMissing {
			continue
		}
		found = append(found, v)
		stale = stale || v.Status == skillStatusStale
	}
	if len(found) == 0 {
		fmt.Printf("\n%s Not installed in ./.claude/skills, ~/.claude/skills, ./.agents/skills or ~/.agents/skills.\n", terminal.InfoSymbol())
		return
	}
	fmt.Printf("\n  %s installed\n\n", terminal.BoldCyan(fmt.Sprintf("%d", len(found))))
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "AGENT", "SCOPE", "STATUS", "VERSION", "PATH")
	for _, v := range found {
		status := terminal.Green(v.Status)
		if v.Status != skillStatusCurrent {
			status = terminal.Yellow(v.Status)
		}
		tbl.AddRow(terminal.Cyan(v.Name), v.Agent, v.Scope, status, v.Version, terminal.Gray(v.Path))
	}
	tbl.Print()
	if stale {
		fmt.Printf("\n%s stale: run %s (with the matching --agent/--scope), or %s\n", terminal.WarningSymbol(),
			terminal.Gray("vigolium skills install --force"), terminal.Gray("vigolium doctor --fix --only skill"))
	}
}

// skillGetItem is one skill under `skills get -j`.
type skillGetItem struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	EmbedPath   string `json:"embed_path"`
	// Path is the reference file this item holds, under --ref.
	Path       string           `json:"path,omitempty"`
	Content    string           `json:"content"`
	References []skillReference `json:"references,omitempty"`
}

// skillFileView is one file of a skill under `skills get --list-refs`.
type skillFileView struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
	Lines int    `json:"lines"`
}

// skillReference is one reference file of a skill, included under --full.
type skillReference struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func runSkillsGet(cmd *cobra.Command, names []string) error {
	if skillsOpts.Profile != "" {
		return runSkillsGetProfile(cmd, names)
	}
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}

	// The path form names one file: <skill>/references/<file>.md.
	refs := append([]string(nil), skillsOpts.Refs...)
	bare := make([]string, 0, len(names))
	for _, n := range names {
		skillName, file, isPath := strings.Cut(n, "/")
		if isPath {
			refs = append(refs, file)
		}
		bare = append(bare, skillName)
	}
	modes := 0
	for _, on := range []bool{skillsOpts.Full, len(refs) > 0, skillsOpts.ListRefs} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return usageErrorf("skills get: --full, --ref (or a <skill>/<file> path) and --list-refs are mutually exclusive")
	}

	var targets []bundledSkill
	switch {
	case skillsOpts.All:
		targets = skills
	case len(bare) == 0:
		return usageErrorf("skills get: provide a skill name or --all (available: %s)", bundleNames(skills))
	default:
		if targets, err = resolveNamedTargets(skills, bare); err != nil {
			return err
		}
		targets = uniqueBundles(targets)
	}

	if skillsOpts.ListRefs {
		return emitSkillFiles(cmd, targets)
	}
	if len(refs) > 0 {
		return emitSkillRefs(cmd, targets, refs)
	}
	if globalJSON {
		return emitSkillsGetJSON(cmd, targets)
	}

	for i, b := range targets {
		if len(targets) > 1 {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("===== %s =====\n\n", b.Name)
		}
		body, readErr := public.StaticFS.ReadFile(b.EmbedDir + "/SKILL.md")
		if readErr != nil {
			return fmt.Errorf("read %s: %w", b.Name, readErr)
		}
		writeBody(skillTextForSession(body))

		if skillsOpts.Full {
			for _, ref := range b.References {
				refBody, refErr := public.StaticFS.ReadFile(b.EmbedDir + "/" + ref)
				if refErr != nil {
					continue
				}
				fmt.Printf("\n\n----- %s/%s -----\n\n", b.Name, ref)
				writeBody(skillTextForSession(refBody))
			}
		}
	}
	return nil
}

// skillTextForSession is skill markdown as this session may read it: under
// VIGOLIUM_PINNED=1, without the lines naming what the pin refuses and with
// the pin's note (pinnedSkillView); otherwise unchanged.
func skillTextForSession(md []byte) []byte {
	if !pinnedEnv() {
		return md
	}
	return []byte(pinnedSkillView(string(md)))
}

// runSkillsGetProfile answers `skills get vigolium-scanner --profile <name>`.
func runSkillsGetProfile(cmd *cobra.Command, names []string) error {
	if skillsOpts.Profile != skillProfileEmbedded {
		return usageErrorf("skills get: unknown --profile %q (want: %s)", skillsOpts.Profile, skillProfileEmbedded)
	}
	if skillsOpts.Full || skillsOpts.All || skillsOpts.ListRefs || len(skillsOpts.Refs) > 0 {
		return usageErrorf("skills get: --profile prints one generated document; drop --full, --all, --ref and --list-refs")
	}
	if len(names) != 1 || names[0] != defaultInstallSkill {
		return usageErrorf("skills get: --profile %s is a profile of %s: vigolium skills get %s --profile %s",
			skillsOpts.Profile, defaultInstallSkill, defaultInstallSkill, skillsOpts.Profile)
	}
	content := embeddedSkillProfile(rootCmd)
	if globalJSON {
		item := skillGetItem{Name: defaultInstallSkill, Description: "embedded profile, generated from this build",
			EmbedPath: "profile:" + skillProfileEmbedded, Content: content}
		return emitRead(cmd, "", []skillGetItem{item}, 1, 0, 1)
	}
	writeBody([]byte(content))
	return nil
}

// emitSkillsGetJSON writes the requested skills as envelope rows, with each
// SKILL.md (and, under --full, every reference file) as content. The raw
// markdown stream is the human form; under -j the one document is the contract.
func emitSkillsGetJSON(cmd *cobra.Command, targets []bundledSkill) error {
	items := make([]skillGetItem, 0, len(targets))
	for _, b := range targets {
		body, err := public.StaticFS.ReadFile(b.EmbedDir + "/SKILL.md")
		if err != nil {
			return fmt.Errorf("read %s: %w", b.Name, err)
		}
		item := skillGetItem{Name: b.Name, Description: b.Description, EmbedPath: b.EmbedDir, Content: string(skillTextForSession(body))}
		if skillsOpts.Full {
			item.References = []skillReference{}
			for _, ref := range b.References {
				refBody, refErr := public.StaticFS.ReadFile(b.EmbedDir + "/" + ref)
				if refErr != nil {
					continue
				}
				item.References = append(item.References, skillReference{Path: ref, Content: string(skillTextForSession(refBody))})
			}
		}
		items = append(items, item)
	}
	return emitRead(cmd, "", items, int64(len(items)), 0, len(items))
}

// skillsInstallBaseDir resolves the parent directory that skill bundles are
// installed into, from --agent and --scope. Returns an absolute path.
func skillsInstallBaseDir(agent, scope string) (string, error) {
	var sub string
	switch strings.ToLower(agent) {
	case "claude":
		sub = skill.ClaudeSkillsSubdir
	case "codex", "agents":
		sub = skill.AgentsSkillsSubdir
	default:
		return "", usageErrorf("unknown --agent %q (want: claude, codex, or agents)", agent)
	}

	switch strings.ToLower(scope) {
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve working directory: %w", err)
		}
		return filepath.Join(cwd, sub), nil
	case "global":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, sub), nil
	default:
		return "", usageErrorf("unknown --scope %q (want: project or global)", scope)
	}
}

func runSkillsInstall(cmd *cobra.Command, names []string) error {
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}

	// Resolve which bundles to install.
	var targets []bundledSkill
	switch {
	case skillsOpts.All:
		targets = skills
	case len(names) == 0:
		b, ok := findBundle(skills, defaultInstallSkill)
		if !ok {
			return fmt.Errorf("default skill %q is not bundled (available: %s)", defaultInstallSkill, bundleNames(skills))
		}
		targets = []bundledSkill{b}
	default:
		if targets, err = resolveNamedTargets(skills, names); err != nil {
			return err
		}
	}

	baseDir, err := resolveSkillsBaseDir()
	if err != nil {
		return err
	}

	out := humanOut()
	installed, skipped := 0, 0
	items := make([]skillInstallView, 0, len(targets))
	now := time.Now()
	for _, b := range targets {
		dest := filepath.Join(baseDir, b.Name)
		install := installSkillBundle
		if skillsInstallDryRun {
			install = previewSkillInstall
		}
		res, instErr := install(b, dest, globalForce, Version, Commit, now)
		if instErr != nil {
			return fmt.Errorf("install %s: %w", b.Name, instErr)
		}
		view := skillInstallView{Name: b.Name, Path: dest, Installed: res.Installed, Status: res.Status,
			StatusAfter: skillStatusAfterInstall(b, dest, res), PreviousVersion: res.Version, Backup: res.Backup, Pruned: res.Pruned}
		if !res.Installed {
			skipped++
			view.Reason = skillSkipReason(res.Status)
			printSkillSkip(out, b.Name, dest, res)
			items = append(items, view)
			continue
		}
		if res.Backup != "" {
			_, _ = fmt.Fprintf(out, "%s Moved the previous (unstamped) install of %s to %s\n",
				terminal.InfoSymbol(), terminal.Cyan(b.Name), terminal.Gray(res.Backup))
		}
		if len(res.Pruned) > 0 {
			_, _ = fmt.Fprintf(out, "%s Removed %d file(s) the bundle no longer ships: %s\n",
				terminal.InfoSymbol(), len(res.Pruned), terminal.Gray(strings.Join(res.Pruned, ", ")))
		}
		verbDone := "Installed"
		if skillsInstallDryRun {
			verbDone = "Dry run: would install"
		}
		_, _ = fmt.Fprintf(out, "%s %s %s → %s\n",
			terminal.SuccessSymbol(), verbDone, terminal.Cyan(b.Name), terminal.Gray(dest))
		installed++
		items = append(items, view)
	}

	if globalJSON {
		action := "install"
		if installed == 0 {
			action = "noop"
		}
		return emitMutation(cmd, "", mutationResult{
			Changed: installed > 0,
			Action:  action,
			DryRun:  skillsInstallDryRun,
			Items:   items,
			Extra:   map[string]any{"installed": installed, "skipped": skipped, "dir": baseDir},
		})
	}

	fmt.Printf("\n%s %d installed, %d skipped. Your agent will auto-trigger on these skills when you mention vigolium.\n",
		terminal.InfoSymbol(), installed, skipped)
	// --dir bypasses scope resolution entirely, so the hint would be noise.
	if skillsOpts.Dir == "" {
		printSkillsScopeHint(skillsOpts.Scope)
	}
	return nil
}

// skillInstallView is one bundle in `skills install -j`: where it went, and
// whether this run wrote it.
//
// status is the state found before this run (missing, current, stale,
// modified) and status_after the state this run left (a dry run: the state it
// would leave); reason says why a bundle was skipped (already_installed for a
// current copy, otherwise the status). previous_version, backup and pruned
// describe what a --force reinstall replaced.
type skillInstallView struct {
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	Installed       bool     `json:"installed"`
	Status          string   `json:"status"`
	StatusAfter     string   `json:"status_after"`
	Reason          string   `json:"reason,omitempty"`
	PreviousVersion string   `json:"previous_version,omitempty"`
	Backup          string   `json:"backup,omitempty"`
	Pruned          []string `json:"pruned,omitempty"`
}

// skillStatusAfterInstall is the install state at dest once this run is over:
// read back from disk after a real install, predicted for a dry run (a written
// bundle is current; a skipped one keeps its state).
func skillStatusAfterInstall(b bundledSkill, dest string, res skillInstallOutcome) string {
	if skillsInstallDryRun {
		if res.Installed {
			return skillStatusCurrent
		}
		return res.Status
	}
	_, digest, err := bundleContents(b)
	if err != nil {
		return res.Status
	}
	return inspectSkillInstall(dest, digest).Status
}

// resolveSkillsBaseDir is the parent directory install and uninstall work in:
// --dir when given, else the one --agent and --scope name. Both flags are
// validated either way, so a typo is never silently ignored next to --dir.
func resolveSkillsBaseDir() (string, error) {
	computed, err := skillsInstallBaseDir(skillsOpts.Agent, skillsOpts.Scope)
	if err != nil {
		return "", err
	}
	if skillsOpts.Dir == "" {
		return computed, nil
	}
	dir := config.ExpandPath(skillsOpts.Dir)
	if abs, absErr := filepath.Abs(dir); absErr == nil {
		dir = abs
	}
	return dir, nil
}

// skillInstallExtras are the top-level counters of `skills install -j`.
type skillInstallExtras struct {
	Installed int    `json:"installed"`
	Skipped   int    `json:"skipped"`
	Dir       string `json:"dir"`
}

// skillSkipReason names why an existing install was left alone.
func skillSkipReason(status string) string {
	if status == skillStatusCurrent {
		return "already_installed"
	}
	return status
}

// printSkillSkip explains a skipped install and what --force would do.
func printSkillSkip(out io.Writer, name, dest string, res skillInstallOutcome) {
	switch res.Status {
	case skillStatusStale:
		was := "an unstamped install"
		if res.Version != "" {
			was = "installed by " + res.Version
		}
		_, _ = fmt.Fprintf(out, "%s %s at %s is stale (%s; this binary is %s): run %s\n",
			terminal.WarningSymbol(), terminal.Cyan(name), terminal.Gray(dest), was, Version,
			terminal.Gray("vigolium skills install --force"))
	case skillStatusModified:
		_, _ = fmt.Fprintf(out, "%s %s at %s has local edits (use --force to overwrite them)\n",
			terminal.WarningSymbol(), terminal.Cyan(name), terminal.Gray(dest))
	default:
		_, _ = fmt.Fprintf(out, "%s %s already installed and current at %s\n",
			terminal.InfoSymbol(), terminal.Cyan(name), terminal.Gray(dest))
	}
}

// printSkillsScopeHint tells the user which scope they just installed into and
// how to pick the other one, so a project-local install isn't mistaken for a
// machine-wide one (and vice versa).
func printSkillsScopeHint(scope string) {
	if strings.EqualFold(scope, "global") {
		fmt.Printf("%s Installed globally (home dir) - available in every project. Use %s to install into the current folder instead.\n",
			terminal.InfoSymbol(), terminal.Gray("--scope project"))
		return
	}
	fmt.Printf("%s Installed for this project only. Use %s to install into your home dir for every project.\n",
		terminal.InfoSymbol(), terminal.Gray("--scope global"))
}

// copyEmbeddedSkillBundle recursively copies an embedded bundle directory to
// destRoot on disk, creating parent directories as needed.
func copyEmbeddedSkillBundle(embedDir, destRoot string) error {
	return fs.WalkDir(public.StaticFS, embedDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(embedDir, path)
		if relErr != nil {
			return relErr
		}
		dest := filepath.Join(destRoot, rel)

		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		data, readErr := public.StaticFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if mkErr := os.MkdirAll(filepath.Dir(dest), 0o755); mkErr != nil {
			return mkErr
		}
		return os.WriteFile(dest, data, 0o644)
	})
}

// uniqueBundles drops repeats, keeping the first: `get x/references/a.md
// x/references/b.md` names one skill twice.
func uniqueBundles(in []bundledSkill) []bundledSkill {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, b := range in {
		if !seen[b.Name] {
			seen[b.Name] = true
			out = append(out, b)
		}
	}
	return out
}

// bundleFiles is SKILL.md followed by the reference files, as paths relative
// to the bundle directory.
func bundleFiles(b bundledSkill) []string {
	return append([]string{"SKILL.md"}, b.References...)
}

// resolveSkillRef maps what was typed (recipes, recipes.md,
// references/recipes.md, SKILL.md) to one of the bundle's files.
func resolveSkillRef(b bundledSkill, typed string) (string, error) {
	want := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(typed), "./"))
	files := bundleFiles(b)
	var stems []string
	for _, f := range files {
		lf := strings.ToLower(f)
		base := strings.TrimPrefix(lf, "references/")
		stem := strings.TrimSuffix(base, ".md")
		if want == lf || want == base || want == stem || want == "references/"+stem {
			return f, nil
		}
		stems = append(stems, strings.TrimSuffix(strings.TrimPrefix(f, "references/"), ".md"))
	}
	return "", clicommon.CLIError{
		Err:        fmt.Errorf("skill %s has no reference %q (references: %s)", b.Name, typed, strings.Join(stems, ", ")),
		DidYouMean: textutil.Closest(strings.TrimSuffix(strings.TrimPrefix(want, "references/"), ".md"), stems),
		Hint:       "vigolium skills get " + b.Name + " --list-refs",
	}
}

// emitSkillRefs prints the requested reference files of each target: raw
// markdown (separated when there is more than one), or one item per file
// under -j.
func emitSkillRefs(cmd *cobra.Command, targets []bundledSkill, refs []string) error {
	var items []skillGetItem
	for _, b := range targets {
		for _, r := range refs {
			path, err := resolveSkillRef(b, r)
			if err != nil {
				return err
			}
			body, err := public.StaticFS.ReadFile(b.EmbedDir + "/" + path)
			if err != nil {
				return fmt.Errorf("read %s/%s: %w", b.Name, path, err)
			}
			items = append(items, skillGetItem{Name: b.Name, Description: b.Description, EmbedPath: b.EmbedDir, Path: path, Content: string(skillTextForSession(body))})
		}
	}
	if globalJSON {
		return emitRead(cmd, "", items, int64(len(items)), 0, len(items))
	}
	for i, it := range items {
		if len(items) > 1 {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("----- %s/%s -----\n\n", it.Name, it.Path)
		}
		writeBody([]byte(it.Content))
	}
	return nil
}

// emitSkillFiles lists each target's files with their sizes.
func emitSkillFiles(cmd *cobra.Command, targets []bundledSkill) error {
	items := []skillFileView{}
	for _, b := range targets {
		for _, f := range bundleFiles(b) {
			body, err := public.StaticFS.ReadFile(b.EmbedDir + "/" + f)
			if err != nil {
				continue
			}
			items = append(items, skillFileView{Name: b.Name, Path: f, Bytes: len(body), Lines: bytes.Count(body, []byte("\n"))})
		}
	}
	if globalJSON {
		return emitRead(cmd, "", items, int64(len(items)), 0, len(items))
	}
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "SKILL", "FILE", "LINES", "BYTES")
	for _, it := range items {
		tbl.AddRow(terminal.Cyan(it.Name), it.Path, fmt.Sprintf("%d", it.Lines), fmt.Sprintf("%d", it.Bytes))
	}
	tbl.Print()
	if len(targets) > 0 {
		fmt.Printf("\n%s Read one: %s\n", terminal.InfoSymbol(), terminal.Gray("vigolium skills get "+targets[0].Name+" --ref <file>"))
	}
	return nil
}
