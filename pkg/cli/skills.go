package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
	"gopkg.in/yaml.v3"
)

// skillFrontmatterRe captures the leading YAML frontmatter block of a SKILL.md.
var skillFrontmatterRe = regexp.MustCompile(`(?s)\A---\s*\n(.*?)\n---\s*(?:\n|$)`)

// lenientFrontmatter scrapes name/description from a SKILL.md's frontmatter
// without the strict typing skill.Parse enforces, so bundles that use a
// looser schema (e.g. a comma-string allowed-tools) still surface metadata.
func lenientFrontmatter(raw []byte) (name, description string) {
	content := strings.ReplaceAll(string(raw), "\r\n", "\n")
	m := skillFrontmatterRe.FindStringSubmatch(content)
	if m == nil {
		return "", ""
	}
	var fm struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(m[1]), &fm); err != nil {
		return "", ""
	}
	return strings.TrimSpace(fm.Name), strings.TrimSpace(fm.Description)
}

// embedSkillsRoot is the directory inside public.StaticFS that holds the
// coding-agent-facing skill bundles (vigolium-scanner, agent-browser).
const embedSkillsRoot = "skills"

// defaultInstallSkill is installed when `skills install` is run without an
// explicit skill name.
const defaultInstallSkill = "vigolium-scanner"

// thirdPartySkills names bundles authored outside vigolium (vendored companion
// tools). They're hidden from listings and bulk (--all) selection, and only
// surface when named explicitly or with --third-party-skills.
var thirdPartySkills = map[string]bool{
	"agent-browser": true,
}

var skillsOpts = &skillsOptions{}

type skillsOptions struct {
	Full       bool
	All        bool
	ThirdParty bool
	Agent      string
	Scope      string
	Dir        string
}

// bundledSkill is a parsed skill bundle shipped inside the binary.
type bundledSkill struct {
	Name        string   // directory / frontmatter name (e.g. "vigolium-scanner")
	Description string   // frontmatter description
	EmbedDir    string   // path inside public.StaticFS (e.g. "skills/vigolium-scanner")
	References  []string // reference file paths relative to EmbedDir (e.g. "references/commands.md")
	ThirdParty  bool     // vendored companion skill, hidden unless opted in
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
		return runSkillsList()
	},
}

// Subcommand: vigolium skills list
var skillsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all bundled skills",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsList()
	},
}

// Subcommand: vigolium skills get <name>...
var skillsGetCmd = &cobra.Command{
	Use:   "get [name...]",
	Short: "Print a skill's full content",
	Long: `Print a skill's SKILL.md to stdout. Pass --full to also include its
reference files, or --all to output every bundled skill.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsGet(args)
	},
}

// Subcommand: vigolium skills install [name]...
var skillsInstallCmd = &cobra.Command{
	Use:   "install [name...]",
	Short: "Install skill bundle(s) into a coding agent's skills directory",
	Long: `Copy one or more bundled skills into a coding agent's skills directory so
the agent can auto-trigger on them.

With no name, installs the '` + defaultInstallSkill + `' skill. Pass --all to install
every bundle, or name specific skills. Vendored third-party skills (e.g.
agent-browser) are excluded from --all unless --third-party-skills is set, but
can always be installed by naming them explicitly.

Destination is chosen from --agent and --scope:

  --agent claude          .claude/skills/   (project)   ~/.claude/skills/   (global)
  --agent codex|agents    .agents/skills/   (project)   ~/.agents/skills/   (global)

An already-installed skill is skipped unless --force is given. --dir
overrides the computed destination entirely.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsInstall(args)
	},
}

func init() {
	rootCmd.AddCommand(skillsCmd)
	skillsCmd.AddCommand(skillsListCmd, skillsGetCmd, skillsInstallCmd)

	// Persistent so it applies to the parent's default list run and every
	// subcommand (list/get/install).
	skillsCmd.PersistentFlags().BoolVar(&skillsOpts.ThirdParty, "third-party-skills", false,
		"Include vendored third-party skills (e.g. agent-browser) in listings and --all")

	skillsGetCmd.Flags().BoolVar(&skillsOpts.Full, "full", false, "Include reference files, not just SKILL.md")
	skillsGetCmd.Flags().BoolVar(&skillsOpts.All, "all", false, "Output every bundled skill")

	skillsInstallCmd.Flags().StringVar(&skillsOpts.Agent, "agent", "claude", "Target coding agent: claude, codex, or agents")
	skillsInstallCmd.Flags().StringVar(&skillsOpts.Scope, "scope", "project", "Install scope: project (current folder) or global (home dir)")
	skillsInstallCmd.Flags().BoolVar(&skillsOpts.All, "all", false, "Install every bundled skill")
	skillsInstallCmd.Flags().StringVar(&skillsOpts.Dir, "dir", "", "Override the destination directory (skips --agent/--scope resolution)")
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
		desc := ""
		if parsed, perr := skill.Parse(raw, skillMd, embedDir, skill.SourceEmbedded); perr == nil {
			desc = parsed.Description
		} else if _, ld := lenientFrontmatter(raw); ld != "" {
			// skill.Parse is strict (e.g. it rejects the comma-string
			// `allowed-tools` form Claude Code skills use). Fall back to a
			// permissive description scrape so those bundles still list.
			desc = ld
		}

		out = append(out, bundledSkill{
			Name:        e.Name(),
			Description: desc,
			EmbedDir:    embedDir,
			References:  listBundleReferences(embedDir),
			ThirdParty:  thirdPartySkills[e.Name()],
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

// visibleBundles returns the bundles used for browsing (list) and bulk
// selection (--all): first-party always, third-party only when
// --third-party-skills is set. hidden reports how many third-party bundles were
// filtered out (0 when the flag is on).
func visibleBundles(skills []bundledSkill) (visible []bundledSkill, hidden int) {
	for _, s := range skills {
		if s.ThirdParty && !skillsOpts.ThirdParty {
			hidden++
			continue
		}
		visible = append(visible, s)
	}
	return visible, hidden
}

// resolveNamedTargets maps explicit skill names to bundles, erroring on the
// first unknown name. Shared by get/install; named args resolve against the
// full set so a third-party skill can always be reached by name.
func resolveNamedTargets(skills []bundledSkill, names []string) ([]bundledSkill, error) {
	targets := make([]bundledSkill, 0, len(names))
	for _, n := range names {
		b, ok := findBundle(skills, n)
		if !ok {
			return nil, fmt.Errorf("unknown skill %q (available: %s)", n, bundleNames(skills))
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

func runSkillsList() error {
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}
	visible, hidden := visibleBundles(skills)

	if globalJSON {
		type jsonEntry struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			EmbedPath   string   `json:"embed_path"`
			References  []string `json:"references"`
			ThirdParty  bool     `json:"third_party"`
		}
		entries := make([]jsonEntry, len(visible))
		for i, s := range visible {
			entries[i] = jsonEntry{s.Name, s.Description, s.EmbedDir, s.References, s.ThirdParty}
		}
		return writeAgentJSON(map[string]any{"skills": entries, "total": len(entries), "hidden_third_party": hidden})
	}

	if len(visible) == 0 {
		fmt.Printf("%s No skills to show.", terminal.InfoSymbol())
		if hidden > 0 {
			fmt.Printf(" %d third-party skill(s) hidden — pass --third-party-skills to show.", hidden)
		}
		fmt.Println()
		return nil
	}

	fmt.Printf("\n  %s %s bundled skill(s)\n\n",
		terminal.InfoSymbol(), terminal.BoldCyan(fmt.Sprintf("%d", len(visible))))

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "DESCRIPTION", "REFS")
	for _, s := range visible {
		tbl.AddRow(terminal.Cyan(s.Name), s.Description, terminal.Gray(fmt.Sprintf("%d", len(s.References))))
	}
	tbl.Print()

	fmt.Printf("\n%s Read a skill:    %s\n", terminal.InfoSymbol(), terminal.Gray("vigolium skills get "+visible[0].Name+" --full"))
	fmt.Printf("%s Install a skill: %s\n", terminal.InfoSymbol(), terminal.Gray("vigolium skills install --agent claude --scope project"))
	if hidden > 0 {
		fmt.Printf("%s %s third-party skill(s) hidden — pass %s to show.\n",
			terminal.InfoSymbol(), terminal.BoldCyan(fmt.Sprintf("%d", hidden)), terminal.Gray("--third-party-skills"))
	}
	return nil
}

func runSkillsGet(names []string) error {
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}

	var targets []bundledSkill
	switch {
	case skillsOpts.All:
		targets, _ = visibleBundles(skills)
	case len(names) == 0:
		return fmt.Errorf("skills get: provide a skill name or --all (available: %s)", bundleNames(skills))
	default:
		if targets, err = resolveNamedTargets(skills, names); err != nil {
			return err
		}
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
		writeBody(body)

		if skillsOpts.Full {
			for _, ref := range b.References {
				refBody, refErr := public.StaticFS.ReadFile(b.EmbedDir + "/" + ref)
				if refErr != nil {
					continue
				}
				fmt.Printf("\n\n----- %s/%s -----\n\n", b.Name, ref)
				writeBody(refBody)
			}
		}
	}
	return nil
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
		return "", fmt.Errorf("unknown --agent %q (want: claude, codex, or agents)", agent)
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
		return "", fmt.Errorf("unknown --scope %q (want: project or global)", scope)
	}
}

func runSkillsInstall(names []string) error {
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}

	// Resolve which bundles to install.
	var targets []bundledSkill
	switch {
	case skillsOpts.All:
		targets, _ = visibleBundles(skills)
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

	// Resolve the destination base directory.
	baseDir := skillsOpts.Dir
	if baseDir == "" {
		baseDir, err = skillsInstallBaseDir(skillsOpts.Agent, skillsOpts.Scope)
		if err != nil {
			return err
		}
	} else if abs, absErr := filepath.Abs(config.ExpandPath(baseDir)); absErr == nil {
		baseDir = abs
	}

	installed, skipped := 0, 0
	for _, b := range targets {
		dest := filepath.Join(baseDir, b.Name)
		if _, statErr := os.Stat(filepath.Join(dest, "SKILL.md")); statErr == nil && !globalForce {
			fmt.Printf("%s %s already installed at %s (use --force to overwrite)\n",
				terminal.WarningSymbol(), terminal.Cyan(b.Name), terminal.Gray(dest))
			skipped++
			continue
		}
		if copyErr := copyEmbeddedSkillBundle(b.EmbedDir, dest); copyErr != nil {
			return fmt.Errorf("install %s: %w", b.Name, copyErr)
		}
		fmt.Printf("%s Installed %s → %s\n",
			terminal.SuccessSymbol(), terminal.Cyan(b.Name), terminal.Gray(dest))
		installed++
	}

	fmt.Printf("\n%s %d installed, %d skipped. Your agent will auto-trigger on these skills when you mention vigolium.\n",
		terminal.InfoSymbol(), installed, skipped)
	return nil
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
