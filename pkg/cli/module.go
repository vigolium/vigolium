package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/vulnclass"
)

var moduleOpts = &moduleOptions{}

type moduleOptions struct {
	ModuleType  string
	ListEnabled bool
	Verbose     bool
	TagsOnly    bool
}

// Parent command: vigolium module [search]
var moduleCmd = &cobra.Command{
	Use:     "module [search]",
	Aliases: []string{"mo", "modules"},
	Short:   "Manage scanner modules",
	Long:    "List, enable, and disable built-in scanner modules. Running 'vigolium module [search]' is a shortcut for 'module ls [search]'. Use 'enable' / 'disable' subcommands to toggle modules in the active configuration.",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		return printModuleTable(cmd, moduleOpts, filter)
	},
}

// Subcommand: vigolium module ls [filter]
var moduleLsCmd = &cobra.Command{
	Use:     "ls [filter]",
	Aliases: []string{"list"},
	Short:   "List available modules",
	Long:    "Print a table of every registered active or passive module, grouped by scan scope. Filter by substring on id/name/description/tag, or by --type (active|passive). Use --list-enabled to show only enabled modules, --tags to dump unique tags, and -v for full descriptions and confirmation criteria.",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		return printModuleTable(cmd, moduleOpts, filter)
	},
}

// listModulesShortcut runs the root -M/--list-modules shortcut as `module ls`.
// A variable assigned in init, because the root command's own literal calling
// printModuleTable would be an initialization cycle (the envelope resolves
// command paths through rootCmd).
var listModulesShortcut func() error

func init() {
	rootCmd.AddCommand(moduleCmd)
	moduleCmd.AddCommand(moduleLsCmd)
	listModulesShortcut = func() error { return printModuleTable(moduleLsCmd, moduleOpts, "") }

	for _, cmd := range []*cobra.Command{moduleCmd, moduleLsCmd} {
		cmd.Flags().StringVar(&moduleOpts.ModuleType, "type", "all",
			"Filter modules by type: all, active, or passive")
		cmd.Flags().BoolVar(&moduleOpts.ListEnabled, "list-enabled", false,
			"Show only enabled modules")
		cmd.Flags().BoolVarP(&moduleOpts.Verbose, "verbose", "v", false,
			"Show long description and confirmation criteria")
		cmd.Flags().BoolVar(&moduleOpts.TagsOnly, "tags", false,
			"Show only unique module tags, with how many modules carry each (rows {tag, modules} under -j)")
	}
}

// moduleMatchesFilter returns true if any of the module's ID, name, or short
// description contains the filter substring (case-insensitive).
func moduleMatchesFilter(m modules.Module, filter string) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	if strings.Contains(strings.ToLower(m.ID()), f) ||
		strings.Contains(strings.ToLower(m.Name()), f) ||
		strings.Contains(strings.ToLower(m.ShortDescription()), f) {
		return true
	}
	for _, tag := range m.Tags() {
		if strings.Contains(strings.ToLower(tag), f) {
			return true
		}
	}
	return false
}

// loadEnabledModulesConfig loads the enabled_modules section from the config
// file. Falls back to defaults (all enabled) on any error, with one warning —
// see settingsOrDefaults for why this one cannot simply fail.
func loadEnabledModulesConfig() *config.EnabledModulesConfig {
	return &settingsOrDefaults().DynamicAssessment.EnabledModules
}

// moduleRow holds display data for a single module in the table.
type moduleRow struct {
	symbol, moduleType, id, desc, status, tags string
}

// moduleScopeGroup groups module rows under a scan scope header.
type moduleScopeGroup struct {
	scope modules.ScanScope
	rows  []moduleRow
}

// scopeOrder defines the display order for scan scope groups.
var scopeOrder = []modules.ScanScope{
	modules.ScanScopeInsertionPoint,
	modules.ScanScopeRequest,
	modules.ScanScopeHost,
}

// scopeLabel returns a prefix and description for a scope group header.
func scopeLabel(s modules.ScanScope) (string, string) {
	switch s {
	case modules.ScanScopeInsertionPoint:
		return "Scanning Scope:", "Per Insertion Point — tests each parameter, header, or path segment individually"
	case modules.ScanScopeRequest:
		return "Scanning Scope:", "Per Request — analyzes complete HTTP request/response pairs"
	case modules.ScanScopeHost:
		return "Scanning Scope:", "Per Host — runs once per target host"
	default:
		return "Scanning Scope:", "Other"
	}
}

// moduleBelongsToScope returns true if the module's primary scope matches.
// Hybrid modules (multiple scopes) are placed under the first matching scope in scopeOrder.
func modulePrimaryScope(m modules.Module) modules.ScanScope {
	scopes := m.ScanScopes()
	for _, s := range scopeOrder {
		if scopes.Has(s) {
			return s
		}
	}
	return 0
}

// printModuleTable renders the module list. cmd names the command in the -j
// envelope; the -M/--list-modules shortcut passes moduleLsCmd, whose list it is.
func printModuleTable(cmd *cobra.Command, opts *moduleOptions, filter string) error {
	if globalJSON {
		return printModuleJSON(cmd, opts, filter)
	}

	if opts.TagsOnly {
		printModuleTags(opts, filter)
		return nil
	}

	if opts.Verbose {
		printModuleVerbose(opts, filter)
		return nil
	}

	emCfg := loadEnabledModulesConfig()

	var activeGroups, passiveGroups []moduleScopeGroup
	var totalActive, totalPassive, enabledActive, enabledPassive int

	if opts.ModuleType == "all" || opts.ModuleType == "active" {
		// Bucket active modules by scope
		buckets := make(map[modules.ScanScope][]moduleRow)
		for _, m := range modules.GetActiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			enabled := emCfg.ActiveEnabled(m.ID())
			if opts.ListEnabled && !enabled {
				continue
			}
			totalActive++
			if enabled {
				enabledActive++
			}
			status := terminal.Green("enabled")
			if !enabled {
				status = terminal.Yellow("disabled")
			}
			scope := modulePrimaryScope(m)
			buckets[scope] = append(buckets[scope], moduleRow{
				terminal.ActiveModuleSymbol(),
				terminal.BoldRed("active"),
				terminal.Cyan(m.ID()),
				m.ShortDescription(),
				status,
				terminal.Gray(formatTags(m.Tags())),
			})
		}
		for _, s := range scopeOrder {
			if rows, ok := buckets[s]; ok {
				sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
				activeGroups = append(activeGroups, moduleScopeGroup{scope: s, rows: rows})
			}
		}
	}

	if opts.ModuleType == "all" || opts.ModuleType == "passive" {
		buckets := make(map[modules.ScanScope][]moduleRow)
		for _, m := range modules.GetPassiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			enabled := emCfg.PassiveEnabled(m.ID())
			if opts.ListEnabled && !enabled {
				continue
			}
			totalPassive++
			if enabled {
				enabledPassive++
			}
			status := terminal.Green("enabled")
			if !enabled {
				status = terminal.Yellow("disabled")
			}
			scope := modulePrimaryScope(m)
			buckets[scope] = append(buckets[scope], moduleRow{
				terminal.PassiveModuleSymbol(),
				terminal.BoldBlue("passive"),
				terminal.Cyan(m.ID()),
				m.ShortDescription(),
				status,
				terminal.Gray(formatTags(m.Tags())),
			})
		}
		for _, s := range scopeOrder {
			if rows, ok := buckets[s]; ok {
				sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
				passiveGroups = append(passiveGroups, moduleScopeGroup{scope: s, rows: rows})
			}
		}
	}

	// Print stats summary
	total := totalActive + totalPassive
	enabled := enabledActive + enabledPassive
	fmt.Printf("\n  %s Module Statistics: %s modules (%s active, %s passive) | %s enabled\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(fmt.Sprintf("%d", total)),
		terminal.BoldRed(fmt.Sprintf("%d", totalActive)),
		terminal.BoldBlue(fmt.Sprintf("%d", totalPassive)),
		terminal.Green(fmt.Sprintf("%d", enabled)),
	)

	// Print grouped tables
	printScopedGroups("Active Modules", activeGroups, terminal.BoldRed)
	printScopedGroups("Passive Modules", passiveGroups, terminal.BoldBlue)

	printModuleFooter()
	return nil
}

func printScopedGroups(title string, groups []moduleScopeGroup, colorFn func(string) string) {
	if len(groups) == 0 {
		return
	}

	fmt.Printf("\n  %s\n", terminal.BoldCyan(title))

	for _, g := range groups {
		prefix, desc := scopeLabel(g.scope)
		fmt.Printf("\n  %s\n",
			terminal.HiCyan(fmt.Sprintf("─ %s %s (%d)", prefix, desc, len(g.rows))),
		)

		tbl := terminal.NewTableWithMaxWidth(globalWidth, "", "TYPE", "ID", "SHORT DESCRIPTION", "STATUS", "TAGS")
		for _, r := range g.rows {
			tbl.AddRow(r.symbol, r.moduleType, r.id, r.desc, r.status, r.tags)
		}
		tbl.Print()
	}
}

func printModuleFooter() {
	fmt.Println()
	fmt.Printf("%s Use module IDs with -m flag: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium scan -m <id1>,<id2>"))
	fmt.Printf("%s Filter by tag: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium scan --module-tag spring --module-tag injection"))
	// The same resolution `module enable/disable` writes through, so the file
	// this names under --config is the file an edit would land in.
	fmt.Printf("%s Configure enabled modules in: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray(effectiveConfigPath()))
	fmt.Printf("%s Module docs: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("https://docs.vigolium.com"))
}

type moduleJSONEntry struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Type                 string   `json:"type"`
	Description          string   `json:"description"`
	ShortDescription     string   `json:"short_description"`
	ConfirmationCriteria string   `json:"confirmation_criteria"`
	Severity             string   `json:"severity"`
	Confidence           string   `json:"confidence"`
	ScanScope            []string `json:"scan_scope"`
	Tags                 []string `json:"tags"`
	Enabled              bool     `json:"enabled"`
	// Tier is the intensity tier the module's tags declare: light, moderate,
	// heavy or intrusive, or "none" (no tier tag: it runs at every intensity).
	Tier string `json:"tier"`
	// RiskHigh: the module carries risk:high (its probes can change server
	// state); a broad selection drops it below --intensity deep unless
	// --allow-risky-payloads is set.
	RiskHigh bool `json:"risk_high"`
	// VulnClass is the module's reported class (pkg/vulnclass), the value its
	// findings carry as vuln_class; "multiple" when its findings span classes
	// and each names its own; absent for a module with no declaration.
	VulnClass string `json:"vuln_class,omitempty"`
}

// newModuleJSONEntry is the -j row of one module.
func newModuleJSONEntry(m modules.Module, typ string, enabled bool) moduleJSONEntry {
	tags := m.Tags()
	return moduleJSONEntry{
		ID:                   m.ID(),
		Name:                 m.Name(),
		Type:                 typ,
		Description:          m.Description(),
		ShortDescription:     m.ShortDescription(),
		ConfirmationCriteria: m.ConfirmationCriteria(),
		Severity:             m.Severity().String(),
		Confidence:           m.Confidence().String(),
		ScanScope:            scanScopeNames(m.ScanScopes()),
		Tags:                 tags,
		Enabled:              enabled,
		Tier:                 modules.ModuleTierName(tags),
		RiskHigh:             modules.IsRiskHighModule(tags),
		VulnClass:            string(vulnclass.ForModule(m.ID())),
	}
}

// moduleTagRow is one row of `module ls -j --tags`.
type moduleTagRow struct {
	Tag     string `json:"tag"`
	Modules int    `json:"modules"`
}

func printModuleJSON(cmd *cobra.Command, opts *moduleOptions, filter string) error {
	if opts.TagsOnly {
		counts := moduleTagCounts(opts, filter)
		rows := make([]moduleTagRow, 0, len(counts))
		for tag, n := range counts {
			rows = append(rows, moduleTagRow{Tag: tag, Modules: n})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Tag < rows[j].Tag })
		return emitRead(cmd, "tags", rows, int64(len(rows)), 0, len(rows))
	}
	emCfg := loadEnabledModulesConfig()
	entries := []moduleJSONEntry{}
	var activeCount, passiveCount int

	if opts.ModuleType == "all" || opts.ModuleType == "active" {
		for _, m := range modules.GetActiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			enabled := emCfg.ActiveEnabled(m.ID())
			if opts.ListEnabled && !enabled {
				continue
			}
			activeCount++
			entries = append(entries, newModuleJSONEntry(m, "active", enabled))
		}
	}

	if opts.ModuleType == "all" || opts.ModuleType == "passive" {
		for _, m := range modules.GetPassiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			enabled := emCfg.PassiveEnabled(m.ID())
			if opts.ListEnabled && !enabled {
				continue
			}
			passiveCount++
			entries = append(entries, newModuleJSONEntry(m, "passive", enabled))
		}
	}

	// The rows are `items` (legacy alias `modules`); the per-type counts stay at
	// the top level under their old names.
	return emitRead(cmd, "modules", entries, int64(len(entries)), 0, len(entries),
		withExtra("active_count", activeCount),
		withExtra("passive_count", passiveCount))
}

// formatTags joins tags with commas for table display.
func formatTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return strings.Join(tags, ", ")
}

// scanScopeNames converts a ScanScope bitmask to a list of human-readable names.
func scanScopeNames(s modkit.ScanScope) []string {
	var names []string
	if s.Has(modkit.ScanScopeInsertionPoint) {
		names = append(names, "PER_INSERTION_POINT")
	}
	if s.Has(modkit.ScanScopeRequest) {
		names = append(names, "PER_REQUEST")
	}
	if s.Has(modkit.ScanScopeHost) {
		names = append(names, "PER_HOST")
	}
	return names
}

// moduleTagCounts counts, per tag, the modules the type and name filters keep.
func moduleTagCounts(opts *moduleOptions, filter string) map[string]int {
	tagCounts := make(map[string]int)
	if opts.ModuleType == "all" || opts.ModuleType == "active" {
		for _, m := range modules.GetActiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			for _, tag := range m.Tags() {
				tagCounts[tag]++
			}
		}
	}
	if opts.ModuleType == "all" || opts.ModuleType == "passive" {
		for _, m := range modules.GetPassiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			for _, tag := range m.Tags() {
				tagCounts[tag]++
			}
		}
	}
	return tagCounts
}

func printModuleTags(opts *moduleOptions, filter string) {
	tagCounts := moduleTagCounts(opts, filter)

	if len(tagCounts) == 0 {
		fmt.Printf("%s No tags found.\n", terminal.InfoSymbol())
		return
	}

	tags := make([]string, 0, len(tagCounts))
	for tag := range tagCounts {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "TAG", "MODULES")
	for _, tag := range tags {
		tbl.AddRow(terminal.Cyan(tag), fmt.Sprintf("%d", tagCounts[tag]))
	}
	tbl.Print()
	fmt.Printf("\n%s %d unique tags across modules\n", terminal.InfoSymbol(), len(tags))
	fmt.Printf("%s Filter by tag: %s\n", terminal.InfoSymbol(), terminal.Gray("vigolium scan --module-tag <tag>"))
}

func printModuleVerbose(opts *moduleOptions, filter string) {
	emCfg := loadEnabledModulesConfig()

	printVerboseEntry := func(m modules.Module, enabled bool, symbolFn func() string, typeName string, typeColorFn func(string) string) {
		status := terminal.Green("enabled")
		if !enabled {
			status = terminal.Yellow("disabled")
		}
		name := m.ID()
		fmt.Printf("  %s [%s] %s  %s\n", symbolFn(), typeColorFn(typeName), terminal.Cyan(name), status)
		fmt.Printf("      %s %s\n", terminal.Gray("Short Description:"), m.ShortDescription())
		if desc := m.Description(); desc != "" {
			first := strings.SplitN(desc, "\n", 2)[0]
			fmt.Printf("      %s %s\n", terminal.Gray("Description:"), first)
		}
		if cc := m.ConfirmationCriteria(); cc != "" {
			fmt.Printf("      %s %s\n", terminal.Gray("Confirmation:"), cc)
		}
		if tags := m.Tags(); len(tags) > 0 {
			fmt.Printf("      %s %s\n", terminal.Gray("Tags:"), strings.Join(tags, ", "))
		}
		fmt.Println()
	}

	if opts.ModuleType == "all" || opts.ModuleType == "active" {
		printed := false
		for _, m := range modules.GetActiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			enabled := emCfg.ActiveEnabled(m.ID())
			if opts.ListEnabled && !enabled {
				continue
			}
			if !printed {
				fmt.Println("  " + terminal.BoldCyan("Active Modules"))
				fmt.Println("  " + strings.Repeat("─", len("Active Modules")))
				fmt.Println()
				printed = true
			}
			printVerboseEntry(m, enabled, terminal.ActiveModuleSymbol, "active", terminal.BoldRed)
		}
	}

	if opts.ModuleType == "all" || opts.ModuleType == "passive" {
		printed := false
		for _, m := range modules.GetPassiveModules() {
			if !moduleMatchesFilter(m, filter) {
				continue
			}
			enabled := emCfg.PassiveEnabled(m.ID())
			if opts.ListEnabled && !enabled {
				continue
			}
			if !printed {
				fmt.Println("  " + terminal.BoldCyan("Passive Modules"))
				fmt.Println("  " + strings.Repeat("─", len("Passive Modules")))
				fmt.Println()
				printed = true
			}
			printVerboseEntry(m, enabled, terminal.PassiveModuleSymbol, "passive", terminal.BoldBlue)
		}
	}

	printModuleFooter()
}
