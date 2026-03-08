package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/yamlext"
	"github.com/vigolium/vigolium/public"
	"github.com/spf13/cobra"
)

var extOpts = &extensionOptions{}
var docsShowExamples bool

type extensionOptions struct {
	ExtType string
	Verbose bool
}

// Parent command: vigolium extensions
var extensionsCmd = &cobra.Command{
	Use:     "extensions [filter]",
	Aliases: []string{"ext"},
	Short:   "Manage JavaScript extensions",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		printExtensionsTable(extOpts, filter)
	},
}

// Subcommand: vigolium extensions ls [filter]
var extensionsLsCmd = &cobra.Command{
	Use:     "ls [filter]",
	Aliases: []string{"list"},
	Short:   "List loaded extensions",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		printExtensionsTable(extOpts, filter)
	},
}

// Subcommand: vigolium extensions docs [function]
var extensionsDocsCmd = &cobra.Command{
	Use:     "docs [function]",
	Aliases: []string{"doc", "api"},
	Short:   "Show extension API reference with examples",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		printExtensionDocs(filter)
	},
}

// Subcommand: vigolium extensions preset [name]
var extensionsPresetCmd = &cobra.Command{
	Use:     "preset [name]",
	Aliases: []string{"presets", "init"},
	Short:   "Install example extension presets into extensions directory",
	Long:    "Copies starter extension scripts to ~/.vigolium/extensions/. If a name is given, installs only that preset.",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		installPresets(filter)
	},
}

func init() {
	rootCmd.AddCommand(extensionsCmd)
	extensionsCmd.AddCommand(extensionsLsCmd)
	extensionsCmd.AddCommand(extensionsDocsCmd)
	extensionsCmd.AddCommand(extensionsPresetCmd)
	extensionsCmd.AddCommand(extensionsEvalCmd)
	extensionsLsCmd.Flags().StringVar(&extOpts.ExtType, "type", "all",
		"Filter by type: all, active, passive, pre_hook, post_hook")
	extensionsLsCmd.Flags().BoolVarP(&extOpts.Verbose, "verbose", "v", false,
		"Show long description and confirmation criteria per extension")

	extensionsDocsCmd.Flags().BoolVar(&docsShowExamples, "example", false,
		"Show usage examples for each function")
}

// matchesFilter returns true if filter is empty or if any of id/name/desc
// contain the filter substring (case-insensitive).
func matchesFilter(id, name, desc, filter string) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	return strings.Contains(strings.ToLower(id), f) ||
		strings.Contains(strings.ToLower(name), f) ||
		strings.Contains(strings.ToLower(desc), f)
}

func extensionMatchesFilter(meta jsext.ScriptMetadata, filter string) bool {
	return matchesFilter(meta.ID, meta.Name, meta.Description, filter)
}

// extRow holds display data for a single extension in the table.
type extRow struct {
	symbol, typeLabel, id, severity, scanTypes, scope, lang, desc, file string
}

// abbreviateScanTypes joins scan types with short names for compact display.
func abbreviateScanTypes(types []string) string {
	if len(types) == 0 {
		return terminal.Gray("—")
	}
	var parts []string
	for _, t := range types {
		switch t {
		case "per_insertion_point":
			parts = append(parts, "per_ip")
		case "per_request":
			parts = append(parts, "per_req")
		case "per_host":
			parts = append(parts, "per_host")
		default:
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, ",")
}

// severityColor returns a colored severity string for active/passive modules.
func extensionSeverityLabel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return terminal.BoldMagenta(sev)
	case "high":
		return terminal.BoldRed(sev)
	case "medium":
		return terminal.BoldYellow(sev)
	case "low":
		return terminal.BoldGreen(sev)
	case "info":
		return terminal.BoldBlue(sev)
	default:
		if sev == "" {
			return terminal.Gray("—")
		}
		return sev
	}
}

func yamlMatchesFilter(def *yamlext.ExtensionDef, filter string) bool {
	return matchesFilter(def.ID, def.Name, def.Description, filter)
}

func printExtensionsTable(opts *extensionOptions, filter string) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		fmt.Printf("%s Failed to load settings: %v\n", terminal.ErrorSymbol(), err)
		return
	}

	if !settings.DynamicAssessment.Extensions.Enabled {
		fmt.Printf("%s Extensions not enabled. Enable with: %s\n",
			terminal.WarningSymbol(),
			terminal.Gray("vigolium config set dynamic_assessment.extensions.enabled true"))
		fmt.Println()
		return
	}

	loadedScripts, err := jsext.LoadScripts(&settings.DynamicAssessment.Extensions)
	if err != nil {
		fmt.Printf("%s Failed to load JS extensions: %v\n", terminal.ErrorSymbol(), err)
		return
	}

	loadedYAML, _ := yamlext.LoadFromConfig(&settings.DynamicAssessment.Extensions)

	if len(loadedScripts) == 0 && len(loadedYAML) == 0 {
		fmt.Printf("%s No extensions found. Configure %s or %s in config.\n",
			terminal.InfoSymbol(),
			terminal.Gray("extensions.extension_dir"),
			terminal.Gray("extensions.custom_dir"))
		fmt.Printf("%s Install starter examples: %s\n",
			terminal.InfoSymbol(),
			terminal.Gray("vigolium extensions preset"))
		fmt.Printf("%s Browse API reference: %s\n",
			terminal.InfoSymbol(),
			terminal.Gray("vigolium extensions docs"))
		fmt.Println()
		return
	}

	// Group by type
	groups := []struct {
		key   jsext.ScriptType
		title string
	}{
		{jsext.ScriptTypeActive, "Active Extensions"},
		{jsext.ScriptTypePassive, "Passive Extensions"},
		{jsext.ScriptTypePreHook, "Pre-Hooks"},
		{jsext.ScriptTypePostHook, "Post-Hooks"},
	}

	buckets := make(map[jsext.ScriptType][]extRow)
	var countActive, countPassive, countHooks int

	// Build rows from JS scripts
	for _, script := range loadedScripts {
		meta := script.Metadata
		if !extensionMatchesFilter(meta, filter) {
			continue
		}
		if opts.ExtType != "all" && string(meta.Type) != opts.ExtType {
			continue
		}

		var symbol, typeLabel, sevLabel, scanTypesLabel, scopeLabel string
		switch meta.Type {
		case jsext.ScriptTypeActive:
			symbol = terminal.ActiveModuleSymbol()
			typeLabel = terminal.Green("active")
			sevLabel = extensionSeverityLabel(meta.Severity)
			scanTypesLabel = abbreviateScanTypes(meta.ScanTypes)
			scopeLabel = terminal.Gray("—")
			countActive++
		case jsext.ScriptTypePassive:
			symbol = terminal.PassiveModuleSymbol()
			typeLabel = terminal.Cyan("passive")
			sevLabel = extensionSeverityLabel(meta.Severity)
			scanTypesLabel = abbreviateScanTypes(meta.ScanTypes)
			if meta.Scope == "" {
				scopeLabel = terminal.Gray("both")
			} else {
				scopeLabel = meta.Scope
			}
			countPassive++
		case jsext.ScriptTypePreHook:
			symbol = terminal.InfoSymbol()
			typeLabel = terminal.Yellow("pre_hook")
			sevLabel = terminal.Gray("—")
			scanTypesLabel = terminal.Gray("—")
			scopeLabel = terminal.Gray("—")
			countHooks++
		case jsext.ScriptTypePostHook:
			symbol = terminal.InfoSymbol()
			typeLabel = terminal.Yellow("post_hook")
			sevLabel = terminal.Gray("—")
			scanTypesLabel = terminal.Gray("—")
			scopeLabel = terminal.Gray("—")
			countHooks++
		default:
			symbol = " "
			typeLabel = string(meta.Type)
			sevLabel = terminal.Gray("—")
			scanTypesLabel = terminal.Gray("—")
			scopeLabel = terminal.Gray("—")
		}

		desc := meta.Description
		if desc == "" {
			desc = meta.Name
		}
		buckets[meta.Type] = append(buckets[meta.Type], extRow{
			symbol:    symbol,
			typeLabel: typeLabel,
			id:        terminal.Cyan(meta.ID),
			severity:  sevLabel,
			scanTypes: scanTypesLabel,
			scope:     scopeLabel,
			lang:      terminal.Gray("JS"),
			desc:      desc,
			file:      terminal.Gray(filepath.Base(script.Path)),
		})
	}

	// Build rows from YAML extensions
	for _, def := range loadedYAML {
		if !yamlMatchesFilter(def, filter) {
			continue
		}
		extType := jsext.ScriptType(def.Type)
		if opts.ExtType != "all" && def.Type != opts.ExtType {
			continue
		}

		var symbol, typeLabel, sevLabel, scanTypesLabel, scopeLabel string
		switch extType {
		case jsext.ScriptTypeActive:
			symbol = terminal.ActiveModuleSymbol()
			typeLabel = terminal.Green("active")
			sevLabel = extensionSeverityLabel(def.Severity)
			scanTypesLabel = abbreviateScanTypes(def.ScanTypes)
			scopeLabel = terminal.Gray("—")
			countActive++
		case jsext.ScriptTypePassive:
			symbol = terminal.PassiveModuleSymbol()
			typeLabel = terminal.Cyan("passive")
			sevLabel = extensionSeverityLabel(def.Severity)
			scanTypesLabel = abbreviateScanTypes(def.ScanTypes)
			if def.Scope == "" {
				scopeLabel = terminal.Gray("both")
			} else {
				scopeLabel = def.Scope
			}
			countPassive++
		case jsext.ScriptTypePreHook:
			symbol = terminal.InfoSymbol()
			typeLabel = terminal.Yellow("pre_hook")
			sevLabel = terminal.Gray("—")
			scanTypesLabel = terminal.Gray("—")
			scopeLabel = terminal.Gray("—")
			countHooks++
		case jsext.ScriptTypePostHook:
			symbol = terminal.InfoSymbol()
			typeLabel = terminal.Yellow("post_hook")
			sevLabel = terminal.Gray("—")
			scanTypesLabel = terminal.Gray("—")
			scopeLabel = terminal.Gray("—")
			countHooks++
		default:
			symbol = " "
			typeLabel = def.Type
			sevLabel = terminal.Gray("—")
			scanTypesLabel = terminal.Gray("—")
			scopeLabel = terminal.Gray("—")
		}

		desc := def.Description
		if desc == "" {
			desc = def.Name
		}
		buckets[extType] = append(buckets[extType], extRow{
			symbol:    symbol,
			typeLabel: typeLabel,
			id:        terminal.Cyan(def.ID),
			severity:  sevLabel,
			scanTypes: scanTypesLabel,
			scope:     scopeLabel,
			lang:      terminal.Yellow("YAML"),
			desc:      desc,
			file:      terminal.Gray(filepath.Base(def.SourcePath())),
		})
	}

	total := countActive + countPassive + countHooks
	fmt.Printf("\n  %s Extension Statistics: %s extensions (%s active, %s passive, %s hooks)\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(fmt.Sprintf("%d", total)),
		terminal.BoldGreen(fmt.Sprintf("%d", countActive)),
		terminal.BoldCyan(fmt.Sprintf("%d", countPassive)),
		terminal.BoldYellow(fmt.Sprintf("%d", countHooks)),
	)

	if opts.Verbose {
		printExtensionsVerbose(loadedScripts, loadedYAML, opts, filter)
	} else {
		for _, g := range groups {
			rows, ok := buckets[g.key]
			if !ok || len(rows) == 0 {
				continue
			}
			fmt.Printf("\n  %s\n", terminal.BoldCyan(fmt.Sprintf("%s (%d)", g.title, len(rows))))
			tbl := terminal.NewTableWithMaxWidth(globalWidth, "", "TYPE", "ID", "SEVERITY", "SCAN_TYPES", "SCOPE", "LANG", "DESCRIPTION", "FILE")
			for _, r := range rows {
				tbl.AddRow(r.symbol, r.typeLabel, r.id, r.severity, r.scanTypes, r.scope, r.lang, r.desc, r.file)
			}
			tbl.Print()
		}
	}

	fmt.Println()
	fmt.Printf("%s Filter by type: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium extensions ls --type active"))
	fmt.Printf("%s Verbose mode: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium extensions ls -v"))
	fmt.Println()
}

// printExtensionsVerbose prints each extension with full description and confirmation criteria.
func printExtensionsVerbose(scripts []*jsext.LoadedScript, yamlDefs []*yamlext.ExtensionDef, opts *extensionOptions, filter string) {
	currentType := jsext.ScriptType("")
	for _, script := range scripts {
		meta := script.Metadata
		if !extensionMatchesFilter(meta, filter) {
			continue
		}
		if opts.ExtType != "all" && string(meta.Type) != opts.ExtType {
			continue
		}
		if meta.Type != currentType {
			currentType = meta.Type
			fmt.Printf("\n  %s\n", terminal.BoldCyan(strings.ToUpper(string(meta.Type))))
			fmt.Println("  " + strings.Repeat("─", len(string(meta.Type))))
		}
		fmt.Println()
		fmt.Printf("    %s %s %s %s\n",
			terminal.Cyan(meta.ID),
			terminal.Gray("·"),
			terminal.Gray(filepath.Base(script.Path)),
			terminal.Gray("[JS]"))
		if meta.Name != "" && meta.Name != meta.ID {
			fmt.Printf("      Name: %s\n", meta.Name)
		}
		if meta.Severity != "" {
			fmt.Printf("      Severity: %s\n", extensionSeverityLabel(meta.Severity))
		}
		if len(meta.ScanTypes) > 0 {
			fmt.Printf("      Scan types: %s\n", strings.Join(meta.ScanTypes, ", "))
		}
		if meta.Scope != "" {
			fmt.Printf("      Scope: %s\n", meta.Scope)
		}
		if meta.Description != "" {
			fmt.Printf("      Description: %s\n", meta.Description)
		}
		if meta.ConfirmationCriteria != "" {
			fmt.Printf("      Confirmation: %s\n", terminal.Gray(meta.ConfirmationCriteria))
		}
	}

	for _, def := range yamlDefs {
		if !yamlMatchesFilter(def, filter) {
			continue
		}
		if opts.ExtType != "all" && def.Type != opts.ExtType {
			continue
		}
		extType := jsext.ScriptType(def.Type)
		if extType != currentType {
			currentType = extType
			fmt.Printf("\n  %s\n", terminal.BoldCyan(strings.ToUpper(def.Type)))
			fmt.Println("  " + strings.Repeat("─", len(def.Type)))
		}
		fmt.Println()
		fmt.Printf("    %s %s %s %s\n",
			terminal.Cyan(def.ID),
			terminal.Gray("·"),
			terminal.Gray(filepath.Base(def.SourcePath())),
			terminal.Yellow("[YAML]"))
		if def.Name != "" && def.Name != def.ID {
			fmt.Printf("      Name: %s\n", def.Name)
		}
		if def.Severity != "" {
			fmt.Printf("      Severity: %s\n", extensionSeverityLabel(def.Severity))
		}
		if len(def.ScanTypes) > 0 {
			fmt.Printf("      Scan types: %s\n", strings.Join(def.ScanTypes, ", "))
		}
		if def.Scope != "" {
			fmt.Printf("      Scope: %s\n", def.Scope)
		}
		if def.Description != "" {
			fmt.Printf("      Description: %s\n", def.Description)
		}
		if def.ConfirmationCriteria != "" {
			fmt.Printf("      Confirmation: %s\n", terminal.Gray(def.ConfirmationCriteria))
		}
	}
}

// ──────────────────────────────────────────────────────────────
// extensions docs
// ──────────────────────────────────────────────────────────────

func printExtensionDocs(filter string) {
	registry := jsext.APIRegistry()
	filterLower := strings.ToLower(filter)

	// Fuzzy-match against name, full name, namespace, description, and returns
	var filtered []jsext.APIFunction
	for _, fn := range registry {
		if filter == "" ||
			strings.Contains(strings.ToLower(fn.Name), filterLower) ||
			strings.Contains(strings.ToLower(fn.FullName()), filterLower) ||
			strings.Contains(strings.ToLower(fn.Namespace), filterLower) ||
			strings.Contains(strings.ToLower(fn.Description), filterLower) ||
			strings.Contains(strings.ToLower(fn.Returns), filterLower) {
			filtered = append(filtered, fn)
		}
	}

	if len(filtered) == 0 && filter != "" {
		fmt.Printf("%s No API functions matching %q\n", terminal.WarningSymbol(), filter)
		fmt.Printf("  Try: %s, %s, %s\n",
			terminal.Gray("ext docs http"),
			terminal.Gray("ext docs log"),
			terminal.Gray("ext docs utils"))
		return
	}

	if docsShowExamples {
		printDocsVerbose(filtered)
	} else {
		tbl := terminal.NewTableFullWidthWeighted(terminal.TerminalWidth(), []int{2, 4, 5, 2}, "CATEGORY", "SIGNATURE", "DESCRIPTION", "RETURNS")
		for _, fn := range filtered {
			cat := fn.Category
			if cat == "" {
				cat = fn.Namespace
			}
			var colorFn func(string) string
			switch {
			case strings.HasPrefix(fn.Namespace, "vigolium.log"):
				colorFn = terminal.Green
			case strings.HasPrefix(fn.Namespace, "vigolium.utils"):
				colorFn = terminal.Yellow
			case strings.HasPrefix(fn.Namespace, "vigolium.http"):
				colorFn = terminal.Cyan
			case strings.HasPrefix(fn.Namespace, "vigolium.scan"):
				colorFn = terminal.Magenta
			case strings.HasPrefix(fn.Namespace, "vigolium.ingest"):
				colorFn = terminal.Blue
			case strings.HasPrefix(fn.Namespace, "vigolium.source"):
				colorFn = terminal.Green
			case strings.HasPrefix(fn.Namespace, "vigolium.db"):
				colorFn = terminal.Blue
			default:
				colorFn = terminal.Gray
			}
			tbl.AddRow(colorFn(cat), colorFn(fn.Namespace+fn.Signature), fn.Description, terminal.Gray(fn.Returns))
		}
		tbl.Print()
		fmt.Println()
		if filter != "" {
			fmt.Printf("%s %d functions matching %q. Use %s to see code examples.\n",
				terminal.InfoSymbol(), len(filtered), filter,
				terminal.Gray("--example"))
		} else {
			fmt.Printf("%s %d functions. Filter: %s. Use %s to see code examples.\n",
				terminal.InfoSymbol(), len(filtered),
				terminal.Gray("ext docs <search>"),
				terminal.Gray("--example"))
		}
	}

	// Print supplementary reference only with --example flag
	if filter == "" && docsShowExamples {
		fmt.Println()
		printContextReference()
		printInsertionPointReference()
		printReturnContractReference()
		printParseURLReference()
		printModuleTemplates()
	}
}

func printDocsVerbose(functions []jsext.APIFunction) {
	currentCat := ""
	for _, fn := range functions {
		cat := fn.Category
		if cat == "" {
			cat = fn.Namespace
		}
		if cat != currentCat {
			if currentCat != "" {
				fmt.Println()
			}
			currentCat = cat
			fmt.Println("  " + terminal.BoldCyan(currentCat))
			fmt.Println("  " + strings.Repeat("─", len(currentCat)))
		}
		fmt.Println()
		fmt.Printf("    %s%s %s\n", terminal.Green(fn.Namespace), terminal.Green(fn.Signature), terminal.Gray("-> "+fn.Returns))
		fmt.Printf("      %s\n", fn.Description)
		fmt.Printf("      Example: %s\n", terminal.Gray(fn.Example))
	}
}

func printContextReference() {
	fmt.Println("  " + terminal.BoldCyan("Context Object (ctx)"))
	fmt.Println("  " + strings.Repeat("─", 20))
	fmt.Println()
	fmt.Println("    Passed to scanPerRequest, scanPerInsertionPoint, and scanPerHost:")
	fmt.Println()
	fmt.Println("    ctx.request.url        " + terminal.Gray("string  — full request URL"))
	fmt.Println("    ctx.request.method     " + terminal.Gray("string  — HTTP method (GET, POST, ...)"))
	fmt.Println("    ctx.request.headers    " + terminal.Gray("object  — request headers {Name: Value}"))
	fmt.Println("    ctx.request.raw        " + terminal.Gray("string  — full raw HTTP request"))
	fmt.Println("    ctx.response.status    " + terminal.Gray("number  — HTTP status code"))
	fmt.Println("    ctx.response.body      " + terminal.Gray("string  — response body"))
	fmt.Println("    ctx.response.headers   " + terminal.Gray("object  — response headers {name: value}"))
	fmt.Println("    ctx.response.raw       " + terminal.Gray("string  — full raw HTTP response"))
	fmt.Println()
}

func printInsertionPointReference() {
	fmt.Println("  " + terminal.BoldCyan("Insertion Point (insertion)"))
	fmt.Println("  " + strings.Repeat("─", 27))
	fmt.Println()
	fmt.Println("    Passed to scanPerInsertionPoint only:")
	fmt.Println()
	fmt.Println("    insertion.name                    " + terminal.Gray("string  — parameter name"))
	fmt.Println("    insertion.baseValue               " + terminal.Gray("string  — original parameter value"))
	fmt.Println("    insertion.type                    " + terminal.Gray("string  — insertion point type (url_param, body_param, ...)"))
	fmt.Println("    insertion.buildRequest(payload)   " + terminal.Gray("string  — build raw HTTP request with payload injected"))
	fmt.Println()
}

func printReturnContractReference() {
	fmt.Println("  " + terminal.BoldCyan("Return Values"))
	fmt.Println("  " + strings.Repeat("─", 13))
	fmt.Println()
	fmt.Println("    " + terminal.Yellow("pre_hook") + " execute(request):")
	fmt.Println("      return request             " + terminal.Gray("— pass through (optionally modified)"))
	fmt.Println("      return {headers: {...}}     " + terminal.Gray("— merge/override headers"))
	fmt.Println("      return {raw: \"...\"}         " + terminal.Gray("— replace entire raw request"))
	fmt.Println("      return null                 " + terminal.Gray("— skip this request"))
	fmt.Println()
	fmt.Println("    " + terminal.Yellow("post_hook") + " execute(result):")
	fmt.Println("      return result              " + terminal.Gray("— pass through (optionally modified)"))
	fmt.Println("      return null                " + terminal.Gray("— drop this finding"))
	fmt.Println()
	fmt.Println("    " + terminal.Yellow("active/passive") + " scanPerRequest(ctx) / scanPerInsertionPoint(ctx, insertion):")
	fmt.Println("      return [{matched, url, name, description, severity}]   " + terminal.Gray("— array of findings"))
	fmt.Println("      return null                                            " + terminal.Gray("— no findings"))
	fmt.Println()
}

func printParseURLReference() {
	fmt.Println("  " + terminal.BoldCyan("parse_url Format Directives"))
	fmt.Println("  " + strings.Repeat("─", 27))
	fmt.Println()
	fmt.Println("    %s   scheme        " + terminal.Gray("(https)"))
	fmt.Println("    %d   hostname      " + terminal.Gray("(sub.example.com)"))
	fmt.Println("    %S   subdomain     " + terminal.Gray("(sub)"))
	fmt.Println("    %r   root domain   " + terminal.Gray("(example.com)"))
	fmt.Println("    %t   TLD           " + terminal.Gray("(com)"))
	fmt.Println("    %P   port          " + terminal.Gray("(8080, empty if default)"))
	fmt.Println("    %p   path          " + terminal.Gray("(/api/v1/users)"))
	fmt.Println("    %e   file ext      " + terminal.Gray("(html, js)"))
	fmt.Println("    %q   query string  " + terminal.Gray("(key=val&foo=bar)"))
	fmt.Println("    %f   fragment      " + terminal.Gray("(section1)"))
	fmt.Println("    %a   authority     " + terminal.Gray("(example.com:8080)"))
	fmt.Println("    %%   literal %")
	fmt.Println()
}

func printModuleTemplates() {
	fmt.Println("  " + terminal.BoldCyan("Module Export Templates"))
	fmt.Println("  " + strings.Repeat("─", 22))
	fmt.Println()
	fmt.Println(terminal.Gray("    // Pre-hook: modify or filter requests before scanning"))
	fmt.Println(terminal.Gray("    module.exports = {"))
	fmt.Println(terminal.Gray("      id: \"my-hook\", name: \"My Hook\", type: \"pre_hook\","))
	fmt.Println(terminal.Gray("      execute: function(request) { return request; }"))
	fmt.Println(terminal.Gray("    };"))
	fmt.Println()
	fmt.Println(terminal.Gray("    // Passive module: inspect responses without sending new requests"))
	fmt.Println(terminal.Gray("    module.exports = {"))
	fmt.Println(terminal.Gray("      id: \"my-passive\", name: \"My Passive\", type: \"passive\","))
	fmt.Println(terminal.Gray("      severity: \"info\", scope: \"response\", scanTypes: [\"per_request\"],"))
	fmt.Println(terminal.Gray("      scanPerRequest: function(ctx) { return null; }"))
	fmt.Println(terminal.Gray("    };"))
	fmt.Println()
	fmt.Println(terminal.Gray("    // Active module: send custom payloads per insertion point"))
	fmt.Println(terminal.Gray("    module.exports = {"))
	fmt.Println(terminal.Gray("      id: \"my-active\", name: \"My Active\", type: \"active\","))
	fmt.Println(terminal.Gray("      severity: \"medium\", scanTypes: [\"per_insertion_point\"],"))
	fmt.Println(terminal.Gray("      scanPerInsertionPoint: function(ctx, insertion) { return null; }"))
	fmt.Println(terminal.Gray("    };"))
	fmt.Println()
	fmt.Printf("  %s Install working examples: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium extensions preset"))
	fmt.Println()
}

// ──────────────────────────────────────────────────────────────
// extensions preset
// ──────────────────────────────────────────────────────────────

func installPresets(filter string) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		fmt.Printf("%s Failed to load settings: %v\n", terminal.ErrorSymbol(), err)
		return
	}

	targetDir := config.ExpandPath(settings.DynamicAssessment.Extensions.ExtensionDir)
	if targetDir == "" {
		targetDir = config.ExpandPath("~/.vigolium/extensions/")
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Printf("%s Failed to create directory %s: %v\n", terminal.ErrorSymbol(), targetDir, err)
		return
	}

	entries, err := public.StaticFS.ReadDir("presets/extensions")
	if err != nil {
		fmt.Printf("%s Failed to read embedded presets: %v\n", terminal.ErrorSymbol(), err)
		return
	}

	filterLower := strings.ToLower(filter)
	var installed, skipped int

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".vgm.yaml") {
			continue
		}

		if filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		destPath := filepath.Join(targetDir, name)

		if _, err := os.Stat(destPath); err == nil {
			fmt.Printf("  %s %s %s\n", terminal.WarningSymbol(), name, terminal.Gray("(already exists, skipped)"))
			skipped++
			continue
		}

		data, err := public.StaticFS.ReadFile("presets/extensions/" + name)
		if err != nil {
			fmt.Printf("  %s Failed to read %s: %v\n", terminal.ErrorSymbol(), name, err)
			continue
		}

		if err := os.WriteFile(destPath, data, 0644); err != nil {
			fmt.Printf("  %s Failed to write %s: %v\n", terminal.ErrorSymbol(), name, err)
			continue
		}

		fmt.Printf("  %s %s\n", terminal.SuccessSymbol(), name)
		installed++
	}

	fmt.Println()
	if installed > 0 {
		fmt.Printf("%s %d preset(s) installed to %s\n", terminal.SuccessSymbol(), installed, terminal.Gray(targetDir))
	}
	if skipped > 0 {
		fmt.Printf("%s %d preset(s) skipped (already exist)\n", terminal.InfoSymbol(), skipped)
	}
	if installed == 0 && skipped == 0 && filter != "" {
		fmt.Printf("%s No presets matching %q\n", terminal.WarningSymbol(), filter)
	}

	if !settings.DynamicAssessment.Extensions.Enabled {
		fmt.Println()
		fmt.Printf("%s Extensions not enabled. Enable with: %s\n",
			terminal.WarningSymbol(),
			terminal.Gray("vigolium config set dynamic_assessment.extensions.enabled true"))
	}
	fmt.Println()
}
