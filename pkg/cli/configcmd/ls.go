package configcmd

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func newLsCmd(deps Deps, example string) *cobra.Command {
	var showSecrets, effective bool
	cmd := &cobra.Command{
		Use:     "ls [filter]",
		Aliases: []string{"list", "view"},
		Short:   "Display current configuration",
		Long: "Display the settings a scan in the active project runs under: the global config with the project's overlay applied. " +
			"Every settable key is listed, including keys set to false or empty, with its typed value, default and the layer that set it " +
			"(default, file, env:NAME, project, flag). --effective lists only the keys a layer set. " +
			"String credentials (API keys, tokens, passwords) are redacted by default; pass --show-secrets to reveal them in plaintext. " +
			"Optionally filter by key (substring or fuzzy subsequence match, e.g. \"store\" matches \"storage.*\"). Filters containing glob metacharacters (* ? [ ]) are matched as glob patterns against the full key or any dot-segment, e.g. \"kno*\" matches \"known_issue_scan.*\".",
		Example: example,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigLs(cmd, deps, args, showSecrets, effective)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Reveal sensitive values (API keys, tokens, credentials) in plaintext instead of [redacted]; prints a warning to stderr")
	cmd.Flags().BoolVar(&effective, "effective", false, "List only the keys a layer set (file, env:NAME, project, flag), each with its source")
	return cmd
}

// EntryView is one setting in the shape a machine consumer reads.
//
// Value is typed (bool, number, string, list, object) and REDACTED under the
// default policy when the key is a string credential; Display is the string
// the human table prints. `sensitive` is carried so a consumer can tell a
// genuinely empty setting from one that was withheld.
type EntryView struct {
	Key       string `json:"key"`
	Value     any    `json:"value"`
	Display   string `json:"display"`
	Default   any    `json:"default"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Redacted  bool   `json:"redacted"`
}

// display renders the value for the human table.
func (v EntryView) display() string {
	if v.Empty {
		return "(empty)"
	}
	return v.Display
}

func newConfigEntryView(entry config.SettingEntry, source string, showSecrets bool) EntryView {
	v := EntryView{
		Key:       entry.Key,
		Value:     entry.Value,
		Display:   config.DisplaySettingValue(entry.Value),
		Default:   entry.Default,
		Type:      entry.Type,
		Source:    source,
		Sensitive: entry.Sensitive,
		Empty:     isEmptyValue(entry.Value),
	}
	if entry.Sensitive && !showSecrets && !v.Empty {
		v.Value = clicommon.SecretPlaceholder
		v.Display = clicommon.SecretPlaceholder
		v.Redacted = true
	}
	if entry.Sensitive && !showSecrets {
		// A default credential is redacted too: it may be a real key baked
		// into a build.
		if d, ok := entry.Default.(string); ok && d != "" {
			v.Default = clicommon.SecretPlaceholder
		}
	}
	return v
}

func isEmptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func runConfigLs(cmd *cobra.Command, deps Deps, args []string, showSecrets, effective bool) error {
	settings, projectUUID, err := deps.loadSettings()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	var flagKeys []string
	if deps.FlagKeys != nil {
		flagKeys = deps.FlagKeys()
	}
	sources, err := config.TraceSources(config.TraceOptions{ConfigPath: deps.ConfigFlag(), ProjectUUID: projectUUID, FlagKeys: flagKeys})
	if err != nil {
		return fmt.Errorf("failed to trace config sources: %w", err)
	}

	entries := config.SettingEntries(settings)

	// Apply filter if provided
	filter := ""
	if len(args) > 0 {
		filter = strings.ToLower(args[0])
	}

	// Secret reveal is gated exclusively on the purpose-specific --show-secrets
	// flag, never on the generic --force. This keeps API keys and tokens out of
	// agent transcripts and CI logs unless plaintext is explicitly requested.
	if showSecrets {
		fmt.Fprintf(os.Stderr, "%s Revealing sensitive configuration values in plaintext.\n", terminal.WarningSymbol())
	}

	matched := make([]EntryView, 0, len(entries))
	for _, entry := range entries {
		if filter != "" && !keyMatches(strings.ToLower(entry.Key), filter) {
			continue
		}
		source := config.SourceOf(sources, entry.Key)
		if effective && source == config.SourceDefault {
			continue
		}
		matched = append(matched, newConfigEntryView(entry, source, showSecrets))
	}

	// The redaction rule is identical in both modes: a machine caller is the
	// LAST consumer that should be handed plaintext credentials, since -j
	// output routinely lands in an agent transcript.
	if deps.jsonRequested() {
		extra := map[string]any{
			"config_path": config.ContractPath(clicommon.EffectiveConfigPath(deps.ConfigFlag())),
			"redacted":    !showSecrets,
			"filter":      filter,
			"effective":   effective,
		}
		if projectUUID != "" {
			extra["project_uuid"] = projectUUID
		}
		return deps.WriteJSON(cmd, "entries", matched, len(matched), extra)
	}

	for _, e := range matched {
		line := fmt.Sprintf("%s = %s", sectionKeyColor(e.Key)(e.Key), colorizeValue(e.display()))
		if effective || e.Source != config.SourceDefault {
			line += "  " + terminal.Gray("("+e.Source+")")
		}
		fmt.Println(line)
	}

	if count := len(matched); count == 0 {
		if filter != "" {
			fmt.Printf("%s No config keys matching %q\n", terminal.WarnPrefix(), filter)
		} else {
			fmt.Printf("%s No configuration found\n", terminal.WarnPrefix())
		}
		return nil
	}

	if filter == "" {
		fmt.Println()
		fmt.Printf("%s Config file: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(clicommon.EffectiveConfigPath(deps.ConfigFlag()))))
		if projectUUID != "" {
			fmt.Printf("%s Project overlay: %s\n", terminal.InfoSymbol(), terminal.Gray(projectUUID))
		}
	}

	return nil
}

// keyMatches reports whether filter selects key. A filter containing glob
// metacharacters (* ? [ ]) is treated as a glob pattern; anything else falls
// back to the substring / fuzzy-subsequence match. A malformed glob pattern
// also falls back to fuzzy matching so a stray bracket never silently hides
// every key. Both inputs must already be lowercased.
func keyMatches(key, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.ContainsAny(filter, "*?[") {
		if matched, err := globMatchKey(key, filter); err == nil {
			return matched
		}
	}
	return fuzzyMatchKey(key, filter)
}

// globMatchKey reports whether a path.Match-style glob pattern matches the full
// key or any single dot-segment. Keys never contain '/', so '*' matches any run
// of characters (including dots): "kno*" matches the key "known_issue_scan.x"
// directly and the segment "known_issue_scan" inside "scanning_pace.known_issue_scan.y".
// err is non-nil only when the pattern itself is malformed.
func globMatchKey(key, pattern string) (bool, error) {
	matched, err := path.Match(pattern, key)
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}
	for _, segment := range strings.Split(key, ".") {
		matched, err := path.Match(pattern, segment)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// fuzzyMatchKey reports whether filter matches key as a substring, or as an
// in-order subsequence within any single dot-segment. Both inputs must already
// be lowercased. The per-segment subsequence rule lets "store" match
// "storage.*" (s-t-o-r-...-e inside the "storage" segment) while still
// rejecting unrelated keys whose s/t/o/r/e happen to be scattered across
// segments.
func fuzzyMatchKey(key, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.Contains(key, filter) {
		return true
	}
	for _, segment := range strings.Split(key, ".") {
		if subsequenceMatch(segment, filter) {
			return true
		}
	}
	return false
}

func subsequenceMatch(s, filter string) bool {
	i := 0
	for j := 0; j < len(s) && i < len(filter); j++ {
		if s[j] == filter[i] {
			i++
		}
	}
	return i == len(filter)
}

// colorizeValue paints a config value based on its type so `config ls` output
// is easier to scan: redactions stand out in red, booleans/numbers/lists each
// get their own hue, and the placeholder "(empty)" is dimmed.
func colorizeValue(v string) string {
	switch {
	case v == clicommon.SecretPlaceholder:
		return terminal.BoldRed(v)
	case v == "(empty)":
		return terminal.Gray(v)
	case v == "true":
		return terminal.Green(v)
	case v == "false":
		return terminal.Red(v)
	case strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]"):
		return terminal.Magenta(v)
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return terminal.Yellow(v)
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return terminal.Yellow(v)
	}
	return terminal.HiWhite(v)
}

// sectionKeyColor returns a color function based on the top-level config section.
func sectionKeyColor(key string) func(string) string {
	section, _, _ := strings.Cut(key, ".")
	switch section {
	case "server":
		return terminal.Cyan
	case "database":
		return terminal.Blue
	case "notify":
		return terminal.Yellow
	case "dynamic-assessment":
		return terminal.Green
	case "mutation_strategy":
		return terminal.Teal
	case "scope":
		return terminal.HiGreen
	case "scanning_pace":
		return terminal.Magenta
	default:
		return terminal.Cyan
	}
}
