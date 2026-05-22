package configcmd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func newLsCmd(deps Deps, example string) *cobra.Command {
	return &cobra.Command{
		Use:     "ls [filter]",
		Aliases: []string{"list", "view"},
		Short:   "Display current configuration",
		Long:    "Display current configuration settings. Optionally filter by key (substring or fuzzy subsequence match, e.g. \"store\" matches \"storage.*\").",
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigLs(deps, args)
		},
	}
}

func runConfigLs(deps Deps, args []string) error {
	settings, err := config.LoadSettings(deps.ConfigFlag())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	entries := config.FlattenSettings(settings)

	// Sort entries by key for stable output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	// Apply filter if provided
	filter := ""
	if len(args) > 0 {
		filter = strings.ToLower(args[0])
	}

	force := deps.Force()
	count := 0
	for _, entry := range entries {
		if filter != "" && !fuzzyMatchKey(strings.ToLower(entry.Key), filter) {
			continue
		}

		displayValue := entry.Value
		if entry.Sensitive && !force {
			if entry.Value != "" && entry.Value != "<nil>" {
				displayValue = "[redacted]"
			} else {
				displayValue = "(empty)"
			}
		} else if entry.Value == "" || entry.Value == "<nil>" {
			displayValue = "(empty)"
		}

		keyColor := sectionKeyColor(entry.Key)
		fmt.Printf("%s = %s\n", keyColor(entry.Key), colorizeValue(displayValue))
		count++
	}

	if count == 0 {
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
	}

	return nil
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
	case v == "[redacted]":
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
