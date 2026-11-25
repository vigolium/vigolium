package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/utils"
)

// pinnedEnvVar makes the environment pins binding. A caller that pins a
// session with VIGOLIUM_CONFIG, VIGOLIUM_DB_PATH, VIGOLIUM_REQUIRE_SCOPE and
// VIGOLIUM_RATE_CEILING (an orchestrator handing a shell to an agent) sets it
// so the command line can narrow what the pins allow and never widen it:
// each widening flag below exits 2 refused_by_policy, with error.hint carrying
// the same command line without it. VIGOLIUM_RATE_CEILING needs no entry here:
// no flag raises a dial past it (rate_ceiling.go).
const pinnedEnvVar = "VIGOLIUM_PINNED"

// pinnedEnv reports whether VIGOLIUM_PINNED is on (1/true/yes/on).
func pinnedEnv() bool {
	return utils.EnvTruthy(pinnedEnvVar)
}

// pinnedBoolWideners are the switches that widen a pinned session when on:
// out-of-scope sends, cross-host redirects (scan's --ignore-scope), raw
// credentials on stdout, every stored record as input, a browser with its
// security exceptions off, results shipped off the machine, and risky payloads.
var pinnedBoolWideners = []string{
	"ignore-scope", "no-redact", "all-records", "browser-insecure", "upload-results", "allow-risky-payloads",
}

// pinnedRefusedCommands are the commands a pinned session refuses outright,
// with the reason the refusal names.
var pinnedRefusedCommands = map[string]string{
	"scan stop": "`scan stop` ends another run's scan",
}

// pinnedSetPrefixes are the --set keys a pinned session refuses outright: the
// scope and the out-of-band collector are what the pinned config decides.
var pinnedSetPrefixes = []string{"scope.", "oast."}

// pinnedRefusal is one refused part of the command line: why, and which argv
// tokens the corrected line drops.
type pinnedRefusal struct {
	reason string
	drop   func(argv []string) []string
}

// refusePinnedWidening is the one check behind VIGOLIUM_PINNED, run from the
// root PersistentPreRunE before anything loads settings, opens a store or
// sends. argv is the command line after the binary name, for the hint. A nil
// result means the command line widens nothing (or the variable is off).
func refusePinnedWidening(cmd *cobra.Command, argv []string) error {
	if cmd == nil || !pinnedEnv() {
		return nil
	}
	refused := pinnedRefusals(cmd)
	if len(refused) == 0 {
		return nil
	}
	reasons, hint := pinnedRefusalReport(refused, argv)
	return clicommon.CLIError{
		Err:  fmt.Errorf("refused by %s=1: %s; nothing ran", pinnedEnvVar, strings.Join(reasons, "; ")),
		Code: apicontract.CodeRefusedByPolicy,
		Hint: hint,
	}
}

// pinnedRefusals lists what a pinned session refuses on cmd as parsed (its
// flags' Changed state and values, and the --set overlay), whether or not
// the variable is on: refusePinnedWidening applies them, and `explain-argv`
// reports them for a line it parsed without running.
func pinnedRefusals(cmd *cobra.Command) []pinnedRefusal {
	var refused []pinnedRefusal
	add := func(reason string, drop func([]string) []string) {
		refused = append(refused, pinnedRefusal{reason: reason, drop: drop})
	}
	flags := cmd.Flags()

	if reason, ok := pinnedRefusedCommands[commandPathWithoutRoot(cmd)]; ok {
		add(reason, nil)
	}

	// --config / --db naming anything but the pinned file.
	for _, pin := range []struct{ flag, env string }{
		{"config", configEnvVar},
		{"db", dbPathEnvVar},
	} {
		f := flags.Lookup(pin.flag)
		if f == nil || !f.Changed {
			continue
		}
		// A pure read of another file (`traffic -S --db ./scan.jsonl`, `finding --db x`) sends
		// nothing and writes nothing, so it reads freely; only a command that writes a store or
		// sends traffic is held to the pinned one.
		if pin.flag == "db" {
			if t, ok := traitOf(cmd); ok && t.DB == dbRead && !t.SendsTraffic {
				continue
			}
		}
		pinned := strings.TrimSpace(os.Getenv(pin.env))
		if pin.flag == "db" && pinned == "" {
			pinned = strings.TrimSpace(os.Getenv(dbEnvVar))
		}
		typed := strings.TrimSpace(f.Value.String())
		if pinned != "" && config.ExpandPath(typed) == config.ExpandPath(pinned) {
			continue
		}
		add(fmt.Sprintf("--%s %s is not the pinned %s", pin.flag, typed, pin.env), dropFlag(f, nil))
	}

	for _, name := range pinnedBoolWideners {
		if f := flags.Lookup(name); f != nil && f.Changed && f.Value.String() == "true" {
			add("--"+name+" widens the pinned session", dropFlag(f, nil))
		}
	}

	if f := flags.Lookup("redirect-mode"); f != nil && f.Changed && strings.EqualFold(strings.TrimSpace(f.Value.String()), "any") {
		add("--redirect-mode any follows redirects to any host", dropFlag(f, nil))
	}
	if f := flags.Lookup("intensity"); f != nil && f.Changed && strings.EqualFold(strings.TrimSpace(f.Value.String()), "deep") {
		add("--intensity deep lifts scope, tier and risky-payload limits", dropFlag(f, nil))
	}

	ceiling := 0 // the pinned config's dynamic-assessment.max_module_tier rank; 0 = none
	if settings, err := config.LoadSettings(strings.TrimSpace(os.Getenv(configEnvVar))); err == nil {
		ceiling, _ = modules.TierRankByName(settings.DynamicAssessment.MaxModuleTier)
	}
	raisesTier := func(name string) bool {
		if ceiling == 0 {
			return false
		}
		rank, ok := modules.TierRankByName(name)
		return !ok || rank > ceiling
	}
	if f := flags.Lookup("max-module-tier"); f != nil && f.Changed && strings.TrimSpace(f.Value.String()) != "" &&
		raisesTier(f.Value.String()) {
		add(fmt.Sprintf("--max-module-tier %s is above the pinned config's", f.Value.String()), dropFlag(f, nil))
	}

	if f := flags.Lookup("set"); f != nil && f.Changed {
		for _, entry := range globalSetOverlay {
			key, value, _ := strings.Cut(entry, "=")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			reason := ""
			switch {
			case hasAnyPrefix(key, pinnedSetPrefixes):
				reason = "--set " + key + " changes what the pinned config decides"
			case config.SettingPath(key) == "dynamic-assessment.max_module_tier" && raisesTier(value):
				reason = "--set " + key + " raises the pinned module tier ceiling"
			case config.SettingPath(key) == "dynamic-assessment.allow_risky_payloads" && isTrueWord(value):
				reason = "--set " + key + " allows risky payloads"
			}
			if reason != "" {
				refused := entry
				add(reason, dropFlag(f, func(v string) bool { return v == refused }))
			}
		}
	}

	return refused
}

// pinnedRefusalReport is the reasons of refused, in order, and the hint: argv
// (the command line after the binary name) without the refused tokens, or why
// there is nothing to run instead.
func pinnedRefusalReport(refused []pinnedRefusal, argv []string) (reasons []string, hint string) {
	reasons = make([]string, 0, len(refused))
	corrected := append([]string(nil), argv...)
	stopRefused := false
	for _, r := range refused {
		reasons = append(reasons, r.reason)
		if r.drop == nil {
			stopRefused = true
			continue
		}
		corrected = r.drop(corrected)
	}
	hint = "vigolium " + quoteArgv(corrected)
	if stopRefused {
		hint = "nothing to run instead: a pinned session cannot stop another scan; it ends at its own deadline"
	}
	return reasons, hint
}

// dropFlag returns an argv filter that removes f's occurrences (long and
// shorthand, `--f v` and `--f=v`); with match set, only the occurrences whose
// value it accepts.
func dropFlag(f *pflag.Flag, match func(value string) bool) func([]string) []string {
	takesValue := f.NoOptDefVal == "" && f.Value.Type() != "bool"
	return func(argv []string) []string {
		out := make([]string, 0, len(argv))
		for i := 0; i < len(argv); i++ {
			tok := argv[i]
			if tok == "--" {
				return append(out, argv[i:]...)
			}
			name, value, hasValue := flagToken(tok)
			if name != f.Name && (f.Shorthand == "" || name != "-"+f.Shorthand) {
				out = append(out, tok)
				continue
			}
			next := i
			if !hasValue && takesValue && i+1 < len(argv) {
				value = argv[i+1]
				next = i + 1
			}
			if match != nil && !match(value) {
				out = append(out, argv[i:next+1]...)
				i = next
				continue
			}
			i = next
		}
		return out
	}
}

// flagToken splits one argv token: "--name=v" → ("name", "v", true), "--name"
// → ("name", "", false), "-s" → ("-s", "", false). A positional returns "".
func flagToken(tok string) (name, value string, hasValue bool) {
	switch {
	case strings.HasPrefix(tok, "--") && len(tok) > 2:
		name, value, hasValue = strings.Cut(tok[2:], "=")
		return name, value, hasValue
	case strings.HasPrefix(tok, "-") && len(tok) == 2:
		return tok, "", false
	}
	return "", "", false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func isTrueWord(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "yes", "on":
		return true
	}
	return false
}
