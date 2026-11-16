package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/config"
)

// rateCeilingFlags are the flags VIGOLIUM_RATE_CEILING bounds on whichever
// command declares them: the rate (requests/second) and the two count dials.
// The flag names are the CLI's own vocabulary (flag_vocab_test.go holds every
// command to them), so matching by name reaches every sender — scan family,
// fuzz, kit param-mine, finding verify, replay, traffic --replay — without a
// per-command copy, and a new sender that registers one of them is covered
// the day it lands.
var rateCeilingFlags = []string{"rate-limit", "concurrency", "max-per-host"}

// applyRateCeilingToFlags lowers the executing command's rate and count flags
// to VIGOLIUM_RATE_CEILING (config.CeilRate and friends: an unlimited rate of 0
// becomes the ceiling, a value above it the ceiling, anything at or below it is
// untouched). It runs after parsing and before the command, so every reader of
// a flag's variable sees the clamped value; the values the config file, a
// strategy or a profile contribute later are clamped where they are resolved
// (ApplyScanPace, runner.SetSettings, the scanning_pace resolvers).
//
// A negative value is left for the command's own validation to refuse (exit
// 2): clamping it would turn a usage error into a run. Changed is not touched,
// so "did the operator type it" keeps its meaning for the strategy and profile
// precedence rules.
func applyRateCeilingToFlags(cmd *cobra.Command) error {
	if !config.ActiveRateCeiling().Set() {
		return nil
	}
	for _, name := range rateCeilingFlags {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			continue
		}
		if err := ceilFlag(commandPathWithoutRoot(cmd), f); err != nil {
			return err
		}
	}
	return nil
}

// ceilFlag clamps one flag in place.
func ceilFlag(cmdPath string, f *pflag.Flag) error {
	// The scan family's three shared pace knobs: one dial name whichever of
	// scan/run/ingest/scan-url/scan-request/server runs, since they share the
	// variable. Written directly, not through Set, which would mark the bare
	// form typed (globalChanged).
	if knob, ok := f.Value.(*paceKnob); ok {
		if *knob.global >= 0 {
			*knob.global = config.CeilIntRate("--"+f.Name, *knob.global)
		}
		for _, phase := range knob.sortedPhases() {
			if v := knob.perPhase[phase]; v >= 0 {
				knob.perPhase[phase] = config.CeilIntRate("--"+f.Name+" "+phase, v)
			}
		}
		return nil
	}

	label := cmdPath + " --" + f.Name
	switch f.Value.Type() {
	case "float64":
		v, err := strconv.ParseFloat(f.Value.String(), 64)
		if err != nil || v < 0 {
			return nil
		}
		if out := config.CeilRate(label, v); out != v {
			return setFlagValue(f, strconv.FormatFloat(out, 'f', -1, 64))
		}
	case "int":
		v, err := strconv.Atoi(f.Value.String())
		if err != nil || v < 0 {
			return nil
		}
		if out := config.CeilIntRate(label, v); out != v {
			return setFlagValue(f, strconv.Itoa(out))
		}
	}
	return nil
}

// setFlagValue writes through the flag's Value (not FlagSet.Set, which would
// mark it Changed).
func setFlagValue(f *pflag.Flag, value string) error {
	if err := f.Value.Set(value); err != nil {
		return fmt.Errorf("applying %s to --%s: %w", config.RateCeilingEnv, f.Name, err)
	}
	return nil
}
