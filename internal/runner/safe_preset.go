package runner

import (
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/public"
)

// safeOverlayPath is the embedded --safe overlay.
const safeOverlayPath = "presets/overlays/safe.yaml"

// SafeMethods are the only methods a --safe scan's module, discovery and
// browser traffic may use.
var SafeMethods = []string{"GET", "HEAD"}

// ApplySafePreset applies --safe: the embedded overlay
// (presets/overlays/safe.yaml: low pace, a 15m total budget, strict origin,
// shallow recursion, no form submission/uploads/logins in the browser, no
// intrusive known-issue templates), then the parts the code enforces whatever
// the config says: risky payloads off, traffic limited to SafeMethods, param
// mining off unless --param-mining was typed.
//
// Order: after ApplyIntensityAndProfile (the overlay narrows the profile) and
// before ApplyScanSettingOverrides (typed flags still win). A no-op without
// opts.Safe.
func ApplySafePreset(settings *config.Settings, opts *types.Options) error {
	if opts == nil || !opts.Safe {
		return nil
	}
	data, err := public.StaticFS.ReadFile(safeOverlayPath)
	if err != nil {
		return fmt.Errorf("--safe: read embedded overlay: %w", err)
	}
	if err := config.ApplyProfileData(settings, data, safeOverlayPath); err != nil {
		return fmt.Errorf("--safe: %w", err)
	}
	settings.Scope.Methods = append([]string(nil), SafeMethods...)
	if c := settings.ScanningPace.Concurrency; c > 0 {
		opts.ConcurrencyCeiling = c
	}
	off := false
	opts.AllowRiskyPayloads = &off
	settings.DynamicAssessment.AllowRiskyPayloads = false
	if opts.ParamMining == nil {
		opts.ParamMining = &off
	}
	return nil
}

// ApplyDefaultScanBudget bounds the whole scan by
// scanning_pace.scan_max_duration (default 1h; --safe 15m) when no total
// budget was typed. Run after ApplyScanSettingOverrides: the default caps the
// scan's wall clock but, unlike a typed --max-time, does not rescale the
// per-phase budgets (scanning_pace.max_duration × duration_factor).
func ApplyDefaultScanBudget(settings *config.Settings, opts *types.Options) {
	if opts == nil || settings == nil || opts.ScanMaxDuration > 0 {
		return
	}
	if d := settings.ScanningPace.ScanMaxDurationParsed(); d > 0 {
		opts.ScanMaxDuration = d
	}
}

