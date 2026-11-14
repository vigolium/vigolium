package clicommon

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// EffectiveConfigPath resolves the config file path to operate on: the expanded
// --config flag value when set, otherwise the default config file location.
func EffectiveConfigPath(configFlag string) string {
	if configFlag != "" {
		return config.ExpandPath(configFlag)
	}
	return config.ConfigFilePath()
}

// ConfigWarn prints one configuration diagnostic. The default writes to stderr;
// pkg/cli replaces it so --silent and the machine-output modes are honoured.
//
// A package var rather than a parameter for the same reason Policy is one: LoadSettings is reached from ~35 call sites, none of which decides output
// policy, and threading a writer through all of them to answer a question only
// the root command knows is worse than one assignment at startup.
var ConfigWarn = func(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

// configWarned dedupes diagnostics across a process. A command that loads
// settings five times (scan does) must not print the same unknown-key warning
// five times — the repetition reads as five separate problems.
var (
	configWarnMu sync.Mutex
	configWarned = map[string]bool{}
)

// WarnConfigOnce emits msg through ConfigWarn unless this process already has.
// Exported so pkg/cli's own config diagnostics (settingsOrDefaults) share the
// dedupe rather than being the one configuration warning that can repeat.
func WarnConfigOnce(msg string) {
	configWarnMu.Lock()
	seen := configWarned[msg]
	configWarned[msg] = true
	configWarnMu.Unlock()
	if !seen {
		ConfigWarn(msg)
	}
}

// ResetConfigWarningsForTest clears the once-per-process dedupe.
func ResetConfigWarningsForTest() {
	configWarnMu.Lock()
	configWarned = map[string]bool{}
	configWarnMu.Unlock()
}

// DiscoveredConfigFatal makes an unreadable DISCOVERED config fatal in
// LoadSettings. The root command sets it for every command except the ones
// that exist to inspect or repair a broken config (see LoadSettings).
var DiscoveredConfigFatal bool

// LoadSettings is the CLI's single entry point for reading configuration.
//
// It applies the one policy that was previously re-decided (differently) at
// every call site:
//
//   - A config file the operator NAMED with --config is load-bearing. If it
//     cannot be read or parsed, the command fails. Most call sites used to
//     answer that with `settings = config.DefaultSettings()`, so a typo in
//     --config meant the command ran against the default database and the
//     default scan profile and exited 0 — the single worst outcome available,
//     because it looks exactly like success.
//   - A config file found by DISCOVERY that cannot be read is fatal too
//     (config_invalid, naming the path and `vigolium config validate`) on
//     every command that acts on it — DiscoveredConfigFatal, set by the root
//     command. Falling back to built-in defaults silently dropped the operator's
//     scope excludes, rate limits and `oast.enabled: false`. The repair
//     commands (doctor, config validate|clean|ls, version, help) keep the old
//     warn-and-default behaviour so the broken file can be inspected and fixed.
//
// Non-fatal diagnostics (unknown keys, a shadowed ./vigolium-configs.yaml) are
// printed once per process through ConfigWarn.
func LoadSettings(configPath string) (*config.Settings, error) {
	settings, warnings, err := config.LoadSettingsWithWarnings(configPath)
	if err != nil {
		var loadErr *config.LoadError
		if errors.As(err, &loadErr) && !loadErr.Explicit && DiscoveredConfigFatal {
			return nil, CodedErrorf(apicontract.CodeConfigInvalid,
				"config %s is unreadable: %v; fix it (run `vigolium config validate`) or pass --config <file>",
				loadErr.Path, loadErr.Err)
		}
		if errors.As(err, &loadErr) && !loadErr.Explicit {
			WarnConfigOnce(fmt.Sprintf("ignoring unreadable config %s: %v; using built-in defaults",
				loadErr.Path, loadErr.Err))
			return config.DefaultSettings(), nil
		}
		return nil, err
	}
	for _, w := range warnings {
		WarnConfigOnce(w)
	}
	return settings, nil
}

// LoadProjectSettings is LoadSettings plus the project layer: the global config
// (with LoadSettings' explicit-vs-discovered failure policy and warnings), then
// projectUUID's overlay from config.ProjectConfigPath — the file `scope set
// --project` and `project config` write. An empty projectUUID is global-only.
//
// Every command that runs a scan or judges scope under a resolved project loads
// through here, so the documented precedence (global → project → scanning
// profile → CLI) holds: the profile and CLI layers are applied afterwards by
// the scan-options resolver. A broken overlay is fatal for the same reason a
// broken --config is: it was written on purpose, usually to narrow scope.
func LoadProjectSettings(configPath, projectUUID string) (*config.Settings, error) {
	settings, err := LoadSettings(configPath)
	if err != nil {
		return nil, err
	}
	if err := config.ApplyProjectOverlay(settings, projectUUID); err != nil {
		return nil, err
	}
	return settings, nil
}
