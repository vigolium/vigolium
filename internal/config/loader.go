package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/public"
	"gopkg.in/yaml.v3"
)

// Settings holds all configuration settings
type Settings struct {
	Server            ServerConfig            `yaml:"server"`
	Database          DatabaseConfig          `yaml:"database"`
	Notify            NotifyConfig            `yaml:"notify"`
	DynamicAssessment DynamicAssessmentConfig `yaml:"dynamic-assessment"`
	MutationStrategy  MutationStrategyConfig  `yaml:"mutation_strategy"`
	Scope             ScopeConfig             `yaml:"scope"`
	Discovery         DiscoveryConfig         `yaml:"discovery"`
	KnownIssueScan    KnownIssueScanConfig    `yaml:"known_issue_scan"`
	ExternalHarvester ExternalHarvesterConfig `yaml:"external_harvester"`
	ScanningStrategy  ScanningStrategyConfig  `yaml:"scanning_strategy"`
	ScanningPace      ScanningPaceConfig      `yaml:"scanning_pace"`
	Spidering         SpideringConfig         `yaml:"spidering"`
	Agent             AgentConfig             `yaml:"agent"`
	OAST              OASTConfig              `yaml:"oast"`
	Storage           StorageConfig           `yaml:"storage"`
}

// ProfileScanningStrategy is the allowlist of ScanningStrategyConfig keys a
// profile is permitted to override: it selects WHICH strategy applies
// (DefaultStrategy) and tunes the heuristics check, and nothing else. The
// per-strategy phase tables (Lite/Balanced/Deep), session, scan_logs, http, and
// port_sweep are deliberately excluded — a profile picks a strategy, it does not
// redefine WHAT each strategy means or touch global-config concerns. This is why
// ApplyProfile merges scanning_strategy field-by-field (below) rather than through
// the general key-preserving section overlay: the general path would faithfully
// apply any strategy sub-key a profile set, widening this authorization boundary.
type ProfileScanningStrategy struct {
	DefaultStrategy string `yaml:"default_strategy,omitempty"`
	HeuristicsCheck string `yaml:"heuristics_check,omitempty"`
}

// ProfileSettings is the subset of Settings that a scanning profile can override.
// Only non-nil pointer fields are applied; nil fields leave the main config unchanged.
type ProfileSettings struct {
	ScanningStrategy  *ProfileScanningStrategy `yaml:"scanning_strategy,omitempty"`
	ScanningPace      *ScanningPaceConfig      `yaml:"scanning_pace,omitempty"`
	Discovery         *DiscoveryConfig         `yaml:"discovery,omitempty"`
	Spidering         *SpideringConfig         `yaml:"spidering,omitempty"`
	KnownIssueScan    *KnownIssueScanConfig    `yaml:"known_issue_scan,omitempty"`
	DynamicAssessment *DynamicAssessmentConfig `yaml:"dynamic-assessment,omitempty"`
	ExternalHarvester *ExternalHarvesterConfig `yaml:"external_harvester,omitempty"`
	MutationStrategy  *MutationStrategyConfig  `yaml:"mutation_strategy,omitempty"`
	Scope             *ScopeConfig             `yaml:"scope,omitempty"`
	Notify            *NotifyConfig            `yaml:"notify,omitempty"`

	// raw holds the profile document's top-level section value-nodes, keyed by
	// their YAML key, captured by LoadProfile and consumed by ApplyProfile (see
	// there for why). Unexported, so it never round-trips through YAML; nil for a
	// ProfileSettings built programmatically rather than loaded from a file.
	raw map[string]*yaml.Node
}

// LoadProfile reads and parses a scanning profile YAML file.
func LoadProfile(path string) (*ProfileSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file %s: %w", path, err)
	}
	return parseProfile(data, path)
}

// LoadProfileWithBuiltin is LoadProfile with a fallback for the built-in
// profiles: when path does not exist and name is a bare built-in profile name
// (quick, standard, full — the files under public/presets/profiles), the
// embedded copy is parsed instead. A container that mounts a config but never
// ran `init` has no profiles directory, and `--intensity quick` must still
// work there. A file on disk always wins, so operator edits stand.
func LoadProfileWithBuiltin(path, name string) (*ProfileSettings, error) {
	profile, err := LoadProfile(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return profile, err
	}
	if data, ok := BuiltinProfile(name); ok {
		return parseProfile(data, "embedded presets/profiles/"+name+".yaml")
	}
	return nil, err
}

// BuiltinProfile returns the embedded YAML of a built-in profile by bare name.
func BuiltinProfile(name string) ([]byte, bool) {
	if name == "" || strings.ContainsAny(name, `/\~.`) {
		return nil, false
	}
	data, err := public.StaticFS.ReadFile("presets/profiles/" + name + ".yaml")
	if err != nil {
		return nil, false
	}
	return data, true
}

// parseProfile parses profile YAML; label names the source in errors.
func parseProfile(data []byte, path string) (*ProfileSettings, error) {
	content := ExpandEnvVars(string(data))

	// Parse once into a node, then derive both the typed struct and the per-section
	// raw nodes from it. ApplyProfile overlays each present section from the raw
	// nodes so it applies only the keys the file actually set (key-preserving).
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse profile file %s: %w", path, err)
	}
	var profile ProfileSettings
	if err := doc.Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile file %s: %w", path, err)
	}
	profile.raw = topLevelSectionNodes(&doc)

	return &profile, nil
}

// topLevelSectionNodes returns the value node for each top-level mapping key in a
// parsed YAML document, keyed by the key string; these are what make ApplyProfile
// key-preserving. Returns nil for an empty or non-mapping document.
func topLevelSectionNodes(doc *yaml.Node) map[string]*yaml.Node {
	root := doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	sections := make(map[string]*yaml.Node, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		sections[root.Content[i].Value] = root.Content[i+1]
	}
	return sections
}

// ApplyProfile overlays non-nil profile sections onto settings.
//
// Each section is overlaid KEY-PRESERVINGLY: the section's raw YAML node (captured
// by LoadProfile) is decoded onto the live settings section, so only the keys the
// profile file actually set are written and an omitted sub-key (e.g.
// discovery.jstangle) keeps its global/default value. This replaces an earlier
// marshal→unmarshal round-trip that emitted every non-omitempty field as its zero
// value — which is how --intensity deep once silently zeroed
// discovery.jstangle.memory_budget_mb and aborted the whole Discovery phase.
//
// ScanningStrategy is handled specially via the ProfileScanningStrategy allowlist
// (merged field-by-field above) and never flows through the section overlay. Only
// sections present as raw nodes are overlaid, so a programmatically-built
// ProfileSettings (no raw nodes, e.g. tests) applies only ScanningStrategy here;
// every current caller of the section overlay goes through LoadProfile.
func ApplyProfile(settings *Settings, profile *ProfileSettings) error {
	if profile.ScanningStrategy != nil {
		if v := profile.ScanningStrategy.DefaultStrategy; v != "" {
			settings.ScanningStrategy.DefaultStrategy = v
		}
		if v := profile.ScanningStrategy.HeuristicsCheck; v != "" {
			settings.ScanningStrategy.HeuristicsCheck = v
		}
	}

	// Each entry pairs a section's YAML key (matching its ProfileSettings/Settings
	// yaml tag) with the live destination. Presence is decided by the raw node
	// alone: a key the file omitted is left untouched — defaults intact, never
	// re-zeroed — and a key written as an explicit null decodes as a no-op. The
	// matching ProfileSettings pointer fields are not consulted here; they exist
	// so LoadProfile type-checks the document up front.
	type overlay struct {
		key  string
		dest any
	}

	for _, o := range []overlay{
		{"scanning_pace", &settings.ScanningPace},
		{"discovery", &settings.Discovery},
		{"spidering", &settings.Spidering},
		{"known_issue_scan", &settings.KnownIssueScan},
		{"dynamic-assessment", &settings.DynamicAssessment},
		{"external_harvester", &settings.ExternalHarvester},
		{"mutation_strategy", &settings.MutationStrategy},
		{"scope", &settings.Scope},
		{"notify", &settings.Notify},
	} {
		node, ok := profile.raw[o.key]
		if !ok {
			continue
		}
		if err := node.Decode(o.dest); err != nil {
			return fmt.Errorf("failed to apply profile section %q: %w", o.key, err)
		}
	}

	return nil
}

// LoadError reports a configuration file that could not be used, and names the
// file. Every LoadSettings failure is one of these.
//
// Explicit distinguishes the two cases a caller must handle differently. A file
// the operator named with --config is load-bearing: failing to read it means
// running under settings they did not choose, so the caller fails. A file found
// by discovery is a convenience; an unreadable one warns and falls back to
// defaults. The distinction used to be invisible — LoadSettings returned a bare
// fmt.Errorf and ~35 call sites answered it with `settings = DefaultSettings()`,
// so `--config ./prod.yaml` with a typo in it ran the scan against the DEFAULT
// database and reported success.
//
// Op is "stat", "read" or "parse": which step failed, for a caller that wants to
// word its own message. Err is the underlying error and unwraps, so
// errors.Is(err, fs.ErrNotExist) still works.
type LoadError struct {
	Path     string
	Explicit bool
	Op       string
	Err      error
}

func (e *LoadError) Error() string {
	verb := "load"
	switch e.Op {
	case "stat":
		verb = "access"
	case "read":
		verb = "read"
	case "parse":
		verb = "parse"
	}
	return fmt.Sprintf("config file %s: cannot %s it: %v", e.Path, verb, e.Err)
}

func (e *LoadError) Unwrap() error { return e.Err }

// LoadSettings loads configuration from YAML file
// Search paths (in order):
//  1. --config flag path (if specified)
//  2. $HOME/.vigolium/vigolium-configs.yaml
//  3. ./vigolium-configs.yaml
//
// Every failure is a *LoadError. Use LoadSettingsWithWarnings (or, in the CLI,
// clicommon.LoadSettings) when the non-fatal diagnostics matter too.
func LoadSettings(configPath string) (*Settings, error) {
	settings, _, err := LoadSettingsWithWarnings(configPath)
	return settings, err
}

// LoadSettingsWithWarnings is LoadSettings plus the diagnostics that are worth
// printing but must not fail the command: unknown keys, and a cwd config file
// that discovery passed over.
//
// Both describe a file the operator wrote that is not doing what they think it
// is, which is otherwise indistinguishable from the setting having no effect.
// They are returned rather than printed so this package stays free of output
// policy (--silent, machine modes) that only the CLI knows.
func LoadSettingsWithWarnings(configPath string) (*Settings, []string, error) {
	var (
		path     string
		explicit = configPath != ""
		warnings []string
	)

	if explicit {
		path = ExpandPath(configPath)
		if _, err := os.Stat(path); err != nil {
			return nil, nil, &LoadError{Path: path, Explicit: true, Op: "stat", Err: err}
		}
	} else {
		home := ExpandPath("~/.vigolium/vigolium-configs.yaml")
		const cwdConfig = "./vigolium-configs.yaml"

		found := false
		for _, p := range []string{home, cwdConfig} {
			_, err := os.Stat(p)
			if err == nil {
				path = p
				found = true
				break
			}
			// ONLY a missing file falls through to the next candidate. A permission
			// error, a dangling symlink or an I/O error on ~/.vigolium means the
			// operator's config exists and could not be looked at, and silently
			// continuing to the next candidate (or to defaults) answered that with
			// a scan configured by nobody.
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, nil, &LoadError{Path: p, Explicit: false, Op: "stat", Err: err}
			}
		}

		// If no config file found, return default settings
		if !found {
			return DefaultSettings(), nil, nil
		}

		// Discovery is first-match-wins, so a project-local ./vigolium-configs.yaml
		// is INVISIBLE whenever the home file exists. Someone who drops one in a
		// repo expecting it to apply gets no error and no effect; say so.
		if path == home {
			if _, err := os.Stat(cwdConfig); err == nil {
				warnings = append(warnings, fmt.Sprintf(
					"%s is ignored because %s exists; pass --config %s to use it",
					cwdConfig, ContractPath(home), cwdConfig))
			}
		}
	}

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, &LoadError{Path: path, Explicit: explicit, Op: "read", Err: err}
	}

	// Expand environment variables in YAML content
	content := ExpandEnvVars(string(data))

	// Parse YAML on top of defaults so unspecified sections keep sensible values
	settings := *DefaultSettings()
	if err := yaml.Unmarshal([]byte(content), &settings); err != nil {
		return nil, nil, &LoadError{Path: path, Explicit: explicit, Op: "parse", Err: err}
	}

	if msg := unknownKeyWarning(path, content); msg != "" {
		warnings = append(warnings, msg)
	}

	// Install the configured global User-Agent selector so every scan phase that
	// resolves httpmsg.DefaultUserAgent() at request time picks it up. The
	// selector is "preset" (default, self-identifying string), "random"/"" (a
	// rotating browser string), or a literal; VIGOLIUM_DEFAULT_UA still wins at
	// resolution time.
	httpmsg.SetDefaultUserAgent(settings.ScanningStrategy.HTTP.UserAgent)

	return &settings, warnings, nil
}

// unknownKeyWarning decodes content a second time with KnownFields on and
// reports the keys that match no struct field, or "" when there are none.
//
// A second decode rather than one strict decode, because strictness here must
// never fail the load: a config written for a newer vigolium, or one carrying a
// key a build dropped, should still apply everything it CAN. But a typo
// (`default_stratgy`) is silently inert, and "I set it and nothing changed" is
// the single most expensive kind of configuration bug to chase.
//
// The throwaway destination is a zero Settings rather than defaults: nothing is
// read out of it, and building defaults twice per load is wasted work.
//
// The answer is memoized per exact (path, content), because the strict decode is
// half the cost of a whole load and its only output is a diagnostic the CLI
// already dedupes to one line per process. A scan loads settings five times, so
// four of those decodes could not produce anything observable. Keyed on the
// content itself, so a file that changes mid-process is re-checked rather than
// answered from a stale verdict.
func unknownKeyWarning(path, content string) string {
	cacheKey := path + "\x00" + content
	if cached, ok := unknownKeyCache.Load(cacheKey); ok {
		return cached.(string)
	}
	msg := computeUnknownKeyWarning(path, content)
	unknownKeyCache.Store(cacheKey, msg)
	return msg
}

// unknownKeyCache memoizes unknownKeyWarning. Bounded by the number of distinct
// config contents a process reads, which is one or two.
var unknownKeyCache sync.Map

func computeUnknownKeyWarning(path, content string) string {
	unknown := unknownKeyErrors(content, &Settings{})
	if len(unknown) == 0 {
		return ""
	}
	return fmt.Sprintf("config file %s has %d key(s) vigolium does not recognize (they have no effect): %s",
		path, len(unknown), strings.Join(unknown, "; "))
}

// unknownKeyErrors decodes content into into with KnownFields on and returns
// the decoder's "field X not found in type T" lines, one per unknown key. The
// throwaway destination is a zero value rather than defaults: nothing is read
// out of it. Shared by the load-time warning and `config validate`, so both
// name the same keys.
func unknownKeyErrors(content string, into any) []string {
	dec := yaml.NewDecoder(strings.NewReader(content))
	dec.KnownFields(true)
	err := dec.Decode(into)
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	// A *yaml.TypeError lists every offending key at once. Anything else here is
	// a parse failure the lenient decode already accepted, so it is not an
	// unknown key and saying "unknown key" about it would be wrong.
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return nil
	}
	var unknown []string
	for _, e := range typeErr.Errors {
		if strings.Contains(e, "not found in type") {
			unknown = append(unknown, e)
		}
	}
	return unknown
}

// DefaultSettings returns default configuration
func DefaultSettings() *Settings {
	return &Settings{
		Server:            *DefaultServerConfig(),
		Database:          *DefaultDatabaseConfig(),
		Notify:            *DefaultNotifyConfig(),
		DynamicAssessment: *DefaultDynamicAssessmentConfig(),
		MutationStrategy:  *DefaultMutationStrategyConfig(),
		Scope:             *DefaultScopeConfig(),
		Discovery:         *DefaultDiscoveryConfig(),
		KnownIssueScan:    *DefaultKnownIssueScanConfig(),
		ExternalHarvester: *DefaultExternalHarvesterConfig(),
		ScanningStrategy:  *DefaultScanningStrategyConfig(),
		ScanningPace:      *DefaultScanningPaceConfig(),
		Spidering:         *DefaultSpideringConfig(),
		Agent:             *DefaultAgentConfig(),
		OAST:              *DefaultOASTConfig(),
		Storage:           *DefaultStorageConfig(),
	}
}

// ExpandPath handles ~ expansion and environment variables
func ExpandPath(path string) string {
	// Expand environment variables
	path = ExpandEnvVars(path)

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[2:])
	}

	return path
}

// ContractPath replaces the user's home directory prefix with ~ — the inverse of ExpandPath.
func ContractPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}

// ExpandEnvVars replaces environment variable references in s.
//
// Supported syntax (follows bash/Docker Compose conventions):
//
//	${VAR}            — value of VAR; empty string if unset
//	${VAR:-default}   — value of VAR if set and non-empty, otherwise "default"
//	$VAR              — same as ${VAR} (no default support)
func ExpandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if name, defaultVal, ok := parseDefault(key); ok {
			if v := os.Getenv(name); v != "" {
				return v
			}
			return defaultVal
		}
		return os.Getenv(key)
	})
}

// parseDefault splits "VAR:-default" into ("VAR", "default", true).
// Returns ("", "", false) if the separator is not present.
func parseDefault(key string) (name, defaultVal string, ok bool) {
	idx := strings.Index(key, ":-")
	if idx < 0 {
		return "", "", false
	}
	return key[:idx], key[idx+2:], true
}

// ProjectConfigDir returns the directory for a project's config files.
// Layout: ~/.vigolium/projects/<uuid>/
func ProjectConfigDir(projectUUID string) string {
	return ExpandPath("~/.vigolium/projects/" + projectUUID)
}

// ActiveProjectFilePath returns the path to the file that records the
// shell-independent active project (used as a fallback when no flag/env var
// is set). Layout: ~/.vigolium/active-project
func ActiveProjectFilePath() string {
	return ExpandPath("~/.vigolium/active-project")
}

// ReadActiveProject returns the persisted active project UUID, or "" if the
// file does not exist or is empty. Read errors other than not-exist surface
// to the caller.
func ReadActiveProject() (string, error) {
	data, err := os.ReadFile(ActiveProjectFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteActiveProject persists the active project UUID to disk so that future
// shells/commands resolve to it without needing VIGOLIUM_PROJECT_UUID.
//
// Atomic (temp file + rename): every command that resolves a project without a
// flag or env pin reads this file, so a concurrent reader must see the old UUID
// or the new one, never an empty or half-written file that silently resolves
// to the default project.
func WriteActiveProject(projectUUID string) error {
	path := ActiveProjectFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create vigolium config dir: %w", err)
	}
	if err := atomicfile.WriteFile(path, 0o600, func(w *bufio.Writer) error {
		_, err := w.WriteString(projectUUID + "\n")
		return err
	}); err != nil {
		return fmt.Errorf("failed to write active project file: %w", err)
	}
	return nil
}

// ProjectConfigPath returns the path to a project's config overlay file.
func ProjectConfigPath(projectUUID string) string {
	return filepath.Join(ProjectConfigDir(projectUUID), "config.yaml")
}

// LoadProjectConfig loads the project-specific config overlay if it exists.
// Returns nil (no error) if the file doesn't exist.
func LoadProjectConfig(projectUUID string) (*ProfileSettings, error) {
	profile, err := LoadProfile(ProjectConfigPath(projectUUID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return profile, nil
}

// LoadSettingsWithProject loads global settings, then overlays project-specific
// config on top (ApplyProjectOverlay). This implements the merge strategy:
// global → project → scanning profile → CLI flags; the profile and CLI layers
// are applied by the caller after this returns.
func LoadSettingsWithProject(configPath string, projectUUID string) (*Settings, error) {
	settings, err := LoadSettings(configPath)
	if err != nil {
		return nil, err
	}
	if err := ApplyProjectOverlay(settings, projectUUID); err != nil {
		return nil, err
	}
	return settings, nil
}

// SaveProjectConfig writes a project config overlay to its config directory.
func SaveProjectConfig(projectUUID string, profile *ProfileSettings) error {
	dir := ProjectConfigDir(projectUUID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create project config directory: %w", err)
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal project config: %w", err)
	}

	path := ProjectConfigPath(projectUUID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write project config: %w", err)
	}
	InvalidateProjectOverlay(projectUUID)

	return nil
}

// ConfigFilePath returns the resolved path to the config file.
// It searches the same locations as LoadSettings but only returns the path.
// If no config file exists, returns the default path.
func ConfigFilePath() string {
	paths := []string{
		ExpandPath("~/.vigolium/vigolium-configs.yaml"),
		"./vigolium-configs.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ExpandPath("~/.vigolium/vigolium-configs.yaml")
}

// SaveSettings writes settings to YAML file
func SaveSettings(path string, settings *Settings) error {
	path = ExpandPath(path)

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Atomic: a crash or a full disk mid-write must not leave a truncated
	// config, which the next load would reject (or, discovered, ignore).
	if err := atomicfile.WriteFile(path, 0o600, func(w *bufio.Writer) error {
		_, err := w.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
