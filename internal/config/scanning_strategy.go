package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/portsweep"
)

// ScanningStrategyConfig holds named scanning strategy presets.
// Each preset controls which scan phases are enabled.
type ScanningStrategyConfig struct {
	DefaultStrategy string                `yaml:"default_strategy"`
	HeuristicsCheck string                `yaml:"heuristics_check"`
	ScanningProfile string                `yaml:"scanning_profile"`
	ProfilesDir     string                `yaml:"profiles_dir"`
	Session         SessionStrategyConfig `yaml:"session"`
	ScanLogs        ScanLogsConfig        `yaml:"scan_logs"`
	HTTP            HTTPConfig            `yaml:"http"`
	PortSweep       PortSweepConfig       `yaml:"port_sweep"`
	Lite            StrategyPhases        `yaml:"lite"`
	Balanced        StrategyPhases        `yaml:"balanced"`
	Deep            StrategyPhases        `yaml:"deep"`
}

// PortSweepConfig controls the alternate-port sweep that runs at --intensity deep
// or under --follow-subdomains. For each original CLI target host it TCP-connects
// the configured ports concurrently, HTTP-confirms the open ones, and feeds any
// confirmed web services back into the scan as additional targets. A honeypot
// guard discards a host whose ports are nearly all open with near-identical
// responses (an all-ports-open tarpit).
type PortSweepConfig struct {
	// Ports is the list of alternate HTTP(S) ports probed per host.
	Ports []int `yaml:"ports"`
	// Concurrency is the max number of ports probed in parallel for one host.
	Concurrency int `yaml:"concurrency"`
	// DialTimeoutMs bounds each TCP connect.
	DialTimeoutMs int `yaml:"dial_timeout_ms"`
	// HTTPTimeoutMs bounds each HTTP confirmation request.
	HTTPTimeoutMs int `yaml:"http_timeout_ms"`
	// HoneypotRatio is the open/probed ratio at/above which a host is honeypot-
	// suspect (combined with a near-identical-response check). 0 disables the gate.
	HoneypotRatio float64 `yaml:"honeypot_ratio"`
}

// DefaultPortSweepConfig returns the built-in port-sweep defaults. The values are
// owned by the portsweep package (its single source of truth) so the config and
// the sweep engine never drift; portsweep.Sweep re-applies these for any field
// left zero, so a partial config block stays usable without a Resolve step.
func DefaultPortSweepConfig() PortSweepConfig {
	return PortSweepConfig{
		Ports:         append([]int(nil), portsweep.DefaultPorts...),
		Concurrency:   portsweep.DefaultConcurrency,
		DialTimeoutMs: portsweep.DefaultDialTimeoutMs,
		HTTPTimeoutMs: portsweep.DefaultHTTPTimeoutMs,
		HoneypotRatio: portsweep.DefaultHoneypotRatio,
	}
}

// SessionStrategyConfig controls how authentication sessions behave during scanning.
type SessionStrategyConfig struct {
	// SessionDir is the directory where session YAML files are stored.
	// Defaults to ~/.vigolium/sessions/. Used to resolve --session-file names
	// that are not absolute paths.
	SessionDir string `yaml:"session_dir"`

	// UseInDiscovery controls whether the primary session's headers are applied
	// during the discovery and spidering phases. When false, these phases run
	// unauthenticated even if a primary session is configured. Default: true.
	UseInDiscovery bool `yaml:"use_in_discovery"`

	// CompareEnabled controls whether compare sessions are activated for
	// cross-session IDOR/BOLA replay during the audit phase. Default: true.
	CompareEnabled bool `yaml:"compare_enabled"`

	// ReauthInterval re-executes login flows at this interval to refresh
	// expiring tokens. Zero or empty means login once at scan start.
	// Accepts Go duration strings (e.g. "15m", "1h").
	ReauthInterval string `yaml:"reauth_interval"`

	// ReauthOnStatus triggers re-authentication when the primary session
	// receives one of these HTTP status codes mid-scan. Common values: [401, 403].
	ReauthOnStatus []int `yaml:"reauth_on_status"`

	// ValidateURL is a relative or absolute URL to GET after login to confirm
	// that extracted credentials are working. The scanner checks for a 2xx
	// response before proceeding. Empty means no validation.
	ValidateURL string `yaml:"validate_url"`
}

// DefaultSessionStrategyConfig returns sensible defaults for session behavior.
func DefaultSessionStrategyConfig() *SessionStrategyConfig {
	return &SessionStrategyConfig{
		SessionDir:     "~/.vigolium/sessions/",
		UseInDiscovery: true,
		CompareEnabled: true,
	}
}

// StrategyPhases defines which phases are enabled for a strategy.
type StrategyPhases struct {
	ExternalHarvesting bool `yaml:"external_harvesting"`
	Discovery          bool `yaml:"discovery"`
	Spidering          bool `yaml:"spidering"`
	KnownIssueScan     bool `yaml:"known_issue_scan"`
	DynamicAssessment  bool `yaml:"dynamic-assessment"`
}

// DefaultScanningStrategyConfig returns default configuration with balanced as default.
func DefaultScanningStrategyConfig() *ScanningStrategyConfig {
	return &ScanningStrategyConfig{
		DefaultStrategy: "balanced",
		HeuristicsCheck: "basic",
		ProfilesDir:     "~/.vigolium/profiles/",
		Session:         *DefaultSessionStrategyConfig(),
		ScanLogs:        *DefaultScanLogsConfig(),
		HTTP:            *DefaultHTTPConfig(),
		PortSweep:       DefaultPortSweepConfig(),
		Lite: StrategyPhases{
			ExternalHarvesting: false,
			Discovery:          false,
			KnownIssueScan:     false,
			DynamicAssessment:  true,
		},
		Balanced: StrategyPhases{
			ExternalHarvesting: false,
			Discovery:          true,
			Spidering:          true,
			KnownIssueScan:     true,
			DynamicAssessment:  true,
		},
		Deep: StrategyPhases{
			ExternalHarvesting: true,
			Discovery:          true,
			Spidering:          true,
			KnownIssueScan:     true,
			DynamicAssessment:  true,
		},
	}
}

// Validate checks that DefaultStrategy refers to a known strategy name.
func (c *ScanningStrategyConfig) Validate() error {
	if c.DefaultStrategy == "" {
		return nil
	}
	if _, ok := c.GetStrategy(c.DefaultStrategy); !ok {
		return fmt.Errorf("unknown default_strategy %q; valid names: %v", c.DefaultStrategy, c.StrategyNames())
	}
	return nil
}

// GetStrategy resolves a strategy name to its phases.
func (c *ScanningStrategyConfig) GetStrategy(name string) (StrategyPhases, bool) {
	switch name {
	case "lite":
		return c.Lite, true
	case "balanced":
		return c.Balanced, true
	case "deep":
		return c.Deep, true
	default:
		return StrategyPhases{}, false
	}
}

// StrategyNames returns a sorted list of known strategy names.
func (c *ScanningStrategyConfig) StrategyNames() []string {
	names := []string{"lite", "balanced", "deep"}
	sort.Strings(names)
	return names
}

// ResolveProfilePath resolves a profile name to a filesystem path.
// If name contains a path separator or starts with ~, it is treated as a path
// and expanded. Otherwise it is resolved as {profiles_dir}/{name}.yaml.
func (c *ScanningStrategyConfig) ResolveProfilePath(name string) string {
	if strings.Contains(name, "/") || strings.Contains(name, string(filepath.Separator)) || strings.HasPrefix(name, "~") {
		return ExpandPath(name)
	}
	dir := ExpandPath(c.ProfilesDir)
	return filepath.Join(dir, name+".yaml")
}

// ListProfiles returns the names (without .yaml extension) of profile files
// found in ProfilesDir. Returns nil and no error if the directory does not exist.
func (c *ScanningStrategyConfig) ListProfiles() ([]string, error) {
	dir := ExpandPath(c.ProfilesDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read profiles directory %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			names = append(names, strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// ProfileDescription reads the first line of a profile YAML and extracts a
// description from a "# description: ..." comment. Returns "" if not found.
func ProfileDescription(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if after, ok := strings.CutPrefix(line, "# description:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}
