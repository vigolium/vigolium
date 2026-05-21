// Package piolium drives the Pi-native piolium audit harness from vigolium.
// It mirrors pkg/audit's role for the audit harness — the parser is shared
// (audit and piolium have an interchangeable on-disk schema), so this
// package contributes only the constants, harness spec, and Pi-install
// detection. The actual subprocess and sync logic live in the generic
// AuditAgenticScanner in pkg/agent.
package piolium

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

const (
	// Binary is the Pi CLI name resolved on PATH.
	Binary = "pi"

	// HarnessName is the canonical name of the piolium HarnessSpec. Match
	// against this rather than calling DefaultHarness().Name when branching
	// on harness identity.
	HarnessName = "piolium"

	// DBAgentName is the agent_name column tag for piolium audit rows.
	DBAgentName = "piolium"

	// SourceFolder is the directory piolium writes to under the audited
	// repo root during a run.
	SourceFolder = "piolium"

	// SessionSubdir is where vigolium syncs piolium output under the
	// agent session directory.
	SessionSubdir = "piolium-audit"

	// EnvPrefix is the env-var namespace piolium phase agents read
	// (e.g. PIOLIUM_REPOSITORY, PIOLIUM_GIT_AVAILABLE,
	// PIOLIUM_SESSION_UUID). Must match the prefix piolium itself
	// expects in its agent prompts — see piolium's agents/*.md.
	EnvPrefix = "PIOLIUM_"

	// SlashCommandPrefix is prefixed to the mode to form the Pi slash
	// command (e.g. "balanced" → "/piolium-balanced").
	SlashCommandPrefix = "/piolium-"

	// PackageHint is a substring that identifies a piolium install in the
	// Pi settings.json packages array. Matches local-path installs (which
	// end in "/piolium") and git installs (containing "vigolium/piolium").
	PackageHint = "piolium"

	// HomeEnvVar names the env var that points to a self-contained
	// piolium install root (canonical layout: /opt/piolium with
	// /opt/piolium/agent as PI_CODING_AGENT_DIR and /opt/piolium/package
	// as the extension source). When set, vigolium prefers this layout
	// over the per-user ~/.pi/ install for both detection and runtime
	// dispatch. When unset, detection falls back to ~/.pi/agent/.
	HomeEnvVar = "PIOLIUM_HOME"

	// PiAgentDirEnvVar is the Pi runtime env var that overrides Pi's
	// default agent-config search path (~/.pi/agent). vigolium sets it
	// to AgentDir() when Home() is non-empty so `pi` resolves piolium's
	// settings/skills/agents from the system install.
	PiAgentDirEnvVar = "PI_CODING_AGENT_DIR"

	// UserHomeAutoprobeEnvVar opts an operator into auto-probing
	// $HOME/.piolium — piolium's own standalone-launcher default — as
	// a third Home() fallback after $PIOLIUM_HOME and /opt/piolium.
	// When set to a truthy value ("1", "true", "yes", "on"), a
	// fully-formed install at $HOME/.piolium/agent is treated like a
	// system install: detection reads its settings.json and runtime
	// dispatch injects PI_CODING_AGENT_DIR=$HOME/.piolium/agent.
	//
	// Off by default — see the note on defaultHomeProbe. The opt-in
	// exists so operators who installed piolium standalone (the
	// common case on a workstation) don't have to remember the full
	// PIOLIUM_HOME path; a single boolean flips on the canonical
	// per-user layout.
	UserHomeAutoprobeEnvVar = "VIGOLIUM_PIOLIUM_USERHOME"

	// userHomePioliumSubdir is the directory name piolium's standalone
	// launcher (bin/piolium.mjs) writes to under $HOME. Joined with
	// the resolved $HOME at probe time.
	userHomePioliumSubdir = ".piolium"
)

// ValidModes lists the audit-producing piolium slash commands vigolium
// will dispatch via `vigolium agent piolium --mode`. Operator-only
// commands (`/piolium-status`, `/piolium-smoke`, `/piolium-export`,
// `/piolium-learn`) stay at the raw `pi` layer — they don't produce
// findings vigolium ingests, so routing them through the audit
// pipeline (session sync, database tagging, dedup) just adds noise.
//
// Differs from audit's accepted set: adds `longshot`, omits `mock`.
var ValidModes = map[string]bool{
	"lite":     true,
	"balanced": true,
	"deep":     true,
	"revisit":  true,
	"confirm":  true,
	"merge":    true,
	"diff":     true,
	"longshot": true,
}

func IsValidMode(mode string) bool {
	return ValidModes[mode]
}

// PlmFlags describes piolium's `--plm-*` session-flag passthroughs. The CLI
// (vigolium agent audit) and the server endpoint (POST /api/agent/run/audit)
// both populate this and call Args() so they emit identical flag lists.
//
// All fields are optional; zero values are dropped from the rendered argv so
// piolium's own defaults stay authoritative when a knob isn't set.
type PlmFlags struct {
	ScanLimit       int    // --plm-scan-limit
	ScanSince       string // --plm-scan-since
	PhaseRetries    int    // --plm-phase-retries
	CommandRetries  int    // --plm-command-retries
	LongshotLimit   int    // --plm-longshot-limit
	LongshotTimeout int    // --plm-longshot-timeout
	LongshotLangs   string // --plm-longshot-langs
}

// Args renders the populated knobs into a flag-pair argv slice.
func (p PlmFlags) Args() []string {
	var out []string
	if p.ScanLimit > 0 {
		out = append(out, "--plm-scan-limit", strconv.Itoa(p.ScanLimit))
	}
	if p.ScanSince != "" {
		out = append(out, "--plm-scan-since", p.ScanSince)
	}
	if p.PhaseRetries > 0 {
		out = append(out, "--plm-phase-retries", strconv.Itoa(p.PhaseRetries))
	}
	if p.CommandRetries > 0 {
		out = append(out, "--plm-command-retries", strconv.Itoa(p.CommandRetries))
	}
	if p.LongshotLimit > 0 {
		out = append(out, "--plm-longshot-limit", strconv.Itoa(p.LongshotLimit))
	}
	if p.LongshotTimeout > 0 {
		out = append(out, "--plm-longshot-timeout", strconv.Itoa(p.LongshotTimeout))
	}
	if p.LongshotLangs != "" {
		out = append(out, "--plm-longshot-langs", p.LongshotLangs)
	}
	return out
}

func DefaultHarness() agenttypes.HarnessSpec {
	return agenttypes.HarnessSpec{
		Name:            HarnessName,
		SourceFolder:    SourceFolder,
		SessionSubdir:   SessionSubdir,
		EnvPrefix:       EnvPrefix,
		DBMode:          HarnessName,
		DBAgentName:     DBAgentName,
		DBInputType:     HarnessName,
		FindingIDPrefix: HarnessName,
		FindingTag:      HarnessName,
	}
}

// defaultHomeProbe is the canonical filesystem path Home() probes when
// $PIOLIUM_HOME is unset. Deliberately scoped to the system-wide
// /opt/piolium layout. The per-user ~/.piolium/ tree (piolium's own
// standalone-launcher default) is auto-probed only when the operator
// explicitly opts in via $VIGOLIUM_PIOLIUM_USERHOME, since vigolium
// audit state and standalone-piolium state otherwise share the same
// session/auth files.
//
// Exposed as a var so tests can redirect the probe to a temp dir.
// Production code MUST NOT write to it; tests MUST restore it via
// t.Cleanup.
var defaultHomeProbe = "/opt/piolium"

// Home returns the active piolium install root, in this order:
//  1. $PIOLIUM_HOME (cleaned) when set and non-blank.
//  2. /opt/piolium when its agent/ subdir exists (canonical system
//     install — auto-detected so operators don't have to remember
//     to export the env var).
//  3. $HOME/.piolium when its agent/ subdir exists AND the opt-in
//     env var $VIGOLIUM_PIOLIUM_USERHOME is truthy. Off by default —
//     see the note on defaultHomeProbe for why ~/.piolium/ requires
//     explicit consent.
//  4. "" — the signal for callers to fall back to the per-user
//     ~/.pi/ layout.
//
// The agent/ existence check on steps 2 and 3 is what keeps a vanilla
// machine (no /opt/piolium and no ~/.piolium/) from short-circuiting
// into a broken-install path; ~/.pi/ stays the answer when neither
// candidate is present.
func Home() string {
	if h := strings.TrimSpace(os.Getenv(HomeEnvVar)); h != "" {
		return filepath.Clean(h)
	}
	if info, err := os.Stat(filepath.Join(defaultHomeProbe, "agent")); err == nil && info.IsDir() {
		return defaultHomeProbe
	}
	if userHomeAutoprobeEnabled() {
		if dir := userHomePioliumDir(); dir != "" {
			if info, err := os.Stat(filepath.Join(dir, "agent")); err == nil && info.IsDir() {
				return dir
			}
		}
	}
	return ""
}

// userHomeAutoprobeEnabled reports whether $VIGOLIUM_PIOLIUM_USERHOME
// is set to a truthy value. Treats "1", "true", "yes", and "on"
// (case-insensitive) as enable; any other value — including unset —
// keeps the prior default-off behavior.
func userHomeAutoprobeEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(UserHomeAutoprobeEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// userHomePioliumDir returns $HOME/.piolium when $HOME is resolvable,
// "" otherwise. Exposed as a separate helper so tests can isolate the
// resolution and so future callers (install verification, doctor
// output) can render the path without re-running os.UserHomeDir.
func userHomePioliumDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, userHomePioliumSubdir)
}

// AgentDir returns the Pi agent directory for the active install:
// $PIOLIUM_HOME/agent when Home() is set, or "" to mean "use Pi's
// default (~/.pi/agent)". This is the value vigolium injects as
// PI_CODING_AGENT_DIR when launching pi.
func AgentDir() string {
	h := Home()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "agent")
}

// PackageDir returns the piolium extension package directory under
// $PIOLIUM_HOME, or "" when Home() is unset. Currently informational —
// detection only consults AgentDir() — but exposed so future helpers
// (install verification, version probes) have a single source of truth.
func PackageDir() string {
	h := Home()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "package")
}

// RuntimeEnv returns the env-var lines vigolium must inject when
// launching `pi` so a system piolium install (rooted at $PIOLIUM_HOME)
// is used instead of the per-user ~/.pi/. Returns nil when Home() is
// unset — callers should append unconditionally; nil leaves the
// subprocess env untouched.
//
// Today this is just PI_CODING_AGENT_DIR. Centralized so future
// additions (extra agent search paths, package overrides) don't need
// changes in pkg/agent.
func RuntimeEnv() []string {
	dir := AgentDir()
	if dir == "" {
		return nil
	}
	return []string{PiAgentDirEnvVar + "=" + dir}
}

// piSettingsFile returns the path to the Pi settings.json that
// EnsurePiInstalled inspects. With $PIOLIUM_HOME set this points at
// the system install's agent dir; otherwise it falls back to the
// per-user ~/.pi/agent/settings.json.
func piSettingsFile() string {
	if dir := AgentDir(); dir != "" {
		return filepath.Join(dir, "settings.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".pi", "agent", "settings.json")
}

type piSettings struct {
	Packages []string `json:"packages"`
}

// pioliumHelpProbeTimeout caps `pi -h` since piolium-loaded pi prints
// help locally without network calls — anything slower means pi is wedged.
// Generous bound so a heavily-loaded host (parallel CI test runs spawning
// many subprocesses at once) doesn't trip the cap before pi's process
// actually executes.
const pioliumHelpProbeTimeout = 30 * time.Second

// piolium injects a block of `--plm-*` flags into pi's help output when
// it's loaded as an extension. Their presence is the cheapest behavioral
// signal that pi will recognize `/piolium-*` slash commands.
const pioliumHelpFlagMarker = "--plm-"

// IsAvailable returns true when all three checks pass:
//  1. The `pi` CLI is on PATH.
//  2. piolium is registered in ~/.pi/agent/settings.json.
//  3. `pi -h` emits the `--plm-*` flag block, proving the extension code
//     actually loaded into pi.
//
// (3) catches the false-positive cases (2) misses on its own — a stale
// local-path entry pointing at a moved install, a half-uninstalled
// extension, or a settings.json that lists "piolium" by name only. Used
// as a fast predicate for the autopilot / swarm audit-harness picker
// and the audit dispatcher's skip-and-warn logic; does not hit the network.
func IsAvailable() bool {
	return Diagnose() == nil
}

// Diagnose runs the same three checks as IsAvailable but returns the
// first failure as a descriptive error. Used by callers (the audit
// dispatcher's skip-and-warn) that need a human-readable reason
// rather than a bare bool. Returns nil when everything's wired up.
func Diagnose() error {
	if _, err := exec.LookPath(Binary); err != nil {
		return fmt.Errorf("pi CLI not found in PATH (install with `vigolium doctor --fix --only pi`, or: bun add -g @earendil-works/pi-coding-agent)")
	}
	if err := EnsurePiInstalled(); err != nil {
		return err
	}
	return VerifyPiLoadedPiolium()
}

// VerifyPiLoadedPiolium runs `pi -h` and confirms piolium's `--plm-*`
// flags appear in the output. Returns a descriptive error on miss so
// callers can surface why detection failed instead of a bare "not
// available". Bounded by pioliumHelpProbeTimeout — pi help is local
// and instant when healthy.
//
// When $PIOLIUM_HOME is set the probe runs with PI_CODING_AGENT_DIR
// pinned to AgentDir() so it inspects the system piolium install
// (otherwise pi would consult ~/.pi/agent/, which may have a
// different — or no — piolium registered).
func VerifyPiLoadedPiolium() error {
	ctx, cancel := context.WithTimeout(context.Background(), pioliumHelpProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, Binary, "-h")
	if dir := AgentDir(); dir != "" {
		cmd.Env = append(os.Environ(), PiAgentDirEnvVar+"="+dir)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pi -h failed (is pi healthy?): %w", err)
	}
	if !strings.Contains(string(out), pioliumHelpFlagMarker) {
		return fmt.Errorf("pi -h does not list piolium %s* flags — extension not loaded by pi (try: pi list, then: pi install npm:@vigolium/piolium)", pioliumHelpFlagMarker)
	}
	return nil
}

// EnsurePiInstalled verifies that piolium is registered as a Pi package.
// A package entry matches when either:
//
//   - its lowercased path contains PackageHint (catches local-path installs
//     ending in "/piolium" and git URLs like "vigolium/piolium"), OR
//   - Home() is non-empty AND the entry (resolved relative to the
//     settings.json directory) points at $Home()/package (the canonical
//     install layout — settings.json under $Home()/agent registers
//     "../package", which doesn't contain the "piolium" substring but
//     IS the install we just resolved via $PIOLIUM_HOME or auto-probe).
//
// We don't auto-install — `pi install` writes to user settings and pulls
// node_modules, well outside what a subcommand should do silently.
func EnsurePiInstalled() error {
	path := piSettingsFile()
	if path == "" {
		return fmt.Errorf("could not resolve $HOME to locate Pi settings (set %s to a piolium install root, e.g. /opt/piolium)", HomeEnvVar)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if home := Home(); home != "" {
				return fmt.Errorf("piolium install at %s but %s is missing — system install looks broken or unfinished (%s)", home, path, homeOriginNote())
			}
			return fmt.Errorf("pi is not configured (no %s) — install pi and piolium first:\n  pi install npm:@vigolium/piolium", path)
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	var s piSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	settingsDir := filepath.Dir(path)
	wantPackageDir := PackageDir() // "" when Home() is unset
	for _, pkg := range s.Packages {
		if strings.Contains(strings.ToLower(pkg), PackageHint) {
			return nil
		}
		if wantPackageDir != "" && resolvesToPackageDir(pkg, settingsDir, wantPackageDir) {
			return nil
		}
	}
	if home := Home(); home != "" {
		return fmt.Errorf("piolium is not registered in %s (install root %s; %s) — system install is missing the package entry", path, home, homeOriginNote())
	}
	if hint := userHomeOptInHint(); hint != "" {
		return fmt.Errorf("piolium is not registered in %s — %s", path, hint)
	}
	return fmt.Errorf("piolium is not registered in %s — install it with:\n  pi install npm:@vigolium/piolium", path)
}

// userHomeOptInHint returns a one-line install/opt-in hint when a
// fully-formed piolium standalone install exists at $HOME/.piolium/
// but the operator hasn't set $VIGOLIUM_PIOLIUM_USERHOME. Returned as
// a hint string (not a separate error) so it composes into the
// existing "not registered" error message instead of replacing it.
// "" when there's nothing to suggest (no user-home install present).
func userHomeOptInHint() string {
	dir := userHomePioliumDir()
	if dir == "" {
		return ""
	}
	if info, err := os.Stat(filepath.Join(dir, "agent")); err != nil || !info.IsDir() {
		return ""
	}
	return fmt.Sprintf("found a standalone piolium install at %s; opt in with `export %s=1` to use it, or install into pi with:\n  pi install npm:@vigolium/piolium",
		dir, UserHomeAutoprobeEnvVar)
}

// resolvesToPackageDir reports whether a Pi packages[] entry refers to
// the canonical piolium package directory at $Home()/package. Pi accepts
// absolute paths, settings-relative paths ("../package"), and remote
// strings (git: / @scoped). Only the path-shaped entries can match, so
// remote-looking strings short-circuit to false.
func resolvesToPackageDir(entry, settingsDir, wantPackageDir string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	// git URLs, npm specifiers, and other remote forms aren't filesystem
	// paths — skip them so we don't accidentally call filepath.Abs on
	// "git:git@github.com:..." and produce a surprising hit.
	if strings.HasPrefix(entry, "git:") || strings.HasPrefix(entry, "git+") ||
		strings.HasPrefix(entry, "@") || strings.Contains(entry, "://") {
		return false
	}
	resolved := entry
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(settingsDir, resolved)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return false
	}
	wantAbs, err := filepath.Abs(wantPackageDir)
	if err != nil {
		return false
	}
	return filepath.Clean(abs) == filepath.Clean(wantAbs)
}

// homeOriginNote describes how Home() resolved its current value, so
// error messages can tell an operator whether to inspect their shell
// env vs the canonical /opt/piolium tree vs the opt-in user-home tree.
func homeOriginNote() string {
	if strings.TrimSpace(os.Getenv(HomeEnvVar)) != "" {
		return "via $" + HomeEnvVar
	}
	if userHomeAutoprobeEnabled() {
		if dir := userHomePioliumDir(); dir != "" && Home() == dir {
			return "auto-detected from " + dir + " (via $" + UserHomeAutoprobeEnvVar + ")"
		}
	}
	return "auto-detected from " + defaultHomeProbe
}
