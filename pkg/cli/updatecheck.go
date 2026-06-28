package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/mod/semver"
)

// npmDistTagsURL is the lightweight npm registry endpoint that returns just the
// package's dist-tags (e.g. {"latest":"0.1.42-beta",...}) — far cheaper and more
// stable than scraping the npmjs.com HTML page. A var (not const) so tests can
// point it at a local httptest server.
var npmDistTagsURL = "https://registry.npmjs.org/-/package/@vigolium/vigolium/dist-tags"

const (
	// updateCheckNetTimeout bounds the npm fetch so a slow/unreachable registry
	// never delays the CLI for more than a blink.
	updateCheckNetTimeout = 1500 * time.Millisecond

	// updateCheckInterval is how often the npm registry is actually contacted.
	// Between checks the cached latest version drives the notice for free.
	updateCheckInterval = 24 * time.Hour

	// updateCheckCachePath stores the last network check timestamp + latest
	// version so the network is hit at most once per updateCheckInterval.
	updateCheckCachePath = "~/.vigolium/update-check.json"

	// envDisableUpdateCheck turns the whole feature off (notice and auto-update).
	envDisableUpdateCheck = "VIGOLIUM_DISABLE_UPDATE_CHECK"
	// envAutoUpdate makes the CLI silently update and re-exec when behind.
	envAutoUpdate = "VIGOLIUM_AUTO_UPDATE"
	// envAutoUpdateReexeced is an internal sentinel set on the re-exec'd child so
	// a failed/partial install can't trigger an endless update→exec loop.
	envAutoUpdateReexeced = "VIGOLIUM_AUTO_UPDATE_REEXECED"
)

// updateCacheData is the on-disk shape of update-check.json.
type updateCacheData struct {
	CheckedAt     int64  `json:"checked_at"`
	LatestVersion string `json:"latest_version"`
}

// pendingFetch is an in-flight background version lookup whose result is
// collected after the command finishes (see scheduleUpdateNotice / flushUpdateNotice).
type pendingFetch struct {
	ch      chan string // receives the latest version (or "" on failure)
	current string      // the running version to compare it against
}

// Notice-flow state, populated during PersistentPreRunE and flushed at the end
// of Execute() so the "new version available" line is the last thing on screen
// rather than scrolling away during a long scan.
var (
	pendingUpdateNotice string
	updateFetch         *pendingFetch
)

// maybeCheckForUpdate is the single entry point wired into the root command's
// PersistentPreRunE. It either schedules a (non-blocking) update notice or, when
// VIGOLIUM_AUTO_UPDATE is set, synchronously updates and re-execs the new binary.
func maybeCheckForUpdate(cmd *cobra.Command) {
	current := currentSemver()
	if updateCheckHardDisabled(cmd, current) {
		return
	}

	// Auto-update is an explicit opt-in: it runs regardless of TTY so it works in
	// automation, but stays out of --json runs (a multi-minute install would be a
	// nasty surprise for a programmatic caller).
	if autoUpdateEnabled() && !globalJSON {
		runAutoUpdate(current)
		return
	}

	// Notice flow — keep scripted/piped/CI output clean.
	if globalJSON || globalCIOutput || !terminal.IsTerminal() {
		return
	}
	scheduleUpdateNotice(current)
}

// updateCheckHardDisabled reports conditions that switch off both the notice and
// the auto-update paths entirely. current is the running binary's version.
func updateCheckHardDisabled(cmd *cobra.Command, current string) bool {
	if utils.EnvTruthy(envDisableUpdateCheck) {
		return true
	}
	if utils.EnvTruthy(envAutoUpdateReexeced) {
		// We just re-exec'd a freshly installed binary; don't check again.
		return true
	}
	switch cmd.Name() {
	case "version", "update", "init":
		return true
	}
	// A non-release build (Version="dev" or a bare git hash) has no comparable
	// semver, so there is nothing meaningful to compare against npm.
	return !semver.IsValid(current)
}

// scheduleUpdateNotice resolves the latest version (from cache when fresh, else a
// background fetch) and arranges for a notice to print at the end of the run.
func scheduleUpdateNotice(current string) {
	cache, ok := readUpdateCache()
	if ok && !cacheStale(cache) {
		if cache.LatestVersion != "" && isVersionBehind(current, cache.LatestVersion) {
			pendingUpdateNotice = formatUpdateNotice(current, normalizedSemver(cache.LatestVersion))
		}
		return
	}

	// Cache is stale or missing: fetch in the background so the command is never
	// blocked. The result is collected in flushUpdateNotice() — which runs after
	// the command — so the only ever wait happens once per day, after output.
	pf := &pendingFetch{ch: make(chan string, 1), current: current}
	updateFetch = pf
	go func() {
		pf.ch <- resolveLatestVersion(cache, ok)
	}()
}

// flushUpdateNotice resolves any in-flight fetch (bounded wait, after the command
// has finished) and prints the pending notice. Called from Execute().
func flushUpdateNotice() {
	if updateFetch != nil {
		select {
		case latest := <-updateFetch.ch:
			if latest != "" && isVersionBehind(updateFetch.current, latest) {
				pendingUpdateNotice = formatUpdateNotice(updateFetch.current, normalizedSemver(latest))
			}
		case <-time.After(updateCheckNetTimeout + 250*time.Millisecond):
			// Still fetching — skip the notice this run; the cache will be warm
			// for the next invocation.
		}
	}
	if pendingUpdateNotice == "" {
		return
	}
	fmt.Fprint(os.Stderr, "\n"+pendingUpdateNotice)
}

// runAutoUpdate updates the binary silently and re-execs it to continue the
// current command. It is a no-op when already on (or ahead of) the latest.
func runAutoUpdate(current string) {
	latest := resolveLatestVersion(readUpdateCache())
	if latest == "" || !isVersionBehind(current, latest) {
		return
	}

	fmt.Fprintf(os.Stderr, "%s %s %s %s %s\n",
		terminal.WarningSymbol(),
		terminal.White("Auto-updating vigolium"),
		terminal.Yellow(current),
		terminal.Gray("→"),
		terminal.BoldCyan(normalizedSemver(latest)),
	)

	if err := updateBinarySilent(); err != nil {
		zap.L().Warn("auto-update failed; continuing with current binary", zap.Error(err))
		fmt.Fprintf(os.Stderr, "%s %s\n",
			terminal.WarningSymbol(),
			terminal.Yellow("auto-update failed; continuing with the current version"))
		return
	}

	// Warm the cache so the re-exec'd process doesn't immediately re-check, then
	// hand off to the freshly installed binary with the original arguments.
	writeUpdateCache(latest)
	reexecAfterUpdate()
}

// reexecAfterUpdate replaces the current process with the freshly installed
// binary (the install.sh target), preserving the original arguments. It only
// returns if the exec fails, in which case the caller keeps running the old
// process for this invocation.
func reexecAfterUpdate() {
	target := config.ExpandPath(installedBinaryPath)
	if _, err := os.Stat(target); err != nil {
		// Installer target missing (non-standard install location); fall back to
		// the current executable. The loop guard below still prevents a cycle.
		if exe, e := os.Executable(); e == nil {
			target = exe
		} else {
			target = os.Args[0]
		}
	}

	env := append(os.Environ(), envAutoUpdateReexeced+"=1")
	if err := execReplace(target, os.Args, env); err != nil {
		zap.L().Warn("re-exec after auto-update failed; continuing with current process", zap.Error(err))
	}
}

// updateBinarySilent runs the same installer as `vigolium update` but captures
// its output instead of streaming it, so an auto-update stays quiet on the
// console (the full output is still available at debug level).
func updateBinarySilent() error {
	ctx, cancel := context.WithTimeout(context.Background(), updateStepTimeout)
	defer cancel()

	var buf bytes.Buffer
	err := runInstallScript(ctx, &buf)
	level := "auto-update installer completed"
	if err != nil {
		level = "auto-update installer output"
	}
	zap.L().Debug(level, zap.String("output", buf.String()))
	return err
}

// resolveLatestVersion returns the latest npm version given an already-read
// cache: the cached value when fresh, otherwise a fresh network fetch (falling
// back to the stale value on failure). Shared by the synchronous auto-update
// path and the background notice fetch.
func resolveLatestVersion(cache updateCacheData, cacheOK bool) string {
	if cacheOK && !cacheStale(cache) {
		return cache.LatestVersion
	}
	latest, err := fetchLatestNpmVersion()
	if err != nil || latest == "" {
		if cacheOK {
			return cache.LatestVersion // fall back to the stale value
		}
		return ""
	}
	writeUpdateCache(latest)
	return latest
}

// fetchLatestNpmVersion reads the `latest` dist-tag from the npm registry.
func fetchLatestNpmVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), updateCheckNetTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, npmDistTagsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vigolium-update-check")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	var tags struct {
		Latest string `json:"latest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", err
	}
	return strings.TrimSpace(tags.Latest), nil
}

// readUpdateCache loads update-check.json. The bool is false when the cache is
// absent or unreadable.
func readUpdateCache() (updateCacheData, bool) {
	data, err := os.ReadFile(config.ExpandPath(updateCheckCachePath))
	if err != nil {
		return updateCacheData{}, false
	}
	var c updateCacheData
	if err := json.Unmarshal(data, &c); err != nil {
		return updateCacheData{}, false
	}
	return c, true
}

// writeUpdateCache atomically persists the latest version + the current time.
func writeUpdateCache(latest string) {
	path := config.ExpandPath(updateCheckCachePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	payload, err := json.Marshal(updateCacheData{
		CheckedAt:     time.Now().Unix(),
		LatestVersion: latest,
	})
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// cacheStale reports whether the cached check is older than updateCheckInterval.
func cacheStale(c updateCacheData) bool {
	return time.Now().Unix()-c.CheckedAt > int64(updateCheckInterval.Seconds())
}

// formatUpdateNotice renders the single-line "new version available" message.
func formatUpdateNotice(current, latest string) string {
	return fmt.Sprintf("%s %s %s %s %s %s %s %s\n",
		terminal.Yellow(terminal.SymbolLightning),
		terminal.White("A new vigolium version is available:"),
		terminal.Yellow(current),
		terminal.Gray("→"),
		terminal.BoldCyan(latest),
		terminal.White("— run"),
		terminal.Green("`vigolium update`"),
		terminal.White("to upgrade."),
	)
}

// currentSemver returns the running binary's version normalized for semver
// comparison (leading "v" guaranteed).
func currentSemver() string {
	return normalizedSemver(getVersion())
}

// normalizedSemver ensures a leading "v" so the value can be fed to
// golang.org/x/mod/semver (npm reports "0.1.42-beta"; we compare "v0.1.42-beta").
func normalizedSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// isVersionBehind reports whether current is strictly older than latest. Invalid
// versions (e.g. a dev build) are treated as "not behind" so they never nag.
func isVersionBehind(current, latest string) bool {
	c := normalizedSemver(current)
	l := normalizedSemver(latest)
	if !semver.IsValid(c) || !semver.IsValid(l) {
		return false
	}
	return semver.Compare(l, c) > 0
}

func autoUpdateEnabled() bool { return utils.EnvTruthy(envAutoUpdate) }
