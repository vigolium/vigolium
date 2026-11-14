// Package cftbrowser downloads and caches Chrome for Testing binaries from
// Google's official API (https://googlechromelabs.github.io/chrome-for-testing/).
package cftbrowser

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/paths"
	"go.uber.org/zap"
)

// apiURL is the Chrome for Testing version index. A variable so tests can point
// EnsureBrowser at a local server; nothing in production reassigns it.
var apiURL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"

// Progress states, in the order a ProgressFunc sees them: one started, any
// number of downloading, then exactly one finished or failed.
const (
	StateStarted     = "started"
	StateDownloading = "downloading"
	StateFinished    = "finished"
	StateFailed      = "failed"
)

// ProgressEvent is one step of an EnsureBrowser call, for callers that render
// provisioning themselves (the scan runner turns it into an ETA line and a
// scan.setup event).
type ProgressEvent struct {
	State   string // StateStarted, StateDownloading, StateFinished or StateFailed
	Version string // CfT version, once the version index answered
	Bytes   int64  // archive bytes downloaded so far (finished: the archive size; 0 on a cache hit)
	Total   int64  // archive size from Content-Length, 0 when unknown
	Err     error  // set on StateFailed
}

// ProgressFunc receives EnsureBrowser's progress. Called on the calling
// goroutine; downloading events arrive at most once per 5% of the archive.
type ProgressFunc func(ProgressEvent)

// progressOut is where provisioning progress is written. It is STDERR, not
// stdout.
//
// That is a contract, not a preference. This package is reached two ways:
// interactively from `vigolium doctor`, and silently as the browser fallback
// during a scan — including a scan run with `--events ndjson`, where stdout
// carries one JSON object per line and belongs to the machine reader alone.
// Printing a download progress bar there corrupts the stream on the first byte,
// and a first-run scan is exactly when that happens. Stderr reaches an
// interactive terminal identically, so nothing is lost at the human end.
//
// A variable rather than os.Stderr inline so tests can capture it. Nothing in
// production reassigns it, so it needs no guard; if a caller ever wants
// provisioning redirected or silenced, thread an io.Writer through
// EnsureBrowser rather than reintroducing a settable global.
var progressOut io.Writer = os.Stderr

// progressf writes one formatted progress message.
func progressf(format string, args ...any) {
	_, _ = fmt.Fprintf(progressOut, format, args...)
}

// platformInfo maps GOOS_GOARCH to CfT platform key and binary relative path.
type platformInfo struct {
	Key     string // CfT platform key, e.g. "linux64"
	BinPath string // relative path to chrome binary inside the extracted zip
}

var platforms = map[string]platformInfo{
	"linux_amd64":   {Key: "linux64", BinPath: "chrome-linux64/chrome"},
	"darwin_arm64":  {Key: "mac-arm64", BinPath: "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"},
	"darwin_amd64":  {Key: "mac-x64", BinPath: "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"},
	"windows_amd64": {Key: "win64", BinPath: "chrome-win64/chrome.exe"},
	"windows_386":   {Key: "win32", BinPath: "chrome-win32/chrome.exe"},
}

// IsSupported returns true if the current OS/arch has Chrome for Testing builds.
func IsSupported() bool {
	_, ok := platforms[runtime.GOOS+"_"+runtime.GOARCH]
	return ok
}

// PlatformKey returns the CfT platform string for the current OS/arch.
func PlatformKey() (string, error) {
	p, ok := platforms[runtime.GOOS+"_"+runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("chrome for testing is not available for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return p.Key, nil
}

// cacheRoot returns ~/.cache/vigolium/.
func cacheRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home dir: %w", err)
	}
	return filepath.Join(home, ".cache", "vigolium"), nil
}

// versionDir returns the cache directory for a specific CfT version.
func versionDir(version string) (string, error) {
	root, err := cacheRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "chrome-for-testing-"+version), nil
}

// binPathForVersion returns the full path to the chrome binary for a cached version.
func binPathForVersion(version string) (string, error) {
	dir, err := versionDir(version)
	if err != nil {
		return "", err
	}
	p, ok := platforms[runtime.GOOS+"_"+runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return filepath.Join(dir, filepath.FromSlash(p.BinPath)), nil
}

// FindCachedBrowser looks for an already-downloaded Chrome for Testing binary
// without making any network requests. Returns the binary path or an error.
func FindCachedBrowser() (string, error) {
	if !IsSupported() {
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	root, err := cacheRoot()
	if err != nil {
		return "", err
	}

	matches, err := filepath.Glob(filepath.Join(root, "chrome-for-testing-*"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no cached Chrome for Testing found")
	}

	// Sort descending so newest version is first.
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))

	p := platforms[runtime.GOOS+"_"+runtime.GOARCH]
	for _, dir := range matches {
		marker := filepath.Join(dir, ".extracted")
		if _, err := os.Stat(marker); err != nil {
			continue
		}
		bin := filepath.Join(dir, filepath.FromSlash(p.BinPath))
		if _, err := os.Stat(bin); err == nil {
			return bin, nil
		}
	}

	return "", fmt.Errorf("no valid cached Chrome for Testing binary found")
}

// --- API response types ---

type apiResponse struct {
	Channels map[string]channelInfo `json:"channels"`
}

type channelInfo struct {
	Channel   string          `json:"channel"`
	Version   string          `json:"version"`
	Downloads downloadSection `json:"downloads"`
}

type downloadSection struct {
	Chrome []platformDownload `json:"chrome"`
}

type platformDownload struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
}

// fetchDownloadInfo fetches the CfT API and returns (version, downloadURL) for
// the Stable channel on the current platform.
func fetchDownloadInfo(ctx context.Context) (version, downloadURL string, err error) {
	platKey, err := PlatformKey()
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch CfT API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("CfT API returned status %d", resp.StatusCode)
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", "", fmt.Errorf("failed to parse CfT API response: %w", err)
	}

	stable, ok := apiResp.Channels["Stable"]
	if !ok {
		return "", "", fmt.Errorf("no Stable channel in CfT API response")
	}

	for _, dl := range stable.Downloads.Chrome {
		if dl.Platform == platKey {
			return stable.Version, dl.URL, nil
		}
	}

	return "", "", fmt.Errorf("no download URL for platform %q in CfT Stable channel", platKey)
}

// EnsureBrowser downloads and caches Chrome for Testing if not already present.
// Returns the path to the chrome binary.
//
// onProgress may be nil. Without it, progress is printed as text to
// progressOut (stderr), never stdout — the `vigolium doctor --fix` rendering.
// With it, the text is suppressed and the caller gets one started event, then
// downloading events, then exactly one finished or failed event; the caller
// owns the rendering.
func EnsureBrowser(ctx context.Context, onProgress ProgressFunc) (string, error) {
	if !IsSupported() {
		return "", fmt.Errorf(
			"chrome for Testing is not available for %s/%s — install Chromium manually (e.g. apt install chromium)",
			runtime.GOOS, runtime.GOARCH,
		)
	}
	// A stateless (-S) run may use a cached browser but downloads nothing.
	if paths.Stateless() {
		if cached, err := FindCachedBrowser(); err == nil {
			return cached, nil
		}
		return "", fmt.Errorf("no Chrome/Chromium available and a stateless (-S) scan does not download one: " +
			"install with `vigolium doctor --fix --only chrome`, set spidering.browser_path, or skip the crawl with --skip spidering")
	}
	p := provisioner{onProgress: onProgress}
	p.emit(ProgressEvent{State: StateStarted})
	binPath, err := p.ensure(ctx)
	if err != nil {
		p.emit(ProgressEvent{State: StateFailed, Version: p.version, Bytes: p.bytes, Err: err})
		return "", err
	}
	p.emit(ProgressEvent{State: StateFinished, Version: p.version, Bytes: p.bytes})
	return binPath, nil
}

// provisioner carries one EnsureBrowser call's progress sink and what it has
// learned so far, so the terminal event can report it.
type provisioner struct {
	onProgress ProgressFunc
	version    string
	bytes      int64
}

func (p *provisioner) emit(ev ProgressEvent) {
	if p.onProgress != nil {
		p.onProgress(ev)
	}
}

// say prints a text progress fragment, only when no ProgressFunc renders it.
func (p *provisioner) say(format string, args ...any) {
	if p.onProgress == nil {
		progressf(format, args...)
	}
}

func (p *provisioner) ensure(ctx context.Context) (string, error) {
	p.say("  Fetching Chrome for Testing version info... ")
	version, downloadURL, err := fetchDownloadInfo(ctx)
	if err != nil {
		p.say("failed\n")
		return "", fmt.Errorf("failed to get CfT download info: %w", err)
	}
	p.version = version
	p.say("v%s\n", version)

	// Check cache first.
	binPath, err := binPathForVersion(version)
	if err != nil {
		return "", err
	}

	dir, err := versionDir(version)
	if err != nil {
		return "", err
	}

	marker := filepath.Join(dir, ".extracted")
	if data, err := os.ReadFile(marker); err == nil && string(data) == version {
		if _, err := os.Stat(binPath); err == nil {
			p.say("  Chrome for Testing v%s already cached at %s\n", version, binPath)
			return binPath, nil
		}
	}

	// Binary exists but no marker (previous verify failed, e.g. missing libs).
	// Re-verify instead of re-downloading.
	if _, err := os.Stat(binPath); err == nil {
		p.say("  Chrome for Testing extracted but not verified, retrying... ")
		if err := verifyBrowser(binPath); err != nil {
			p.say("failed\n")
			return "", err
		}
		p.say("ok\n")
		if err := os.WriteFile(marker, []byte(version), 0644); err != nil {
			zap.L().Debug("failed to write chrome version marker", zap.String("marker", marker), zap.Error(err))
		}
		p.say("  Chrome for Testing ready: %s\n", binPath)
		return binPath, nil
	}

	// Download.
	p.say("  Downloading Chrome for Testing v%s... ", version)
	tmpFile, err := p.downloadToTemp(ctx, downloadURL)
	if err != nil {
		p.say("failed\n")
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// Print downloaded size.
	if info, statErr := os.Stat(tmpFile); statErr == nil {
		p.bytes = info.Size()
		p.say("done (%.1f MB)\n", float64(info.Size())/1024/1024)
	} else {
		p.say("done\n")
	}

	// Clean old version dir and extract.
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("failed to clean cache dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	p.say("  Extracting... ")
	if err := extractZipFile(tmpFile, dir); err != nil {
		p.say("failed\n")
		return "", fmt.Errorf("extraction failed: %w", err)
	}
	p.say("done\n")

	// Make binary executable.
	if err := os.Chmod(binPath, 0755); err != nil {
		return "", fmt.Errorf("failed to chmod binary: %w", err)
	}

	// Verify the binary actually works (catches missing shared libraries).
	// Done BEFORE writing the marker so a failed verify leaves no marker,
	// allowing a retry after the user installs the required deps.
	p.say("  Verifying Chrome binary... ")
	if err := verifyBrowser(binPath); err != nil {
		p.say("failed\n")
		return "", err
	}
	p.say("ok\n")

	// Write marker only after successful verification.
	if err := os.WriteFile(marker, []byte(version), 0644); err != nil {
		return "", fmt.Errorf("failed to write marker: %w", err)
	}

	p.say("  Chrome for Testing ready: %s\n", binPath)
	zap.L().Info("Chrome for Testing downloaded",
		zap.String("version", version),
		zap.String("path", binPath))

	return binPath, nil
}

// verifyBrowser runs chrome --version to confirm the binary works.
// If it fails due to missing shared libraries, returns an error
// recommending a system Chromium install (which Vigolium prefers over the
// downloaded Chrome for Testing anyway).
func verifyBrowser(binPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	output := string(out)

	// Check for missing shared library errors.
	if strings.Contains(output, "error while loading shared libraries") ||
		strings.Contains(output, "cannot open shared object file") {

		// Extract the specific missing lib name for the message.
		missing := parseMissingLib(output)

		if runtime.GOOS == "linux" {
			progressf("\n\n  Chrome for Testing requires system libraries that are not installed.\n")
			if missing != "" {
				progressf("  Missing: %s\n", missing)
			}
			progressf("\n  Install Chromium with your package manager instead, e.g.:\n" +
				"    sudo apt install chromium\n\n" +
				"  Vigolium will use the system Chromium automatically once it's installed.\n\n")
			return fmt.Errorf("chrome binary missing shared libraries — install chromium with your package manager, e.g.: sudo apt install chromium")
		}

		return fmt.Errorf("chrome binary failed: %s", output)
	}

	return fmt.Errorf("chrome binary verification failed: %s (exit: %w)", output, err)
}

// downloadToTemp downloads a URL to a temporary file, returning its path.
func (p *provisioner) downloadToTemp(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "chrome-for-testing-*.zip")
	if err != nil {
		return "", err
	}

	// Wrap the body in a progress reporter when content length is known.
	var reader io.Reader = resp.Body
	if resp.ContentLength > 0 {
		reader = &progressReader{
			reader:  resp.Body,
			total:   resp.ContentLength,
			version: p.version,
			report:  p.onProgress,
		}
	}

	written, err := io.Copy(tmp, reader)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	// Clear the progress line.
	if resp.ContentLength > 0 && p.onProgress == nil {
		progressf("\r\033[K")
	}

	zap.L().Debug("Download complete",
		zap.Int64("bytes", written),
		zap.String("path", tmp.Name()))

	return tmp.Name(), nil
}

// progressReader wraps an io.Reader and reports download progress every 5%:
// to report when set, else as a text bar on progressOut (stderr).
type progressReader struct {
	reader      io.Reader
	total       int64
	read        int64
	lastPercent int
	version     string
	report      ProgressFunc
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	percent := int(pr.read * 100 / pr.total)
	if percent != pr.lastPercent && percent%5 == 0 {
		pr.lastPercent = percent
		if pr.report != nil {
			pr.report(ProgressEvent{State: StateDownloading, Version: pr.version, Bytes: pr.read, Total: pr.total})
			return n, err
		}
		progressf("\r  Downloading Chrome for Testing... %d%% (%.1f/%.1f MB)",
			percent,
			float64(pr.read)/1024/1024,
			float64(pr.total)/1024/1024)
	}
	return n, err
}

// extractZipFile extracts a zip file on disk to the destination directory.
func extractZipFile(zipPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		path := filepath.Join(dest, f.Name)
		if !isInsideDir(path, dest) {
			return fmt.Errorf("invalid file path (zip slip): %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, f.Mode()); err != nil {
				return fmt.Errorf("failed to create dir %s: %w", path, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("failed to create parent dir for %s: %w", path, err)
		}

		if err := extractSingleFile(f, path); err != nil {
			return err
		}
	}
	return nil
}

func extractSingleFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("failed to open %s in zip: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, rc); err != nil {
		return fmt.Errorf("failed to write %s: %w", destPath, err)
	}
	return nil
}

// parseMissingLib extracts the library name from an error like:
// "error while loading shared libraries: libfoo.so.1: cannot open shared object file"
func parseMissingLib(output string) string {
	const marker = "error while loading shared libraries: "
	idx := strings.Index(output, marker)
	if idx < 0 {
		return ""
	}
	rest := output[idx+len(marker):]
	if end := strings.IndexByte(rest, ':'); end > 0 {
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

// isInsideDir checks if path is inside baseDir (prevents zip slip).
func isInsideDir(path, baseDir string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}
	return strings.HasPrefix(absPath, absBase+string(filepath.Separator)) || absPath == absBase
}
