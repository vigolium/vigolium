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

	"go.uber.org/zap"
)

const apiURL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"

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
	defer resp.Body.Close()

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
// Returns the path to the chrome binary. Progress is printed to stdout so the
// user can see what is happening during `vigolium doctor`.
func EnsureBrowser(ctx context.Context) (string, error) {
	if !IsSupported() {
		return "", fmt.Errorf(
			"Chrome for Testing is not available for %s/%s — install Chromium manually (e.g. apt install chromium)",
			runtime.GOOS, runtime.GOARCH,
		)
	}

	fmt.Print("  Fetching Chrome for Testing version info... ")
	version, downloadURL, err := fetchDownloadInfo(ctx)
	if err != nil {
		fmt.Println("failed")
		return "", fmt.Errorf("failed to get CfT download info: %w", err)
	}
	fmt.Printf("v%s\n", version)

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
			fmt.Printf("  Chrome for Testing v%s already cached at %s\n", version, binPath)
			return binPath, nil
		}
	}

	// Binary exists but no marker (previous verify failed, e.g. missing libs).
	// Re-verify instead of re-downloading.
	if _, err := os.Stat(binPath); err == nil {
		fmt.Print("  Chrome for Testing extracted but not verified, retrying... ")
		if err := verifyBrowser(binPath); err != nil {
			fmt.Println("failed")
			return "", err
		}
		fmt.Println("ok")
		_ = os.WriteFile(marker, []byte(version), 0644)
		fmt.Printf("  Chrome for Testing ready: %s\n", binPath)
		return binPath, nil
	}

	// Download.
	fmt.Printf("  Downloading Chrome for Testing v%s... ", version)
	tmpFile, err := downloadToTemp(ctx, downloadURL)
	if err != nil {
		fmt.Println("failed")
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer os.Remove(tmpFile)

	// Print downloaded size.
	if info, statErr := os.Stat(tmpFile); statErr == nil {
		fmt.Printf("done (%.1f MB)\n", float64(info.Size())/1024/1024)
	} else {
		fmt.Println("done")
	}

	// Clean old version dir and extract.
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("failed to clean cache dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	fmt.Print("  Extracting... ")
	if err := extractZipFile(tmpFile, dir); err != nil {
		fmt.Println("failed")
		return "", fmt.Errorf("extraction failed: %w", err)
	}
	fmt.Println("done")

	// Make binary executable.
	if err := os.Chmod(binPath, 0755); err != nil {
		return "", fmt.Errorf("failed to chmod binary: %w", err)
	}

	// Verify the binary actually works (catches missing shared libraries).
	// Done BEFORE writing the marker so a failed verify leaves no marker,
	// allowing a retry after the user installs the required deps.
	fmt.Print("  Verifying Chrome binary... ")
	if err := verifyBrowser(binPath); err != nil {
		fmt.Println("failed")
		return "", err
	}
	fmt.Println("ok")

	// Write marker only after successful verification.
	if err := os.WriteFile(marker, []byte(version), 0644); err != nil {
		return "", fmt.Errorf("failed to write marker: %w", err)
	}

	fmt.Printf("  Chrome for Testing ready: %s\n", binPath)
	zap.L().Info("Chrome for Testing downloaded",
		zap.String("version", version),
		zap.String("path", binPath))

	return binPath, nil
}

// linuxDepsBase lists packages with their optional t64 variants.
// Ubuntu 24.04+ renames some packages with a t64 suffix.
// Entries: {base, t64Variant} — empty t64Variant means no rename.
// Entries: {base, t64Variant} — empty t64Variant means the package name
// is unchanged on Ubuntu 24.04+. Only packages that were actually renamed
// to t64 on Ubuntu 24.04 have a variant listed here.
var linuxDepsBase = [][2]string{
	{"libglib2.0-0", "libglib2.0-0t64"},
	{"libnss3", ""},
	{"libnspr4", ""},
	{"libatk1.0-0", "libatk1.0-0t64"},
	{"libatk-bridge2.0-0", "libatk-bridge2.0-0t64"},
	{"libatspi2.0-0", "libatspi2.0-0t64"},
	{"libcups2", "libcups2t64"},
	{"libdrm2", ""},
	{"libxkbcommon0", ""},
	{"libxcomposite1", ""},
	{"libxdamage1", ""},
	{"libxfixes3", ""},
	{"libxrandr2", ""},
	{"libgbm1", ""},
	{"libpango-1.0-0", ""},
	{"libpangocairo-1.0-0", ""},
	{"libcairo2", ""},
	{"libcairo-gobject2", ""},
	{"libasound2", "libasound2t64"},
	{"libxshmfence1", ""},
	{"libxi6", ""},
	{"libgtk-3-0", "libgtk-3-0t64"},
	{"libgdk-pixbuf-2.0-0", ""},
	{"libxrender1", ""},
	{"libfreetype6", ""},
	{"libfontconfig1", ""},
	{"libdbus-1-3", ""},
	{"fonts-liberation", ""},
}

// resolveLinuxDeps returns the correct package names for the current system.
// On Ubuntu 24.04+ some packages have t64 variants.
func resolveLinuxDeps() []string {
	// Detect if t64 packages exist by checking if dpkg knows about one of them.
	useT64 := false
	if out, err := exec.Command("dpkg", "-s", "libglib2.0-0t64").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "Status: install ok installed") ||
			strings.Contains(string(out), "Status:") {
			useT64 = true
		}
	} else {
		// dpkg -s failed — check if the t64 package is available in apt cache.
		if out2, err2 := exec.Command("apt-cache", "show", "libglib2.0-0t64").CombinedOutput(); err2 == nil && len(out2) > 0 {
			useT64 = true
		}
	}

	deps := make([]string, 0, len(linuxDepsBase))
	for _, pair := range linuxDepsBase {
		if useT64 && pair[1] != "" {
			deps = append(deps, pair[1])
		} else {
			deps = append(deps, pair[0])
		}
	}
	return deps
}

// verifyBrowser runs chrome --version to confirm the binary works.
// If it fails due to missing shared libraries, returns an error with
// an actionable apt-get install command.
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
			fmt.Println()
			fmt.Println()
			fmt.Println("  Chrome for Testing requires system libraries that are not installed.")
			if missing != "" {
				fmt.Printf("  Missing: %s\n", missing)
			}
			deps := resolveLinuxDeps()
			fmt.Println()
			fmt.Println("  Install them with:")
			fmt.Printf("    sudo apt-get install -y %s\n", strings.Join(deps, " "))
			fmt.Println()
			return fmt.Errorf("Chrome binary missing shared libraries — install deps with: sudo apt-get install -y %s",
				strings.Join(deps, " "))
		}

		return fmt.Errorf("Chrome binary failed: %s", output)
	}

	return fmt.Errorf("Chrome binary verification failed: %s (exit: %v)", output, err)
}

// downloadToTemp downloads a URL to a temporary file, returning its path.
func downloadToTemp(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

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
			reader: resp.Body,
			total:  resp.ContentLength,
		}
	}

	written, err := io.Copy(tmp, reader)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()

	// Clear the progress line.
	if resp.ContentLength > 0 {
		fmt.Print("\r\033[K")
	}

	zap.L().Debug("Download complete",
		zap.Int64("bytes", written),
		zap.String("path", tmp.Name()))

	return tmp.Name(), nil
}

// progressReader wraps an io.Reader and prints download progress to stdout.
type progressReader struct {
	reader      io.Reader
	total       int64
	read        int64
	lastPercent int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	percent := int(pr.read * 100 / pr.total)
	if percent != pr.lastPercent && percent%5 == 0 {
		pr.lastPercent = percent
		fmt.Printf("\r  Downloading Chrome for Testing... %d%% (%.1f/%.1f MB)",
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
	defer r.Close()

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
	defer rc.Close()

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer out.Close()

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
