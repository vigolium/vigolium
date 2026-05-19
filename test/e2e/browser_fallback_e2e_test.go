//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	browserFallbackDockerfile           = "test/e2e/testdata/browser-fallback/Dockerfile"
	browserFallbackNoChromiumDockerfile = "test/e2e/testdata/browser-fallback/Dockerfile.no-chromium"
	browserFallbackSnapStubDockerfile   = "test/e2e/testdata/browser-fallback/Dockerfile.snap-stub"
	browserFallbackCfTDockerfile        = "test/e2e/testdata/browser-fallback/Dockerfile.cft-download"
	browserFallbackImageBase            = "vigolium-browser-fallback-test"
	spideringTarget                     = "https://ginandjuice.shop/"
)

// TestBrowserFallback_SystemChromium verifies that vigolium spidering
// correctly falls back to a system-installed chromium binary when the
// embedded browser is unavailable. This is the common case on ARM64 Linux
// (Docker on Apple Silicon) where the embedded binary extraction fails
// and the auto-download URLs have no linux_arm64 entry.
//
// The test builds a Docker image with system chromium installed (via apt)
// and runs spidering inside it, asserting no browser-related errors appear.
func TestBrowserFallback_SystemChromium(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser fallback e2e test in short mode")
	}

	// Determine which platforms to test based on host architecture.
	// Native arch always runs. Cross-arch runs are opt-in because availability
	// of buildx/QEMU does not guarantee they finish within normal CI/E2E budgets.
	platforms := []string{fmt.Sprintf("linux/%s", runtime.GOARCH)}
	if os.Getenv("VIGOLIUM_E2E_CROSS_ARCH") == "1" && crossPlatformAvailable(t) {
		switch runtime.GOARCH {
		case "arm64":
			platforms = append(platforms, "linux/amd64")
		case "amd64":
			platforms = append(platforms, "linux/arm64")
		}
	}

	// Find repo root (Dockerfile uses COPY . . so context must be repo root)
	repoRoot := findRepoRoot(t)

	for _, platform := range platforms {
		platform := platform
		t.Run(platform, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), browserFallbackTimeout(platform))
			defer cancel()

			imageName := fmt.Sprintf("%s:%s", browserFallbackImageBase, strings.ReplaceAll(platform, "/", "-"))

			// Build the test image for this platform
			buildImage(ctx, t, repoRoot, imageName, platform)
			t.Cleanup(func() { removeImage(imageName) })

			// Run spidering inside the container
			stdout, stderr := runSpidering(ctx, t, imageName, platform)
			output := stdout + "\n" + stderr

			// Assert no browser binary errors
			assert.NotContains(t, output, "can't find a browser binary",
				"spidering should not fail to find browser binary on %s", platform)
			assert.NotContains(t, output, "failed to create browser pool",
				"browser pool creation should succeed on %s", platform)
			assert.NotContains(t, output, "failed to launch browser",
				"browser launch should succeed on %s", platform)

			// Verify system browser was detected (debug output)
			if strings.Contains(output, "Using system browser") {
				t.Logf("[%s] Confirmed: system browser fallback used", platform)
			} else if strings.Contains(output, "Using embedded browser") {
				t.Logf("[%s] Embedded browser was available (expected on amd64)", platform)
			}

			// Spidering should have produced some output (not a zero-record failure)
			assert.Contains(t, output, "Spidering", "spidering phase should have started")
		})
	}
}

func browserFallbackTimeout(platform string) time.Duration {
	if strings.Contains(platform, runtime.GOARCH) {
		return 15 * time.Minute
	}
	return 25 * time.Minute
}

// TestBrowserFallback_SnapStub verifies that vigolium detects and skips
// Ubuntu's snap stub at /usr/bin/chromium-browser and falls back to the
// real /usr/bin/chromium binary instead.
func TestBrowserFallback_SnapStub(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser fallback e2e test in short mode")
	}

	repoRoot := findRepoRoot(t)
	platform := fmt.Sprintf("linux/%s", runtime.GOARCH)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	imageName := browserFallbackImageBase + ":snap-stub"

	buildImageWithDockerfile(ctx, t, repoRoot, imageName, platform, browserFallbackSnapStubDockerfile)
	t.Cleanup(func() { removeImage(imageName) })

	stdout, stderr := runSpidering(ctx, t, imageName, platform)
	output := stdout + "\n" + stderr

	// Should NOT hit the snap stub error
	assert.NotContains(t, output, "requires the chromium snap",
		"should skip the snap stub and use the real chromium binary")
	assert.NotContains(t, output, "failed to create browser pool",
		"browser pool creation should succeed")

	// Should use the real system browser (/usr/bin/chromium)
	if strings.Contains(output, "Using system browser") {
		t.Log("Confirmed: snap stub skipped, real system browser used")
	}

	assert.Contains(t, output, "Spidering", "spidering phase should have started")
}

// buildImage builds the Docker image for the given platform using the default Dockerfile.
func buildImage(ctx context.Context, t *testing.T, repoRoot, imageName, platform string) {
	t.Helper()
	buildImageWithDockerfile(ctx, t, repoRoot, imageName, platform, browserFallbackDockerfile)
}

// runSpidering executes vigolium spidering inside the container and returns output.
func runSpidering(ctx context.Context, t *testing.T, imageName, platform string) (string, string) {
	t.Helper()
	t.Logf("Running spidering in %s (%s)...", imageName, platform)

	args := []string{
		"run", "--rm",
		"--platform", platform,
		imageName,
		"vigolium", "run", "spidering",
		"-t", spideringTarget,
		"--debug",
	}

	cmd := exec.CommandContext(ctx, "docker", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Spidering may exit non-zero if target is unreachable, that's OK.
	// We only care about browser-related errors.
	t.Logf("Exit code: %v", err)
	t.Logf("Stdout (%s):\n%s", platform, stdout.String())
	t.Logf("Stderr (%s):\n%s", platform, stderr.String())

	return stdout.String(), stderr.String()
}

// crossPlatformAvailable checks if Docker buildx with QEMU is set up
// for cross-architecture builds.
func crossPlatformAvailable(t *testing.T) bool {
	t.Helper()

	// Check if docker buildx is available with multi-platform support
	cmd := exec.Command("docker", "buildx", "inspect", "--bootstrap")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log("docker buildx not available, skipping cross-platform tests")
		return false
	}

	output := string(out)
	switch runtime.GOARCH {
	case "arm64":
		return strings.Contains(output, "linux/amd64")
	case "amd64":
		return strings.Contains(output, "linux/arm64")
	}
	return false
}

// findRepoRoot walks up from the working directory to find the repo root
// (the directory containing go.mod).
func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir[:strings.LastIndex(dir, "/")]
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

// TestBrowserFallback_NoChromium verifies that when no browser is installed
// at all, vigolium produces a clear, actionable error message instead of
// the cryptic "can't find a browser binary for your OS" with broken URLs.
func TestBrowserFallback_NoChromium(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser fallback e2e test in short mode")
	}

	repoRoot := findRepoRoot(t)
	platform := fmt.Sprintf("linux/%s", runtime.GOARCH)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	imageName := browserFallbackImageBase + ":no-chromium"

	buildImageWithDockerfile(ctx, t, repoRoot, imageName, platform, browserFallbackNoChromiumDockerfile)
	t.Cleanup(func() { removeImage(imageName) })

	stdout, stderr := runSpidering(ctx, t, imageName, platform)
	output := stdout + "\n" + stderr

	// Should fail gracefully — spidering reports failure but no panic/crash
	assert.Contains(t, output, "Spidering", "spidering phase should have started")

	// Should NOT show the broken URL error with empty path segments
	assert.NotContains(t, output, "chromium-browser-snapshots//",
		"should not produce broken download URLs with empty path segments")

	// Should show a clear error about the browser not being found
	if strings.Contains(output, "install chromium") {
		t.Log("Confirmed: clear error message shown when no browser is available")
	} else if strings.Contains(output, "Spidering failed") {
		t.Log("Spidering failed (expected without chromium)")
	}
}

// buildImageWithDockerfile builds a Docker image using the specified Dockerfile.
func buildImageWithDockerfile(ctx context.Context, t *testing.T, repoRoot, imageName, platform, dockerfile string) {
	t.Helper()
	t.Logf("Building image %s for %s...", imageName, platform)

	args := []string{
		"build",
		"--platform", platform,
		"-t", imageName,
		"-f", dockerfile,
		".",
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = repoRoot

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	if err != nil {
		t.Logf("Docker build output:\n%s", buf.String())
	}
	require.NoError(t, err, "docker build failed for %s", platform)
}

// TestCfTDownload_Doctor verifies that `vigolium doctor --fix` downloads Chrome
// for Testing when no system chromium is installed. Only runs on linux/amd64
// since CfT has no linux/arm64 builds.
func TestCfTDownload_Doctor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CfT download e2e test in short mode")
	}

	repoRoot := findRepoRoot(t)
	platform := "linux/amd64"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	imageName := browserFallbackImageBase + ":cft-download"

	buildImageWithDockerfile(ctx, t, repoRoot, imageName, platform, browserFallbackCfTDockerfile)
	t.Cleanup(func() { removeImage(imageName) })

	// Run `vigolium doctor --fix` — should download Chrome for Testing.
	stdout, stderr := runDocker(ctx, t, imageName, platform,
		"vigolium", "doctor", "--fix", "--verbose")
	output := stdout + "\n" + stderr

	// Should show CfT download progress.
	assert.Contains(t, output, "Chrome for Testing",
		"doctor should attempt Chrome for Testing download")

	// Should report chromium as OK after download.
	assert.Contains(t, output, "chrome-for-testing",
		"doctor should show CfT cache path")

	// Should NOT report chromium as missing/warning after download succeeds.
	if strings.Contains(output, "not found in PATH") && !strings.Contains(output, "chrome-for-testing") {
		t.Error("doctor should have resolved chromium via CfT download")
	}

	t.Logf("Doctor output:\n%s", output)
}

// TestCfTDownload_Spidering verifies that after `vigolium doctor --fix` downloads
// Chrome for Testing, spidering can use the cached binary. Only linux/amd64.
func TestCfTDownload_Spidering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CfT spidering e2e test in short mode")
	}

	repoRoot := findRepoRoot(t)
	platform := "linux/amd64"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	imageName := browserFallbackImageBase + ":cft-spidering"

	buildImageWithDockerfile(ctx, t, repoRoot, imageName, platform, browserFallbackCfTDockerfile)
	t.Cleanup(func() { removeImage(imageName) })

	// Step 1: Run doctor --fix to download Chrome for Testing.
	doctorOut, doctorErr := runDocker(ctx, t, imageName, platform,
		"vigolium", "doctor", "--fix")
	t.Logf("Doctor output:\n%s\n%s", doctorOut, doctorErr)

	// Step 2: Run spidering using the same cached CfT browser.
	// Use `docker run` with a named volume to persist the cache between runs.
	volumeName := "vigolium-cft-test-cache"
	_ = exec.Command("docker", "volume", "rm", "-f", volumeName).Run()
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", volumeName).Run() })

	// Run doctor first with the volume to cache the browser.
	doctorArgs := []string{
		"run", "--rm",
		"--platform", platform,
		"-v", volumeName + ":/root/.cache/vigolium",
		imageName,
		"vigolium", "doctor", "--fix",
	}
	cmd := exec.CommandContext(ctx, "docker", doctorArgs...)
	var dBuf bytes.Buffer
	cmd.Stdout = &dBuf
	cmd.Stderr = &dBuf
	err := cmd.Run()
	t.Logf("Doctor (with volume) exit: %v\nOutput:\n%s", err, dBuf.String())

	// Then run spidering with the same volume.
	spiderArgs := []string{
		"run", "--rm",
		"--platform", platform,
		"-v", volumeName + ":/root/.cache/vigolium",
		imageName,
		"vigolium", "run", "spidering",
		"-t", spideringTarget,
		"--debug",
	}
	cmd = exec.CommandContext(ctx, "docker", spiderArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()

	output := stdout.String() + "\n" + stderr.String()
	t.Logf("Spidering exit: %v", err)
	t.Logf("Spidering output:\n%s", output)

	// Should use the cached CfT browser.
	assert.Contains(t, output, "Spidering", "spidering phase should have started")
	assert.NotContains(t, output, "can't find a browser binary",
		"should find CfT-downloaded browser")
	assert.NotContains(t, output, "failed to create browser pool",
		"browser pool creation should succeed with CfT browser")

	if strings.Contains(output, "Using cached Chrome for Testing") {
		t.Log("Confirmed: spidering used cached Chrome for Testing binary")
	}
}

// TestCfTDownload_SpideringAutoDownload verifies that spidering automatically
// downloads Chrome for Testing when no browser is available — without running
// `vigolium doctor` first. Only linux/amd64.
func TestCfTDownload_SpideringAutoDownload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CfT auto-download e2e test in short mode")
	}

	repoRoot := findRepoRoot(t)
	platform := "linux/amd64"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	imageName := browserFallbackImageBase + ":cft-auto"

	buildImageWithDockerfile(ctx, t, repoRoot, imageName, platform, browserFallbackCfTDockerfile)
	t.Cleanup(func() { removeImage(imageName) })

	// Run spidering directly — no doctor step. CfT should auto-download.
	stdout, stderr := runDocker(ctx, t, imageName, platform,
		"vigolium", "run", "spidering",
		"-t", spideringTarget,
		"--debug")
	output := stdout + "\n" + stderr

	t.Logf("Spidering (auto-download) output:\n%s", output)

	// Should have downloaded CfT on the fly.
	assert.Contains(t, output, "Chrome for Testing",
		"spidering should trigger CfT auto-download when no browser is available")
	assert.Contains(t, output, "Spidering", "spidering phase should have started")
	assert.NotContains(t, output, "can't find a browser binary",
		"should not fall through to broken rod auto-download")
	assert.NotContains(t, output, "failed to create browser pool",
		"browser pool creation should succeed with auto-downloaded CfT browser")

	if strings.Contains(output, "Using downloaded Chrome for Testing") {
		t.Log("Confirmed: spidering auto-downloaded Chrome for Testing")
	}
}

// runDocker executes a command inside a Docker container and returns stdout/stderr.
func runDocker(ctx context.Context, t *testing.T, imageName, platform string, command ...string) (string, string) {
	t.Helper()

	args := []string{"run", "--rm", "--platform", platform, imageName}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	t.Logf("Exit code: %v", err)

	return stdout.String(), stderr.String()
}

// removeImage removes a Docker image (best-effort cleanup).
func removeImage(imageName string) {
	_ = exec.Command("docker", "rmi", "-f", imageName).Run()
}
