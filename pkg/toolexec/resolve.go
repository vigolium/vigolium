package toolexec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PlatformNamer returns (osName, archName) for the current platform.
type PlatformNamer func() (osName, archName string, err error)

// AssetNamer constructs the asset filename from os/arch names.
type AssetNamer func(osName, archName string) string

// ResolveViaAssetLookup returns a ResolveDownloadURL function that queries
// the GitHub release API and matches an asset by name. Use this when the
// release uses asset names that aren't easy to construct from os/arch alone.
func ResolveViaAssetLookup(repoPath string, platform PlatformNamer, asset AssetNamer) func(context.Context, *Downloader, string) (string, error) {
	return func(ctx context.Context, d *Downloader, version string) (string, error) {
		osName, archName, err := platform()
		if err != nil {
			return "", err
		}
		assetName := asset(osName, archName)

		apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repoPath)
		if version != "" {
			apiURL = fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repoPath, version)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return "", fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", d.spec.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("fetch release: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
		}

		var release GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return "", fmt.Errorf("decode release: %w", err)
		}

		for _, a := range release.Assets {
			if a.Name == assetName {
				return a.BrowserDownloadURL, nil
			}
		}

		return "", fmt.Errorf("%w: asset %q not found in release %s", ErrDownloadFailed, assetName, version)
	}
}

// ResolveViaTemplate returns a ResolveDownloadURL function that constructs
// the download URL from a template string.
// The template should contain three %s verbs: version, osName, archName.
// Used by kingfisher which has predictable URL patterns.
func ResolveViaTemplate(urlTemplate string, platform PlatformNamer) func(context.Context, *Downloader, string) (string, error) {
	return func(_ context.Context, _ *Downloader, version string) (string, error) {
		osName, archName, err := platform()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf(urlTemplate, version, osName, archName), nil
	}
}

// ResolveChecksumViaTemplate returns a ResolveChecksum function for releases
// that publish a sidecar checksum file (e.g. "<asset>.sha256"). The template
// takes the same three %s verbs as ResolveViaTemplate: version, osName,
// archName. The fetched file may be a bare hex digest or the common
// "<hex>  <filename>" coreutils format; the leading hex token is used.
func ResolveChecksumViaTemplate(urlTemplate string, platform PlatformNamer) func(context.Context, *Downloader, string) (string, error) {
	return func(ctx context.Context, d *Downloader, version string) (string, error) {
		osName, archName, err := platform()
		if err != nil {
			return "", err
		}
		url := fmt.Sprintf(urlTemplate, version, osName, archName)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", fmt.Errorf("create checksum request: %w", err)
		}
		req.Header.Set("User-Agent", d.spec.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("fetch checksum: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("checksum fetch returned status %d", resp.StatusCode)
		}

		// Checksum files are tiny; cap the read defensively.
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return "", fmt.Errorf("read checksum: %w", err)
		}
		fields := strings.Fields(string(raw))
		if len(fields) == 0 {
			return "", fmt.Errorf("empty checksum file at %s", url)
		}
		return fields[0], nil
	}
}
