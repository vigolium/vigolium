package toolexec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PlatformNamer returns (osName, archName) for the current platform.
type PlatformNamer func() (osName, archName string, err error)

// AssetNamer constructs the asset filename from os/arch names.
type AssetNamer func(osName, archName string) string

// ResolveViaAssetLookup returns a ResolveDownloadURL function that queries
// the GitHub release API and matches an asset by name.
// Used by ast-grep which needs to look up exact asset names from the release.
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
