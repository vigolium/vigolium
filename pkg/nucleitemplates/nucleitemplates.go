// Package nucleitemplates installs the nuclei-templates corpus from a release
// archive over plain HTTPS — no git — optionally pinned to a version and a
// SHA-256, and records what was installed in a marker file so freshness is a
// fact rather than a directory mtime.
package nucleitemplates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/dbimport"
)

// MarkerFile is written into the templates directory after an install.
const MarkerFile = ".vigolium-templates.json"

// Marker is MarkerFile's content.
type Marker struct {
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256,omitempty"`
	Source      string    `json:"source,omitempty"`
	InstalledAt time.Time `json:"installed_at"`
}

// ReadMarker reads dir's marker.
func ReadMarker(dir string) (*Marker, error) {
	data, err := os.ReadFile(filepath.Join(dir, MarkerFile))
	if err != nil {
		return nil, err
	}
	var m Marker
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// WriteMarker writes dir's marker.
func WriteMarker(dir string, m Marker) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, MarkerFile), data, 0o644)
}

// Pin selects what to install. An empty Version installs the latest release
// (resolved from the releases/latest redirect); a non-empty SHA256 must match
// the downloaded archive or the install fails and nothing is replaced.
type Pin struct {
	Version string
	SHA256  string
}

const (
	repoURL = "https://github.com/projectdiscovery/nuclei-templates"
	// maxArchiveBytes bounds the download (the corpus is ~tens of MB gzipped).
	maxArchiveBytes = 1 << 30
)

// Fetcher opens url for reading. Replaceable in tests.
type Fetcher func(ctx context.Context, url string) (io.ReadCloser, error)

// LatestResolver returns the latest release tag. Replaceable in tests.
type LatestResolver func(ctx context.Context) (string, error)

var (
	fetch         Fetcher        = httpFetch
	resolveLatest LatestResolver = httpLatest
)

// SetFetcherForTest swaps the fetcher and latest resolver; the returned func
// restores them.
func SetFetcherForTest(f Fetcher, l LatestResolver) func() {
	pf, pl := fetch, resolveLatest
	fetch, resolveLatest = f, l
	return func() { fetch, resolveLatest = pf, pl }
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
}

func httpFetch(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

func httpLatest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, repoURL+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	c := httpClient()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		return loc[i+len("/tag/"):], nil
	}
	return "", fmt.Errorf("cannot resolve the latest nuclei-templates release (HTTP %d)", resp.StatusCode)
}

// ArchiveURL is the release tarball URL for version.
func ArchiveURL(version string) string {
	return repoURL + "/archive/refs/tags/" + version + ".tar.gz"
}

// Install downloads the pinned (or latest) release archive, verifies its
// digest when pinned, extracts it into a staging directory next to dir and
// swaps it in, then writes the marker. dir is replaced only on success.
func Install(ctx context.Context, dir string, pin Pin) (*Marker, error) {
	version := strings.TrimSpace(pin.Version)
	if version == "" {
		v, err := resolveLatest(ctx)
		if err != nil {
			return nil, err
		}
		version = v
	}
	url := ArchiveURL(version)
	body, err := fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download nuclei-templates %s: %w", version, err)
	}
	defer func() { _ = body.Close() }()

	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(parent, ".nuclei-templates-*.tar.gz")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, maxArchiveBytes+1))
	_ = tmp.Close()
	if err != nil {
		return nil, fmt.Errorf("download nuclei-templates %s: %w", version, err)
	}
	if n > maxArchiveBytes {
		return nil, fmt.Errorf("nuclei-templates archive exceeds %d bytes", maxArchiveBytes)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if want := strings.ToLower(strings.TrimSpace(pin.SHA256)); want != "" && want != sum {
		return nil, fmt.Errorf("nuclei-templates %s: archive sha256 %s does not match the pinned %s", version, sum, want)
	}

	stage, err := os.MkdirTemp(parent, ".nuclei-templates-stage-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := extract(tmp.Name(), stage); err != nil {
		return nil, fmt.Errorf("extract nuclei-templates %s: %w", version, err)
	}
	m := Marker{Version: version, SHA256: sum, Source: url, InstalledAt: time.Now().UTC()}
	if err := WriteMarker(stage, m); err != nil {
		return nil, err
	}
	old := dir + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(stage, dir); err != nil {
		_ = os.Rename(old, dir)
		return nil, err
	}
	_ = os.RemoveAll(old)
	return &m, nil
}

// extract unpacks a .tar.gz into dst, dropping the archive's top-level
// directory and refusing entries that escape dst; links are not written.
func extract(archive, dst string) error {
	files, err := dbimport.ExtractTarGz(archive, dst, true)
	if err != nil {
		return err
	}
	if files == 0 {
		return errors.New("archive contained no files")
	}
	return nil
}
