//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext"
)

const juiceShopGitURL = "https://github.com/juice-shop/juice-shop"

// cloneJuiceShop clones the Juice Shop repo into a temp directory.
// It skips the test if git is unavailable or the clone fails.
func cloneJuiceShop(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found in PATH, skipping source-aware test")
	}

	dir := t.TempDir()
	dest := filepath.Join(dir, "juice-shop")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", juiceShopGitURL, dest)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Skipf("git clone failed (network issue?): %v", err)
	}

	return dest
}

// setupSourceAwareDB creates an in-memory SQLite database for source-aware tests.
func setupSourceAwareDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        ":memory:",
			BusyTimeout: 5000,
			JournalMode: "MEMORY",
			Synchronous: "OFF",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return db, database.NewRepository(db)
}

func TestSourceAware_CloneAndLink(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	repoPath := cloneJuiceShop(t)
	_, repo := setupSourceAwareDB(t)
	ctx := context.Background()

	// Create a SourceRepo record
	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    "localhost",
		Name:        "juice-shop",
		RootPath:    repoPath,
		RepoType:    "git",
		Language:    "typescript",
		Framework:   "angular",
	}
	err := repo.CreateSourceRepo(ctx, sr)
	require.NoError(t, err)
	assert.Greater(t, sr.ID, int64(0), "should have assigned an ID")

	// Verify fields
	got, err := repo.GetSourceRepoByID(ctx, sr.ID)
	require.NoError(t, err)
	assert.Equal(t, "localhost", got.Hostname)
	assert.Equal(t, "juice-shop", got.Name)
	assert.Equal(t, repoPath, got.RootPath)
	assert.Equal(t, "git", got.RepoType)
	assert.Equal(t, "typescript", got.Language)
	assert.Equal(t, "angular", got.Framework)

	// GetSourceReposByHostname
	repos, err := repo.GetSourceReposByHostname(ctx, database.DefaultProjectUUID, "localhost")
	require.NoError(t, err)
	require.Len(t, repos, 1)
	assert.Equal(t, sr.ID, repos[0].ID)
}

func TestSourceAware_ListFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	repoPath := cloneJuiceShop(t)

	// Verify package.json exists at root
	_, err := os.Stat(filepath.Join(repoPath, "package.json"))
	require.NoError(t, err, "package.json should exist at repo root")

	// Walk for .ts files
	var tsFiles []string
	err = filepath.WalkDir(repoPath, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".ts") {
			rel, _ := filepath.Rel(repoPath, path)
			tsFiles = append(tsFiles, rel)
		}
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tsFiles, "should find .ts files in Juice Shop repo")
}

func TestSourceAware_SearchFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	repoPath := cloneJuiceShop(t)

	// Search for require( or import patterns
	re := regexp.MustCompile(`require\(|import `)
	var matches []struct {
		path string
		line int
	}

	err := filepath.WalkDir(repoPath, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".ts" && ext != ".js" {
			return nil
		}
		f, fErr := os.Open(path)
		if fErr != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if re.MatchString(scanner.Text()) {
				rel, _ := filepath.Rel(repoPath, path)
				matches = append(matches, struct {
					path string
					line int
				}{rel, lineNum})
				if len(matches) >= 100 {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, matches, "should find require()/import patterns in Juice Shop")
}

func TestSourceAware_ReadFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	repoPath := cloneJuiceShop(t)

	data, err := os.ReadFile(filepath.Join(repoPath, "package.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "juice-shop", "package.json should contain 'juice-shop'")
}

func TestSourceAware_JSExtAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	repoPath := cloneJuiceShop(t)
	_, repo := setupSourceAwareDB(t)
	ctx := context.Background()

	// Create source repo record
	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    "localhost",
		Name:        "juice-shop",
		RootPath:    repoPath,
		RepoType:    "git",
		Language:    "typescript",
		Framework:   "angular",
	}
	require.NoError(t, repo.CreateSourceRepo(ctx, sr))

	// Create a JS active module that exercises vigolium.source.* APIs
	scriptDir := t.TempDir()
	scriptPath := filepath.Join(scriptDir, "source_test.js")
	require.NoError(t, os.WriteFile(scriptPath, []byte(`
module.exports = {
  id: "source-test",
  name: "Source Test Module",
  description: "Tests vigolium.source API",
  type: "active",
  severity: "info",
  scanTypes: ["per_host"],

  scanPerHost: function(ctx) {
    var results = [];

    // Test getByHostname
    var repos = vigolium.source.getByHostname("localhost");
    if (!repos || repos.length === 0) {
      return [{ matched: "FAIL: getByHostname returned empty", url: ctx.request.url, severity: "info" }];
    }
    var repo = repos[0];
    if (repo.name !== "juice-shop") {
      return [{ matched: "FAIL: repo name mismatch: " + repo.name, url: ctx.request.url, severity: "info" }];
    }

    // Test readFile
    var content = vigolium.source.readFile(repo.hostname, "package.json");
    if (!content || content.indexOf("juice-shop") === -1) {
      return [{ matched: "FAIL: readFile package.json missing juice-shop", url: ctx.request.url, severity: "info" }];
    }

    // Test listFiles with glob
    var jsonFiles = vigolium.source.listFiles(repo.hostname, "*.json");
    var foundPkg = false;
    for (var i = 0; i < jsonFiles.length; i++) {
      if (jsonFiles[i] === "package.json") {
        foundPkg = true;
        break;
      }
    }
    if (!foundPkg) {
      return [{ matched: "FAIL: listFiles *.json missing package.json", url: ctx.request.url, severity: "info" }];
    }

    // Test searchFiles
    var searchResults = vigolium.source.searchFiles(repo.hostname, "express");
    if (!searchResults || searchResults.length === 0) {
      return [{ matched: "FAIL: searchFiles express returned empty", url: ctx.request.url, severity: "info" }];
    }

    // All checks passed
    results.push({
      matched: "ALL_PASSED",
      url: ctx.request.url,
      name: "Source API validation",
      description: "getByHostname, readFile, listFiles, searchFiles all OK",
      severity: "info"
    });
    return results;
  }
};
`), 0644))

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	cfg := &config.ExtensionsConfig{
		Enabled: true,
		CustomDir: []string{scriptPath},
		Limits:  config.ScriptLimits{Timeout: "60s", MaxMemoryMB: 128},
	}

	engine, err := jsext.NewEngine(cfg, infra.HTTPClient, &jsext.EngineOptions{
		Repository: repo,
	})
	require.NoError(t, err)

	activeMods := engine.ActiveModules()
	require.Len(t, activeMods, 1)
	assert.Equal(t, "ext-source-test", activeMods[0].ID())

	// Build a minimal request for scanPerHost
	rawReq := "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(rawReq))
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := activeMods[0].ScanPerHost(rr, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "JS module should return results")
	assert.Equal(t, "ALL_PASSED", results[0].Matched, "all source API checks should pass")
}
