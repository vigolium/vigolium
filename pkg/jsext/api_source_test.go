package jsext

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSourceTestVM(t *testing.T, opts APIOptions) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	vigolium := vm.NewObject()
	_ = vm.Set("vigolium", vigolium)
	registerFuncsUnchecked(vm, opts, sourceFuncDefs())
	return vm
}

// setupSourceRepo creates a temp directory with test files and a SourceRepo record.
func setupSourceRepo(t *testing.T, repo *database.Repository, hostname string) string {
	t.Helper()
	dir := t.TempDir()

	// Create some test files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.js"), []byte("const express = require('express');\napp.get('/api', handler);\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"name":"test-app"}`), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "app.js"), []byte("module.exports = { start: function() {} };\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "util.ts"), []byte("export function helper(): string { return 'ok'; }\n"), 0644))

	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    hostname,
		Name:        "test-repo",
		RootPath:    dir,
		RepoType:    "git",
	}
	require.NoError(t, repo.CreateSourceRepo(context.Background(), sr))

	return dir
}

func TestSourceReadFileByHostname(t *testing.T) {
	repo := newTestRepo(t)
	setupSourceRepo(t, repo, "example.com")
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.source.readFile("example.com", "index.js")`)
	require.NoError(t, err)
	assert.Contains(t, val.String(), "express")
}

func TestSourceReadFileByHostnameNotFound(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	// No repo for this hostname
	val, err := vm.RunString(`vigolium.source.readFile("unknown.com", "index.js")`)
	require.NoError(t, err)
	assert.Equal(t, "", val.String())
}

func TestSourceReadFileNoRepo(t *testing.T) {
	vm := setupSourceTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.source.readFile("example.com", "index.js")`)
	require.NoError(t, err)
	assert.Equal(t, "", val.String())
}

func TestSourceReadFilePathTraversal(t *testing.T) {
	repo := newTestRepo(t)
	setupSourceRepo(t, repo, "example.com")
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.source.readFile("example.com", "../../etc/passwd")`)
	require.NoError(t, err)
	assert.Equal(t, "", val.String())
}

func TestSourceListFilesByHostname(t *testing.T) {
	repo := newTestRepo(t)
	setupSourceRepo(t, repo, "example.com")
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	// List all files
	val, err := vm.RunString(`vigolium.source.listFiles("example.com")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Greater(t, length, int64(0))
}

func TestSourceListFilesWithGlob(t *testing.T) {
	repo := newTestRepo(t)
	setupSourceRepo(t, repo, "example.com")
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	// List only .js files
	val, err := vm.RunString(`vigolium.source.listFiles("example.com", "*.js")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Greater(t, length, int64(0))

	// Check all results end in .js
	for i := int64(0); i < length; i++ {
		item := arr.Get(string(rune('0' + i))).String()
		assert.Contains(t, item, ".js")
	}
}

func TestSourceListFilesNotFound(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.source.listFiles("unknown.com")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(0), length)
}

func TestSourceSearchFilesByHostname(t *testing.T) {
	repo := newTestRepo(t)
	setupSourceRepo(t, repo, "example.com")
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.source.searchFiles("example.com", "require\\(")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Greater(t, length, int64(0))

	// First result should have path, line, match
	first := arr.Get("0").ToObject(vm)
	assert.NotEmpty(t, first.Get("path").String())
	assert.Greater(t, first.Get("line").ToInteger(), int64(0))
	assert.Contains(t, first.Get("match").String(), "require(")
}

func TestSourceSearchFilesNotFound(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.source.searchFiles("unknown.com", "anything")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(0), length)
}

func TestSourceSearchFilesInvalidRegex(t *testing.T) {
	repo := newTestRepo(t)
	setupSourceRepo(t, repo, "example.com")
	vm := setupSourceTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.source.searchFiles("example.com", "[invalid")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(0), length)
}

func TestResolveSourceRepoByHostname(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	dir := t.TempDir()
	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    "test.com",
		Name:        "test-repo",
		RootPath:    dir,
		RepoType:    "git",
	}
	require.NoError(t, repo.CreateSourceRepo(ctx, sr))

	// Should resolve
	got, err := resolveSourceRepoByHostname(repo, "", "test.com")
	require.NoError(t, err)
	assert.Equal(t, "test-repo", got.Name)

	// Empty hostname
	_, err = resolveSourceRepoByHostname(repo, "", "")
	assert.Error(t, err)

	// Unknown hostname
	_, err = resolveSourceRepoByHostname(repo, "", "unknown.com")
	assert.Error(t, err)
}
