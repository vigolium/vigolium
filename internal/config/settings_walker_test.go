package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func entryByKey(entries []SettingEntry, key string) (SettingEntry, bool) {
	for _, e := range entries {
		if e.Key == key {
			return e, true
		}
	}
	return SettingEntry{}, false
}

// Values are typed, false/empty keys are listed, defaults are attached, and
// redaction is by key class: string credentials only.
func TestSettingEntriesTypedAndComplete(t *testing.T) {
	s := DefaultSettings()
	s.Notify.Enabled = false
	s.ExternalHarvester.APIKeys.URLScan = "secret-value"
	entries := SettingEntries(s)

	e, ok := entryByKey(entries, "notify.enabled")
	require.True(t, ok, "a key set to false must be listed")
	require.Equal(t, false, e.Value)
	require.Equal(t, "bool", e.Type)
	require.False(t, e.Sensitive)

	e, ok = entryByKey(entries, "external_harvester.api_keys.urlscan")
	require.True(t, ok)
	require.True(t, e.Sensitive, "a key under api_keys is a credential")

	e, ok = entryByKey(entries, "discovery.engine.disable_secret_scan")
	if ok {
		require.False(t, e.Sensitive, "a boolean is never a credential")
	}

	e, ok = entryByKey(entries, "server.port")
	if ok {
		require.Equal(t, "int", e.Type)
		require.IsType(t, int64(0), e.Value)
		require.Equal(t, e.Value, e.Default)
	}
	for _, e := range entries {
		require.NotEmpty(t, e.Key)
	}
}

func TestIsCredentialKey(t *testing.T) {
	for key, want := range map[string]bool{
		"notify.telegram.bot_token":            true,
		"database.postgres.password":           true,
		"storage.secret_key":                   true,
		"external_harvester.api_keys.urlscan":  true,
		"notify.discord.webhook.url":           true,
		"agent.olium.max_tokens":               false,
		"discovery.engine.disable_secret_scan": true, // a word match; the walker only applies it to strings
		"oast.server_url":                      false,
		"scope.host.include":                   false,
	} {
		require.Equal(t, want, IsCredentialKey(key), key)
	}
}

// The tracer names the file, the env var behind a placeholder, the project
// overlay and a direct environment override.
func TestTraceSources(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "c.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("oast:\n  server_url: ${VIG_TEST_OAST:-oast.pro}\n  token: ${VIG_TEST_UNSET:-}\nnotify:\n  enabled: false\n"), 0o600))
	t.Setenv("VIG_TEST_OAST", "oast.example")
	proj := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, os.MkdirAll(ProjectConfigDir(proj), 0o755))
	require.NoError(t, os.WriteFile(ProjectConfigPath(proj), []byte("scope:\n  host:\n    exclude: [beta.example]\n"), 0o600))
	t.Setenv("VIGOLIUM_STORAGE_ENABLED", "true")

	src, err := TraceSources(TraceOptions{ConfigPath: cfg, ProjectUUID: proj, FlagKeys: []string{"database.sqlite.path"}})
	require.NoError(t, err)
	require.Equal(t, "env:VIG_TEST_OAST", SourceOf(src, "oast.server_url"))
	require.Equal(t, SourceFile, SourceOf(src, "oast.token"), "an unset placeholder falls back to the file's default")
	require.Equal(t, SourceFile, SourceOf(src, "notify.enabled"))
	require.Equal(t, SourceProject, SourceOf(src, "scope.host.exclude"))
	require.Equal(t, "env:VIGOLIUM_STORAGE_ENABLED", SourceOf(src, "storage.enabled"))
	require.Equal(t, SourceFlag, SourceOf(src, "database.sqlite.path"))
	require.Equal(t, SourceDefault, SourceOf(src, "server.port"))
}

// Every VIGOLIUM_* the source reads is in EnvRegistry, and every registry
// entry is still read somewhere (Go source or the config template).
func TestEnvRegistryRatchet(t *testing.T) {
	notEnv := map[string]bool{
		// Payload markers of the PDF-injection module, not variables.
		"VIGOLIUM_PDF_EXEC_": true, "VIGOLIUM_PDF_RENDER_": true,
	}
	lit := regexp.MustCompile(`"(VIGOLIUM_[A-Z0-9_]+)"`)
	tmpl := regexp.MustCompile(`\$\{(VIGOLIUM_[A-Z0-9_]+)`)
	found := map[string]bool{}
	root := filepath.Join("..", "..")
	for _, dir := range []string{"cmd", "internal", "pkg"} {
		require.NoError(t, filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range lit.FindAllStringSubmatch(string(data), -1) {
				if !notEnv[m[1]] {
					found[m[1]] = true
				}
			}
			return nil
		}))
	}
	data, err := os.ReadFile(filepath.Join(root, "public", "vigolium-configs.example.yaml"))
	require.NoError(t, err)
	for _, m := range tmpl.FindAllStringSubmatch(string(data), -1) {
		found[m[1]] = true
	}
	reg := map[string]bool{}
	for _, v := range EnvRegistry {
		reg[v.Name] = true
		require.NotEmpty(t, v.Description, v.Name)
	}
	for name := range found {
		require.True(t, reg[name], "%s is read but missing from EnvRegistry (internal/config/env_registry.go)", name)
	}
	for name := range reg {
		require.True(t, found[name], "%s is in EnvRegistry but nothing reads it", name)
	}
}
