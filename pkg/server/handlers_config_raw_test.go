package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
)

// The REST config and scope writers edit the raw file in place: the settings
// they hold were loaded with the environment expanded, and writing those back
// would store every secret in clear and drop the file's comments.
func TestConfigAndScopeHandlersKeepPlaceholders(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VIGOLIUM_STORAGE_SECRET_KEY", "very-secret-storage-key")
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	src := "# my config\nstorage:\n  secret_key: ${VIGOLIUM_STORAGE_SECRET_KEY}\nnotify:\n  enabled: false # off for now\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := config.LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Storage.SecretKey != "very-secret-storage-key" {
		t.Fatalf("precondition: secret not expanded in memory: %q", settings.Storage.SecretKey)
	}
	h := newBasicHandlers(t, ServerConfig{ConfigPath: path}, &fakeQueue{}, nil, nil, settings)
	app := fiber.New()
	app.Post("/api/config", h.HandleUpdateConfig)
	app.Post("/api/scope", h.HandleUpdateScope)

	for _, rc := range []struct{ path, body string }{
		{"/api/config", `{"notify.enabled":"true"}`},
		{"/api/scope", `{"host":{"include":["a.example"]},"applied_on_ingest":true}`},
	} {
		req := httptest.NewRequest(http.MethodPost, rc.path, strings.NewReader(rc.body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", rc.path, resp.StatusCode)
		}
	}

	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "very-secret-storage-key") {
		t.Fatalf("expanded secret written:\n%s", got)
	}
	for _, keep := range []string{"# my config", "${VIGOLIUM_STORAGE_SECRET_KEY}", "enabled: true # off for now"} {
		if !strings.Contains(string(got), keep) {
			t.Errorf("%q missing from:\n%s", keep, got)
		}
	}
	reloaded, err := config.LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Scope.AppliedOnIngest || len(reloaded.Scope.Host.Include) != 1 {
		t.Fatalf("scope not stored: %+v", reloaded.Scope)
	}
}
