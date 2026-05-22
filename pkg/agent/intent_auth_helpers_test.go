package agent

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

func TestParseCredentialSetsFromString(t *testing.T) {
	t.Run("first pair becomes primary, rest compare", func(t *testing.T) {
		sets := parseCredentialSetsFromString("admin/admin123, user/user123")
		if len(sets) != 2 {
			t.Fatalf("expected 2 sets, got %d: %+v", len(sets), sets)
		}
		if sets[0].Role != "primary" || sets[0].Username != "admin" || sets[0].Password != "admin123" {
			t.Errorf("set[0] = %+v, want primary admin/admin123", sets[0])
		}
		if sets[1].Role != "compare" || sets[1].Username != "user" {
			t.Errorf("set[1] = %+v, want compare user", sets[1])
		}
	})

	t.Run("explicit compare prefix", func(t *testing.T) {
		sets := parseCredentialSetsFromString("admin/pw1, compare bob/pw2")
		if len(sets) != 2 {
			t.Fatalf("expected 2 sets, got %d", len(sets))
		}
		if sets[1].Role != "compare" || sets[1].Username != "bob" || sets[1].Password != "pw2" {
			t.Errorf("set[1] = %+v, want compare bob/pw2", sets[1])
		}
	})

	t.Run("with prefix is stripped without forcing role", func(t *testing.T) {
		sets := parseCredentialSetsFromString("with admin/pw1")
		if len(sets) != 1 || sets[0].Username != "admin" || sets[0].Role != "primary" {
			t.Fatalf("expected single primary admin, got %+v", sets)
		}
	})

	t.Run("malformed entries skipped", func(t *testing.T) {
		sets := parseCredentialSetsFromString("noslash, admin/pw, /onlypass, onlyuser/")
		// only admin/pw is well-formed (user and pass both non-empty).
		if len(sets) != 1 || sets[0].Username != "admin" {
			t.Fatalf("expected only admin/pw, got %+v", sets)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := parseCredentialSetsFromString(""); got != nil {
			t.Errorf("empty input should yield nil, got %+v", got)
		}
	})
}

func TestResolveIntentCredentialSets(t *testing.T) {
	t.Run("structured sets take precedence over raw", func(t *testing.T) {
		sets := []agenttypes.IntentCredentialSet{{Name: "explicit", Username: "e", Password: "p", Role: "primary"}}
		got := resolveIntentCredentialSets("admin/admin", sets)
		if len(got) != 1 || got[0].Name != "explicit" {
			t.Fatalf("structured sets should win, got %+v", got)
		}
		// must be a copy, not the same backing array
		got[0].Name = "mutated"
		if sets[0].Name == "mutated" {
			t.Error("resolveIntentCredentialSets returned the original slice, expected a copy")
		}
	})

	t.Run("falls back to parsing raw string", func(t *testing.T) {
		got := resolveIntentCredentialSets("admin/admin", nil)
		if len(got) != 1 || got[0].Username != "admin" {
			t.Fatalf("expected raw parse, got %+v", got)
		}
	})

	t.Run("empty everything yields nil", func(t *testing.T) {
		if got := resolveIntentCredentialSets("   ", nil); got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})
}

func TestReplaceLoginBodyCredentials_JSON(t *testing.T) {
	set := agenttypes.IntentCredentialSet{Username: "newuser", Password: "newpass"}
	body := `{"username":"old","password":"x","extra":"keep"}`
	got := replaceLoginBodyCredentials(body, "application/json", set)

	var obj map[string]any
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("result is not valid JSON: %v (%s)", err, got)
	}
	if obj["username"] != "newuser" || obj["password"] != "newpass" {
		t.Errorf("credentials not replaced: %+v", obj)
	}
	if obj["extra"] != "keep" {
		t.Errorf("non-credential fields should survive, got %+v", obj)
	}
}

func TestReplaceLoginBodyCredentials_FormURLEncoded(t *testing.T) {
	set := agenttypes.IntentCredentialSet{Username: "newuser", Password: "newpass"}
	body := "user=old&pass=x&csrf=tok"
	got := replaceLoginBodyCredentials(body, "application/x-www-form-urlencoded", set)

	vals, err := url.ParseQuery(got)
	if err != nil {
		t.Fatalf("result is not valid form encoding: %v", err)
	}
	if vals.Get("user") != "newuser" || vals.Get("pass") != "newpass" {
		t.Errorf("credentials not replaced: %v", vals)
	}
	if vals.Get("csrf") != "tok" {
		t.Error("csrf token should survive")
	}
}

func TestReplaceLoginBodyCredentials_EmptyBodyUnchanged(t *testing.T) {
	set := agenttypes.IntentCredentialSet{Username: "u", Password: "p"}
	if got := replaceLoginBodyCredentials("   ", "application/json", set); got != "   " {
		t.Errorf("empty body should be returned unchanged, got %q", got)
	}
}

func TestMatchCredentialSession(t *testing.T) {
	cfg := &AgentSessionConfig{Sessions: []AgentSessionEntry{
		{Name: "admin-sess", Role: "primary"},
		{Name: "user-sess", Role: "compare"},
	}}

	t.Run("matches by role", func(t *testing.T) {
		idx := matchCredentialSession(cfg, agenttypes.IntentCredentialSet{Role: "compare"})
		if idx != 1 {
			t.Errorf("idx = %d, want 1", idx)
		}
	})

	t.Run("matches by name case-insensitive", func(t *testing.T) {
		idx := matchCredentialSession(cfg, agenttypes.IntentCredentialSet{Name: "ADMIN-SESS"})
		if idx != 0 {
			t.Errorf("idx = %d, want 0", idx)
		}
	})

	t.Run("no match returns -1 for multi-session", func(t *testing.T) {
		idx := matchCredentialSession(cfg, agenttypes.IntentCredentialSet{Name: "nope", Role: "ghost"})
		if idx != -1 {
			t.Errorf("idx = %d, want -1", idx)
		}
	})

	t.Run("single session always matches index 0", func(t *testing.T) {
		single := &AgentSessionConfig{Sessions: []AgentSessionEntry{{Name: "only"}}}
		idx := matchCredentialSession(single, agenttypes.IntentCredentialSet{Name: "irrelevant", Role: "nope"})
		if idx != 0 {
			t.Errorf("single session should match 0, got %d", idx)
		}
	})
}

func TestApplyIntentCredentialsToSessionConfig(t *testing.T) {
	base := &AgentSessionConfig{Sessions: []AgentSessionEntry{
		{
			Role: "primary",
			Login: &AgentLoginFlow{
				URL:         "http://x/login",
				ContentType: "application/json",
				Body:        `{"username":"old","password":"old"}`,
			},
		},
	}}
	sets := []agenttypes.IntentCredentialSet{
		{Name: "admin", Role: "primary", Username: "real", Password: "secret"},
	}

	out := applyIntentCredentialsToSessionConfig(base, sets)

	// original must not mutate (clone semantics)
	if strings.Contains(base.Sessions[0].Login.Body, "real") {
		t.Error("base config was mutated; expected a clone")
	}
	if out.Sessions[0].Name != "admin" {
		t.Errorf("name should be filled from credential set, got %q", out.Sessions[0].Name)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out.Sessions[0].Login.Body), &obj); err != nil {
		t.Fatalf("login body invalid JSON: %v", err)
	}
	if obj["username"] != "real" || obj["password"] != "secret" {
		t.Errorf("login body credentials not applied: %+v", obj)
	}
}

func TestApplyIntentCredentialsToSessionConfig_NoopGuards(t *testing.T) {
	// nil base, empty sessions, or empty sets all return base unchanged.
	if got := applyIntentCredentialsToSessionConfig(nil, []agenttypes.IntentCredentialSet{{Name: "x"}}); got != nil {
		t.Error("nil base should return nil")
	}
	base := &AgentSessionConfig{}
	if got := applyIntentCredentialsToSessionConfig(base, nil); got != base {
		t.Error("empty sets should return base unchanged")
	}
}

func TestCloneAgentSessionConfig(t *testing.T) {
	in := &AgentSessionConfig{Sessions: []AgentSessionEntry{
		{
			Name:    "s1",
			Headers: map[string]string{"Authorization": "Bearer x"},
			Login: &AgentLoginFlow{
				URL:     "http://x",
				Extract: []AgentExtractRule{{Source: "json", Path: "$.token"}},
				Expect:  &AgentExpectResponse{Status: []int{200, 201}},
			},
		},
	}}
	out := cloneAgentSessionConfig(in)

	// Deep equality of values...
	if !reflect.DeepEqual(in.Sessions[0].Login.Extract, out.Sessions[0].Login.Extract) {
		t.Error("extract rules not cloned equal")
	}

	// ...but distinct backing arrays/maps.
	out.Sessions[0].Headers["Authorization"] = "tampered"
	if in.Sessions[0].Headers["Authorization"] == "tampered" {
		t.Error("headers map shared between clone and original")
	}
	out.Sessions[0].Login.Expect.Status[0] = 999
	if in.Sessions[0].Login.Expect.Status[0] == 999 {
		t.Error("expect.status slice shared between clone and original")
	}

	if cloneAgentSessionConfig(nil) != nil {
		t.Error("clone of nil should be nil")
	}
}

func TestCloneStringMap(t *testing.T) {
	if got := cloneStringMap(nil); got != nil {
		t.Errorf("clone of nil map should be nil, got %v", got)
	}
	if got := cloneStringMap(map[string]string{}); got != nil {
		t.Errorf("clone of empty map should be nil, got %v", got)
	}
	src := map[string]string{"a": "1", "b": "2"}
	out := cloneStringMap(src)
	if !reflect.DeepEqual(out, src) {
		t.Errorf("clone = %v, want %v", out, src)
	}
	out["a"] = "tampered"
	if src["a"] == "tampered" {
		t.Error("cloned map shares backing with source")
	}
}

func TestWriteAuthConfigYAML(t *testing.T) {
	t.Run("requires session dir", func(t *testing.T) {
		if _, err := WriteAuthConfigYAML("", &AgentSessionConfig{}); err == nil {
			t.Error("empty session dir should error")
		}
	})

	t.Run("nil/empty config yields no file", func(t *testing.T) {
		dir := t.TempDir()
		path, err := WriteAuthConfigYAML(dir, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if path != "" {
			t.Errorf("expected empty path for nil config, got %q", path)
		}
	})

	t.Run("writes yaml with login + extract rules", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &AgentSessionConfig{Sessions: []AgentSessionEntry{
			{
				Name:    "admin",
				Role:    "primary",
				Headers: map[string]string{"X-Api": "v1"},
				Login: &AgentLoginFlow{
					URL:         "http://x/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"u":"a"}`,
					Extract:     []AgentExtractRule{{Source: "json", Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}},
					Expect:      &AgentExpectResponse{Status: []int{200}},
				},
			},
		}}
		path, err := WriteAuthConfigYAML(dir, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if filepath.Base(path) != "auth-config.yaml" {
			t.Errorf("path = %q, want .../auth-config.yaml", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("could not read written file: %v", err)
		}
		content := string(data)
		for _, want := range []string{"admin", "http://x/login", "$.token", "Authorization: Bearer {value}"} {
			if !strings.Contains(content, want) {
				t.Errorf("yaml missing %q:\n%s", want, content)
			}
		}
	})
}

func TestReplaceCredentialKeysAndValues(t *testing.T) {
	set := agenttypes.IntentCredentialSet{Username: "U", Password: "P"}

	obj := map[string]any{"email": "old", "passwd": "old", "untouched": "x"}
	replaceCredentialKeys(obj, set)
	if obj["email"] != "U" || obj["passwd"] != "P" {
		t.Errorf("keys not replaced: %+v", obj)
	}
	if obj["untouched"] != "x" {
		t.Error("non-credential key should be untouched")
	}

	vals := url.Values{"login": {"old"}, "pass": {"old"}, "tok": {"keep"}}
	replaceCredentialValues(vals, set)
	if vals.Get("login") != "U" || vals.Get("pass") != "P" {
		t.Errorf("values not replaced: %v", vals)
	}
	if vals.Get("tok") != "keep" {
		t.Error("non-credential value should be untouched")
	}
}
