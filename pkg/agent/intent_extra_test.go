package agent

import (
	"testing"
)

func TestNeedsAgentSetup(t *testing.T) {
	t.Run("git repo URL triggers setup", func(t *testing.T) {
		if !needsAgentSetup("scan github.com/org/repo for bugs") {
			t.Error("github URL should require agent setup")
		}
		if !needsAgentSetup("clone gitlab.com/foo/bar") {
			t.Error("gitlab URL should require agent setup")
		}
	})

	t.Run("setup keywords trigger setup", func(t *testing.T) {
		for _, p := range []string{
			"docker compose up the app then scan",
			"set up the environment first",
			"build and run the project",
			"deploy it and test",
			"start the app on port 8080",
		} {
			if !needsAgentSetup(p) {
				t.Errorf("%q should require agent setup", p)
			}
		}
	})

	t.Run("plain target does not trigger setup", func(t *testing.T) {
		if needsAgentSetup("scan http://localhost:3000 for xss") {
			t.Error("plain URL should not require agent setup")
		}
	})
}

func TestParseSDKIntentOutput(t *testing.T) {
	t.Run("uses INTENT_JSON marker", func(t *testing.T) {
		out := "I cloned the repo and started docker.\n\nINTENT_JSON:\n" +
			`{"apps":[{"target":"http://localhost:3005","source_path":"/repos/app"}],"cleanup":{"docker_projects":["app"]}}`
		intent, err := parseSDKIntentOutput(out)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(intent.Apps) != 1 || intent.Apps[0].Target != "http://localhost:3005" {
			t.Fatalf("apps not parsed: %+v", intent.Apps)
		}
		if intent.Cleanup == nil || len(intent.Cleanup.DockerProjects) != 1 {
			t.Errorf("cleanup not parsed: %+v", intent.Cleanup)
		}
	})

	t.Run("falls back to extractJSON without marker", func(t *testing.T) {
		out := "Here is the result:\n```json\n" +
			`{"apps":[{"source_path":"/repos/only"}]}` + "\n```"
		intent, err := parseSDKIntentOutput(out)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(intent.Apps) != 1 || intent.Apps[0].SourcePath != "/repos/only" {
			t.Fatalf("apps not parsed via fallback: %+v", intent.Apps)
		}
	})

	t.Run("no JSON anywhere errors", func(t *testing.T) {
		if _, err := parseSDKIntentOutput("I could not complete the setup."); err == nil {
			t.Error("expected error when no JSON present")
		}
	})
}

func TestParseIntentJSONWithCleanup_ExpandsHome(t *testing.T) {
	intent, err := parseIntentJSONWithCleanup(`{"apps":[{"source_path":"~/code/app"}]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(intent.Apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(intent.Apps))
	}
	// ~ should be expanded to an absolute path.
	if got := intent.Apps[0].SourcePath; got == "~/code/app" || got == "" || got[0] != '/' {
		t.Errorf("source path not home-expanded: %q", got)
	}
}

func TestResolveIntentApps_SourceOnlyCodeAudit(t *testing.T) {
	// A source-only app with a nonexistent path (so DetectTargetFromSource
	// returns "") must flip code_audit on and leave discover off.
	intent := &ScanIntent{
		Apps: []AppIntent{{SourcePath: "/definitely/not/a/real/path/xyz"}},
	}
	resolved := ResolveIntentApps(intent)
	app := resolved.Apps[0]
	if !app.CodeAudit {
		t.Error("source-only with no detectable target should set code_audit")
	}
	if app.Discover {
		t.Error("source-only should not set discover")
	}
	if app.Target != "" {
		t.Errorf("target should remain empty, got %q", app.Target)
	}
}
