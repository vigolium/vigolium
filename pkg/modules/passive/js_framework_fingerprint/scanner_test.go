package js_framework_fingerprint

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestBuildIDExtraction(t *testing.T) {
	tests := []struct {
		body    string
		want    string
		wantHit bool
	}{
		{`"buildId":"abc123def"`, "abc123def", true},
		{`"buildId": "xyz-789"`, "xyz-789", true},
		{`no build id here`, "", false},
	}

	for _, tt := range tests {
		m := jsframework.BuildIDRegex.FindStringSubmatch(tt.body)
		if tt.wantHit {
			if len(m) < 2 || m[1] != tt.want {
				t.Errorf("body=%q: got %v, want %q", tt.body, m, tt.want)
			}
		} else {
			if len(m) > 1 {
				t.Errorf("body=%q: unexpected match %q", tt.body, m[1])
			}
		}
	}
}

func TestAppRouterDetection(t *testing.T) {
	if !appRouterPattern.MatchString(`/_next/static/chunks/app/layout.js`) {
		t.Error("expected App Router pattern to match")
	}
	if appRouterPattern.MatchString(`/_next/static/chunks/pages/index.js`) {
		t.Error("expected App Router pattern NOT to match Pages Router path")
	}
}
