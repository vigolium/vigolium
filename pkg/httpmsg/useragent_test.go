package httpmsg

import "testing"

// reset restores the process-global UA state so each subtest is independent.
func reset() {
	uaMu.Lock()
	uaOverride = ""
	buildVersion = ""
	uaMu.Unlock()
}

func TestDefaultUserAgent_BuiltinWhenUnset(t *testing.T) {
	reset()
	if got := DefaultUserAgent(); got != BuiltinUserAgent {
		t.Fatalf("unset override: got %q, want builtin %q", got, BuiltinUserAgent)
	}
}

func TestSetDefaultUserAgent_EmptyIsNoOp(t *testing.T) {
	reset()
	SetDefaultUserAgent("   ") // blank must not clobber the builtin default
	if got := DefaultUserAgent(); got != BuiltinUserAgent {
		t.Fatalf("blank override should be ignored: got %q, want %q", got, BuiltinUserAgent)
	}
}

func TestSetDefaultUserAgent_OverrideWins(t *testing.T) {
	reset()
	const ua = "Mozilla/5.0 (compatible; Vigolium; +https://github.com/vigolium/vigolium)"
	SetDefaultUserAgent("  " + ua + "  ") // surrounding whitespace is trimmed
	if got := DefaultUserAgent(); got != ua {
		t.Fatalf("override: got %q, want %q", got, ua)
	}
}

func TestDefaultUserAgent_VersionPlaceholderExpansion(t *testing.T) {
	reset()
	SetBuildVersion("v9.9.9")
	SetDefaultUserAgent("Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)")
	want := "Mozilla/5.0 (compatible; Vigolium/v9.9.9; +https://github.com/vigolium/vigolium)"
	if got := DefaultUserAgent(); got != want {
		t.Fatalf("version expansion: got %q, want %q", got, want)
	}
}

func TestDefaultUserAgent_VersionPlaceholderFallsBackToDev(t *testing.T) {
	reset()
	SetDefaultUserAgent("Vigolium/{version}")
	if got := DefaultUserAgent(); got != "Vigolium/dev" {
		t.Fatalf("empty build version: got %q, want %q", got, "Vigolium/dev")
	}
}
