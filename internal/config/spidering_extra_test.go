package config

import (
	"slices"
	"strings"
	"testing"
)

func TestSpideringWidenOnlyExtras(t *testing.T) {
	c := DefaultSpideringConfig()
	if c.DenyClickExtraPattern() != "" || len(c.EffectiveExcludeSelectors()) != len(c.ExcludeSelectors) {
		t.Fatal("no extras: nothing added")
	}
	c.ExcludeSelectors = []string{"#a"}
	c.ExcludeSelectorsExtra = []string{"#b"}
	if got := c.EffectiveExcludeSelectors(); !slices.Equal(got, []string{"#a", "#b"}) {
		t.Errorf("EffectiveExcludeSelectors = %q", got)
	}
	c.DenyClickExtra = []string{"pay|send", "  ", "approve"}
	if got := c.DenyClickExtraPattern(); got != "(?:pay|send)|(?:approve)" {
		t.Errorf("DenyClickExtraPattern = %q", got)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid extras rejected: %v", err)
	}
	c.DenyClickExtra = []string{"ok", "(unclosed"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "spidering.deny_click_extra[1]") {
		t.Fatalf("an invalid extra regex must fail validation naming its index, got %v", err)
	}
}

// An extra that matches the empty string would refuse every control: it is a
// validation error naming its index, like an invalid one.
func TestSpideringDenyClickExtraRejectsEmptyMatch(t *testing.T) {
	for _, p := range []string{".*", "a*", "pay|", "(?:)", "^"} {
		c := DefaultSpideringConfig()
		c.DenyClickExtra = []string{"ok", p}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "spidering.deny_click_extra[1]") || !strings.Contains(err.Error(), "empty string") {
			t.Errorf("%q: want an empty-match validation error naming index 1, got %v", p, err)
		}
	}
	c := DefaultSpideringConfig()
	c.DenyClickExtra = []string{"pay+", "a.+b"}
	if err := c.Validate(); err != nil {
		t.Errorf("patterns that need text rejected: %v", err)
	}
}
