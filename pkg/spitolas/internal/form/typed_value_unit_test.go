package form

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// hhmmToMinutes parses "HH:MM" into minutes since midnight for range assertions.
func hhmmToMinutes(s string) int {
	var hh, mm int
	if _, err := fmt.Sscanf(s, "%d:%d", &hh, &mm); err != nil {
		return -1
	}
	return hh*60 + mm
}

// TestTypedFormatValue covers the type→value table: strict HTML5 types get a
// format-valid value; types resolved by name (text/search) or fixed credentials
// (email/password) return "" so the smart/default steps still own them.
func TestTypedFormatValue(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	want := map[action.InputType]string{
		action.InputTypeURL:    "https://example.com",
		action.InputTypeTel:    "+15555555555",
		action.InputTypeNumber: "42",
		action.InputTypeRange:  "50",
		action.InputTypeColor:  "#000000",
		action.InputTypeDate:   "2024-06-15",
		action.InputTypeTime:   "12:00",
	}
	for typ, exp := range want {
		if got := h.typedFormatValue(typ); got != exp {
			t.Errorf("typedFormatValue(%s) = %q, want %q", typ, got, exp)
		}
	}

	for _, typ := range []action.InputType{
		action.InputTypeText, action.InputTypeEmail, action.InputTypePassword,
		action.InputTypeSearch, action.InputTypeTextarea, action.InputTypeSelect,
		action.InputTypeFile, action.InputTypeCheckbox, action.InputTypeRadio,
		action.InputTypeHidden,
	} {
		if got := h.typedFormatValue(typ); got != "" {
			t.Errorf("typedFormatValue(%s) = %q, want empty (resolved elsewhere)", typ, got)
		}
	}
}

// TestTypedValuesAreFormatValid asserts the emitted values actually satisfy the
// format the browser would validate — the whole point is that a form with these
// fields submits instead of stalling.
func TestTypedValuesAreFormatValid(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	u, err := url.Parse(h.typedFormatValue(action.InputTypeURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		t.Errorf("url value not a valid absolute URL: %v", err)
	}
	if !regexp.MustCompile(`^#[0-9a-fA-F]{6}$`).MatchString(h.typedFormatValue(action.InputTypeColor)) {
		t.Errorf("color value not #rrggbb: %q", h.typedFormatValue(action.InputTypeColor))
	}
	if !regexp.MustCompile(`^\+[0-9]{7,15}$`).MatchString(h.typedFormatValue(action.InputTypeTel)) {
		t.Errorf("tel value not E.164-ish: %q", h.typedFormatValue(action.InputTypeTel))
	}
	if _, err := strconv.Atoi(h.typedFormatValue(action.InputTypeNumber)); err != nil {
		t.Errorf("number value not an integer: %q", h.typedFormatValue(action.InputTypeNumber))
	}
	if _, err := strconv.Atoi(h.typedFormatValue(action.InputTypeRange)); err != nil {
		t.Errorf("range value not an integer: %q", h.typedFormatValue(action.InputTypeRange))
	}
	if _, err := time.Parse("2006-01-02", h.typedFormatValue(action.InputTypeDate)); err != nil {
		t.Errorf("date value not YYYY-MM-DD: %q", h.typedFormatValue(action.InputTypeDate))
	}
	if _, err := time.Parse("15:04", h.typedFormatValue(action.InputTypeTime)); err != nil {
		t.Errorf("time value not HH:MM: %q", h.typedFormatValue(action.InputTypeTime))
	}
}

// TestGetValueForInputTypedInputs walks the full getValueForInput pipeline for
// bare typed inputs with an UNMATCHED name (the case that used to fall to "a"),
// and confirms name-based / fixed-credential resolution still wins for the
// non-strict types.
func TestGetValueForInputTypedInputs(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	strict := []struct {
		typ   action.InputType
		valid func(string) bool
	}{
		{action.InputTypeURL, func(v string) bool { u, e := url.Parse(v); return e == nil && u.Host != "" }},
		{action.InputTypeDate, func(v string) bool { _, e := time.Parse("2006-01-02", v); return e == nil }},
		{action.InputTypeTime, func(v string) bool { _, e := time.Parse("15:04", v); return e == nil }},
		{action.InputTypeColor, func(v string) bool { return regexp.MustCompile(`^#[0-9a-fA-F]{6}$`).MatchString(v) }},
		{action.InputTypeNumber, func(v string) bool { _, e := strconv.Atoi(v); return e == nil }},
		{action.InputTypeTel, func(v string) bool { return regexp.MustCompile(`^\+?[0-9]+$`).MatchString(v) }},
		{action.InputTypeRange, func(v string) bool { _, e := strconv.Atoi(v); return e == nil }},
	}
	for _, tc := range strict {
		got := h.getValueForInput(detectedInput(tc.typ, "xyzzy_unmatched_field"))
		if got == "a" || got == "" || !tc.valid(got) {
			t.Errorf("getValueForInput(bare %s) = %q, want a format-valid value (not 'a')", tc.typ, got)
		}
	}

	// Non-strict types keep their existing name-based resolution; typedFormatValue
	// must NOT hijack email/password (they stay the fixed credentials so a
	// multi-step login flow uses one coherent identity).
	if got := h.getValueForInput(detectedInput(action.InputTypeEmail, "email")); got != FixedEmail {
		t.Errorf("getValueForInput(email named email) = %q, want FixedEmail %q", got, FixedEmail)
	}
	if got := h.getValueForInput(detectedInput(action.InputTypePassword, "password")); got != FixedPassword {
		t.Errorf("getValueForInput(password named password) = %q, want FixedPassword %q", got, FixedPassword)
	}
	if got := h.getValueForInput(detectedInput(action.InputTypeText, "xyzzy_unmatched_field")); got != "a" {
		t.Errorf("getValueForInput(bare text) = %q, want fallback 'a'", got)
	}
	// A name-matched URL field keeps the smart value (also valid) — type default
	// never makes a matched field worse.
	if got := h.getValueForInput(detectedInput(action.InputTypeURL, "website")); got == "a" || got == "" {
		t.Errorf("getValueForInput(url named website) = %q, want a URL", got)
	}
}

// TestGetValueForInputRandomModeTyped: even in random fill mode, strict typed
// inputs must get a format-valid value (typedFormatValue runs before the random
// branch), otherwise a randomized URL/date field fails validation.
func TestGetValueForInputRandomModeTyped(t *testing.T) {
	h := newTestHandler(config.FormFillRandom)

	if v := h.getValueForInput(detectedInput(action.InputTypeURL, "x")); v != "https://example.com" {
		t.Errorf("random-mode url = %q, want format-valid default", v)
	}
	if v := h.getValueForInput(detectedInput(action.InputTypeDate, "x")); v != "2024-06-15" {
		t.Errorf("random-mode date = %q, want format-valid default", v)
	}
}

func TestGenerateDateInRange(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	const layout = "2006-01-02"
	min := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	max := time.Date(2024, 3, 10, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 40; i++ {
		v := h.generateDateInRange("2024-03-01", "2024-03-10")
		d, err := time.Parse(layout, v)
		if err != nil {
			t.Fatalf("invalid date %q: %v", v, err)
		}
		if d.Before(min) || d.After(max) {
			t.Errorf("date %q out of [%s,%s]", v, min, max)
		}
	}

	// Reversed bounds are normalized.
	if v := h.generateDateInRange("2024-03-10", "2024-03-01"); v < "2024-03-01" || v > "2024-03-10" {
		t.Errorf("reversed-bound date %q out of range", v)
	}
	// Single-bound and single-day cases.
	if v := h.generateDateInRange("2024-05-05", ""); v != "2024-05-05" {
		t.Errorf("min-only date = %q, want 2024-05-05", v)
	}
	if v := h.generateDateInRange("", "2024-07-07"); v != "2024-07-07" {
		t.Errorf("max-only date = %q, want 2024-07-07", v)
	}
	if v := h.generateDateInRange("2024-06-15", "2024-06-15"); v != "2024-06-15" {
		t.Errorf("single-day date = %q, want 2024-06-15", v)
	}
	// Unparseable falls back to the default.
	if v := h.generateDateInRange("nonsense", ""); v != defaultDateValue {
		t.Errorf("invalid date bounds = %q, want default %q", v, defaultDateValue)
	}
}

func TestGenerateTimeInRange(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)
	lo, hi := hhmmToMinutes("09:00"), hhmmToMinutes("17:00")

	re := regexp.MustCompile(`^\d{2}:\d{2}$`)
	for i := 0; i < 40; i++ {
		v := h.generateTimeInRange("09:00", "17:00")
		if !re.MatchString(v) {
			t.Fatalf("time %q not HH:MM", v)
		}
		if m := hhmmToMinutes(v); m < lo || m > hi {
			t.Errorf("time %q (%d) out of [%d,%d]", v, m, lo, hi)
		}
	}

	if v := h.generateTimeInRange("08:30", ""); v != "08:30" {
		t.Errorf("min-only time = %q, want 08:30", v)
	}
	if v := h.generateTimeInRange("", "22:15"); v != "22:15" {
		t.Errorf("max-only time = %q, want 22:15", v)
	}
	if v := h.generateTimeInRange("bad", "bad"); v != defaultTimeValue {
		t.Errorf("invalid time bounds = %q, want default %q", v, defaultTimeValue)
	}
}

// TestConstrainedRangeAndTypedRouting confirms generateConstrainedValue now
// honors range/date/time min-max and yields in-range, valid values.
func TestConstrainedRangeAndTypedRouting(t *testing.T) {
	h := newTestHandler(config.FormFillNormal)

	// Range input with min/max routes through the numeric range generator.
	rng := detectedInput(action.InputTypeRange, "vol")
	rng.Min, rng.Max, rng.Step = "10", "20", "1"
	v := h.generateConstrainedValue(rng)
	n, err := strconv.Atoi(v)
	if err != nil || n < 10 || n > 20 {
		t.Errorf("range constrained = %q, want integer in [10,20]", v)
	}

	// Date with min/max.
	d := detectedInput(action.InputTypeDate, "dob")
	d.Min, d.Max = "2020-01-01", "2020-01-31"
	if got := h.generateConstrainedValue(d); got < "2020-01-01" || got > "2020-01-31" {
		t.Errorf("date constrained = %q, want in [2020-01-01,2020-01-31]", got)
	}

	// No-constraint strict types yield "" from generateConstrainedValue (so the
	// pipeline falls through to typedFormatValue).
	if got := h.generateConstrainedValue(detectedInput(action.InputTypeDate, "x")); got != "" {
		t.Errorf("unconstrained date = %q, want empty from generateConstrainedValue", got)
	}
}
