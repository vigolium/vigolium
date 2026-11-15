package clicommon

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TimeFilterSyntax is the one-line grammar summary shared by every --from/--to
// help string, so the accepted forms read identically on each command.
const TimeFilterSyntax = `2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a time without a zone is local, results print in UTC`

// TimeFilterUpperBoundNote states the end-of-day contract that upper bounds
// apply. Declared once so every --to/--until help string describes it the same
// way — it is a behavioural promise, not incidental wording.
const TimeFilterUpperBoundNote = "a bare date covers the whole day"

// timeSpec is a parsed time-filter value: an instant, plus whether the input
// named a whole calendar day rather than a precise moment.
type timeSpec struct {
	t time.Time
	// dayOnly marks a value that named a day ("today", "2026-08-05") rather
	// than a moment. An upper bound snaps such a value to the END of that day:
	// a bare "--to 2026-08-05" means "through the 5th", and resolving it to the
	// 5th at 00:00 would silently drop every record from the day the user named.
	dayOnly bool
}

// relativeUnits maps a relative-offset suffix onto its duration. Go's
// time.ParseDuration stops at hours, so d/w are resolved here. "m" stays
// minutes (Go's meaning) and months are deliberately absent: a unit that means
// "month" in some tools and "minute" in others is exactly the ambiguity a
// filter which silently returns the wrong rows must not have.
//
// Only singular spellings are listed; parseRelativeOffset retries with a
// trailing "s" stripped, so "days"/"mins" resolve without doubling the table.
var relativeUnits = map[string]time.Duration{
	"s": time.Second, "sec": time.Second, "second": time.Second,
	"m": time.Minute, "min": time.Minute, "minute": time.Minute,
	"h": time.Hour, "hr": time.Hour, "hour": time.Hour,
	"d": 24 * time.Hour, "day": 24 * time.Hour,
	"w": 7 * 24 * time.Hour, "week": 7 * 24 * time.Hour,
}

// lookupUnit resolves a unit suffix, accepting the plural of any listed form.
//
// The plural retry never strips down to a single letter: "ms" would otherwise
// read as the plural of "m" and silently turn 500 milliseconds into 500 minutes.
// Go's sub-second units (ms/us/ns) all have that shape, so the length guard is
// what keeps them falling through to time.ParseDuration.
func lookupUnit(u string) (time.Duration, bool) {
	if d, ok := relativeUnits[u]; ok {
		return d, true
	}
	if singular, cut := strings.CutSuffix(u, "s"); cut && len(singular) > 1 {
		d, ok := relativeUnits[singular]
		return d, ok
	}
	return 0, false
}

// relativeRe matches a single-unit relative offset ("2d", "30 mins").
var relativeRe = regexp.MustCompile(`^(\d+)\s*([a-z]+)$`)

// localLayouts are the absolute forms parsed in the LOCAL zone. A user typing a
// wall-clock date means their own midnight, not UTC's — resolving "2026-08-05"
// to UTC midnight drops the first hours of the local day east of Greenwich and
// pulls in the tail of the previous day west of it.
var localLayouts = []struct {
	layout  string
	dayOnly bool
}{
	{"2006-01-02", true},
	{"2006-01-02 15:04", false},
	{"2006-01-02T15:04", false},
	{"2006-01-02 15:04:05", false},
	{"2006-01-02T15:04:05", false},
}

// ParseSince resolves a lower-bound time filter (--from / --since) into the
// instant the range opens. See TimeFilterSyntax for the accepted forms.
func ParseSince(s string) (time.Time, error) {
	return parseBoundAt(s, time.Now(), false)
}

// ParseUntil resolves an upper-bound time filter (--to / --until) into the
// instant the range closes. A whole-day value closes at the END of that day.
func ParseUntil(s string) (time.Time, error) {
	return parseBoundAt(s, time.Now(), true)
}

// parseBoundAt resolves s against a caller-supplied "now" so the relative forms
// are testable.
func parseBoundAt(s string, now time.Time, upper bool) (time.Time, error) {
	spec, err := parseTimeSpecAt(s, now)
	if err != nil {
		return time.Time{}, err
	}
	if upper && spec.dayOnly {
		return endOfDay(spec.t), nil
	}
	return spec.t, nil
}

func parseTimeSpecAt(s string, now time.Time) (timeSpec, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return timeSpec{}, fmt.Errorf("empty time value (want %s)", TimeFilterSyntax)
	}

	// Relative and keyword forms are case-insensitive and tolerate the "ago"
	// people naturally append ("2 days ago"); absolute layouts keep the raw text.
	rel := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(raw), " ago"))
	rel = strings.TrimPrefix(rel, "-")

	switch rel {
	case "now":
		return timeSpec{t: now}, nil
	case "today":
		return timeSpec{t: startOfDay(now), dayOnly: true}, nil
	case "yesterday":
		return timeSpec{t: startOfDay(now.AddDate(0, 0, -1)), dayOnly: true}, nil
	}

	if d, ok := parseRelativeOffset(rel); ok {
		return timeSpec{t: now.Add(-d)}, nil
	}

	for _, l := range localLayouts {
		if t, err := time.ParseInLocation(l.layout, raw, now.Location()); err == nil {
			return timeSpec{t: t, dayOnly: l.dayOnly}, nil
		}
	}
	// RFC3339 carries its own offset, so it is parsed as written.
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return timeSpec{t: t}, nil
	}

	return timeSpec{}, fmt.Errorf("unrecognized time %q (want %s)", s, TimeFilterSyntax)
}

// parseRelativeOffset resolves an offset back from now ("2d", "1h30m").
func parseRelativeOffset(s string) (time.Duration, bool) {
	if m := relativeRe.FindStringSubmatch(s); m != nil {
		if unit, ok := lookupUnit(m[2]); ok {
			n, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil || n > math.MaxInt64/int64(unit) {
				return 0, false
			}
			return time.Duration(n) * unit, true
		}
		// Not one of our units — it may still be a Go-native one ("500ms"),
		// so fall through rather than rejecting here.
	}
	// Compound Go durations ("1h30m") and sub-second units.
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return d, true
	}
	return 0, false
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// endOfDay returns the last representable instant of t's day, so an inclusive
// "<= bound" comparison covers the whole day.
func endOfDay(t time.Time) time.Time {
	return startOfDay(t).AddDate(0, 0, 1).Add(-time.Nanosecond)
}

// FormatTimeFilter renders a resolved bound for the "Filtered by:" echo: a bare
// date when the bound sits on a day boundary, otherwise date + time. A relative
// value like "--since 2h" would otherwise print as a bare date it is not.
func FormatTimeFilter(t time.Time) string {
	local := t.Local()
	if local.Equal(startOfDay(local)) || local.Equal(endOfDay(local)) {
		return local.Format("2006-01-02")
	}
	return local.Format("2006-01-02 15:04")
}
