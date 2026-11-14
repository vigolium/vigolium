package httpmsg

import (
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in    string
		want  time.Duration
		found bool
	}{
		{"", 0, false},
		{"5", 5 * time.Second, true},
		{" 0 ", 0, true},
		{"-3", 0, false},
		{"soon", 0, false},
		{now.Add(7 * time.Second).Format(http.TimeFormat), 7 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
		{"99999999999", 24 * time.Hour, true},
	}
	for _, tc := range cases {
		got, found := ParseRetryAfter(tc.in, now)
		if got != tc.want || found != tc.found {
			t.Errorf("ParseRetryAfter(%q) = %v, %v; want %v, %v", tc.in, got, found, tc.want, tc.found)
		}
	}
}
