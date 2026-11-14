package httpmsg

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxRetryAfter caps a delay-seconds Retry-After so an absurd value cannot
// overflow time.Duration.
const maxRetryAfter = 24 * time.Hour

// ParseRetryAfter reads a Retry-After value (RFC 9110 §10.2.3): delay-seconds
// (capped at 24h) or an HTTP-date relative to now. found is false for an
// empty, negative or unparseable value; a date in the past is a zero wait
// that was found.
func ParseRetryAfter(v string, now time.Time) (wait time.Duration, found bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second, true
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}
