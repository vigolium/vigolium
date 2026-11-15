package stream

import (
	"errors"
	"strings"
)

// ErrProviderUnreachable marks a provider whose endpoint refused the
// connection or whose name did not resolve before any call to it had
// succeeded. Retrying such an error only waits out the deadline: nothing is
// listening, or the name is wrong.
var ErrProviderUnreachable = errors.New("provider unreachable")

// dialErrSubstrings are the transient-list entries that mean "never
// connected" rather than "connection dropped".
var dialErrSubstrings = []string{"connection refused", "no such host"}

// IsDialErr reports whether err is a failure to connect at all: a refused
// connection or an unresolvable name.
func IsDialErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrProviderUnreachable) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range dialErrSubstrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}
