package parammine

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
)

// BuiltinWordlistName is the embedded list of common parameter names, also
// printable with `vigolium kit wordlist params`.
//
// It is curated in-repo rather than copied from a third-party list (Arjun's is
// GPL-3): generic names web frameworks and APIs commonly read (debug, callback,
// redirect_uri, …), the parameter names the scanner's own modules already probe
// (xss_light_scanner discovery, open-redirect, LFI, SSRF, OAuth, LDAP, IDOR),
// and common entity names with their id/name/type suffixes (user_id, orderId).
const BuiltinWordlistName = "params.txt"

// BuiltinHeaderWordlistName is the embedded list of request header names
// mined under LocationHeader (`vigolium kit wordlist headers`): override,
// routing, client-address, identity and debug headers, curated in-repo.
const BuiltinHeaderWordlistName = "headers.txt"

// maxNameLen bounds a usable parameter name; longer entries are noise.
const maxNameLen = 64

var (
	builtinOnce  sync.Once
	builtinNames []string
	builtinErr   error
)

// Builtin returns the embedded parameter-name list, parsed once.
func Builtin() ([]string, error) {
	builtinOnce.Do(func() {
		data, err := wordlists.ReadList(BuiltinWordlistName)
		if err != nil {
			builtinErr = err
			return
		}
		builtinNames = ParseNames(data)
	})
	return builtinNames, builtinErr
}

var (
	builtinHeadersOnce sync.Once
	builtinHeaderNames []string
	builtinHeadersErr  error
)

// BuiltinHeaders returns the embedded header-name list, parsed once.
func BuiltinHeaders() ([]string, error) {
	builtinHeadersOnce.Do(func() {
		data, err := wordlists.ReadList(BuiltinHeaderWordlistName)
		if err != nil {
			builtinHeadersErr = err
			return
		}
		builtinHeaderNames = ParseNames(data)
	})
	return builtinHeaderNames, builtinHeadersErr
}

// ReadWordlistFile reads a one-name-per-line file ("#" comments allowed).
func ReadWordlistFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseNames(data), nil
}

// ParseNames splits a one-name-per-line list, skipping blanks, comments and
// unusable names.
func ParseNames(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !ValidName(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ValidName reports whether s can be sent as a parameter name: non-empty,
// bounded, and free of whitespace, control characters and the separators that
// would split it into something else.
func ValidName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("&=?#\"\\", r) {
			return false
		}
	}
	return true
}

// MergeWordlists concatenates the sources in priority order, dropping invalid
// names and duplicates (first occurrence wins), and stops at max names when max
// is positive. Put the names most likely to matter first: the ones the target's
// own JavaScript and traffic use, then the built-in list.
func MergeWordlists(max int, sources ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, src := range sources {
		for _, n := range src {
			n = strings.TrimSpace(n)
			if !ValidName(n) || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
			if max > 0 && len(out) >= max {
				return out
			}
		}
	}
	return out
}
