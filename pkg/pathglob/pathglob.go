// Package pathglob matches URL paths against scope globs.
//
// filepath.Match is a file-name matcher: its "*" stops at "/", so the sample
// config's `/api/*` never excluded `/api/users/1`, and it was handed paths that
// still carried the query string, so an exclude of `/logout` missed
// `/logout?next=/`. Scope rules mean URL paths: "*" crosses "/", "**" is a
// synonym kept for operators who write it, and the query/fragment is never
// part of the subject.
package pathglob

import (
	"regexp"
	"strings"
	"sync"
)

// ScopePath returns p without its query string or fragment.
func ScopePath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

var cache sync.Map // pattern -> *regexp.Regexp (nil for an invalid pattern)

// Match reports whether path matches pattern. "*" (and "**") match any run of
// characters including "/", "?" matches one character, "[...]" is a character
// class ("[!...]" negated). Matching is exact (anchored) and case-sensitive;
// callers lowercase both sides when they want case-insensitivity. An invalid
// pattern matches nothing.
func Match(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	re := compile(pattern)
	return re != nil && re.MatchString(path)
}

func compile(pattern string) *regexp.Regexp {
	if v, ok := cache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	var b strings.Builder
	b.WriteString(`\A`)
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			for i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
			}
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end < 0 {
				cache.Store(pattern, (*regexp.Regexp)(nil))
				return nil
			}
			class := pattern[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += end + 1
		case '\\':
			if i+1 < len(pattern) {
				i++
				b.WriteString(regexp.QuoteMeta(string(pattern[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`\z`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		re = nil
	}
	cache.Store(pattern, re)
	return re
}
