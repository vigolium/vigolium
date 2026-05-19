package nextjs_chunk_audit

import (
	"regexp"
	"sort"
	"strings"
)

var (
	chunkRefRe = regexp.MustCompile(`/_next/static/chunks/[A-Za-z0-9._/\-]+\.js`)

	absoluteURLRe = regexp.MustCompile(`https?://[A-Za-z0-9._\-]+(?:\:[0-9]+)?(?:/[^\s"'<>` + "`" + `\\)]*)?`)

	// SYNC WITH pkg/modules/passive/sourcemap_detect/scanner.go (sourceMappingRe).
	sourceMapRefRe = regexp.MustCompile(`(?m)^[ \t/*]*[#@]\s*sourceMappingURL=\s*([^\s*]+)`)
)

func ExtractChunkPaths(body []byte) []string {
	return uniqueSortedMatches(body, chunkRefRe, nil)
}

func ExtractAbsoluteURLs(body []byte) []string {
	return uniqueSortedMatches(body, absoluteURLRe, trimURLTail)
}

func ExtractSourceMapRefs(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	matches := sourceMapRefRe.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		ref := strings.TrimSpace(string(m[1]))
		if ref == "" {
			continue
		}
		seen[ref] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedMatches(body []byte, re *regexp.Regexp, transform func(string) string) []string {
	if len(body) == 0 {
		return nil
	}
	matches := re.FindAll(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		s := string(m)
		if transform != nil {
			s = transform(s)
		}
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func trimURLTail(u string) string {
	for len(u) > 0 {
		last := u[len(u)-1]
		switch last {
		case '.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"', '`':
			u = u[:len(u)-1]
		default:
			return u
		}
	}
	return u
}
