package state

import (
	"hash/fnv"
	"math/bits"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Structural near-duplicate detection (MISS-28a). State identity is the exact
// hash of the stripped DOM, so two renderings of the same template that differ
// in a counter, a timestamp or one list item were two states, and the crawl
// spent its budget re-exploring each. StructID is a SimHash over the DOM's
// tag-path shingles: pages built from the same template land within a few bits
// of each other regardless of their text.

// structMaxHamming is the SimHash distance within which two states on the same
// URL template are clones.
const structMaxHamming = 3

// minStructElements is the smallest element count that gets a StructID.
const minStructElements = 30

var tagTokenRe = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9-]*)[^>]*?(/?)>`)

// voidTags never have a closing tag.
var voidTags = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true,
}

// StructSimHash is the 64-bit SimHash of html's tag-path shingles (each
// element's root-to-element tag path is one shingle).
func StructSimHash(html string) uint64 {
	var weights [64]int
	var stack []string
	n := 0
	for _, m := range tagTokenRe.FindAllStringSubmatch(html, -1) {
		closing, tag, selfClose := m[1] == "/", strings.ToLower(m[2]), m[3] == "/"
		if closing {
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i] == tag {
					stack = stack[:i]
					break
				}
			}
			continue
		}
		path := strings.Join(append(stack, tag), "/")
		h := fnv.New64a()
		_, _ = h.Write([]byte(path))
		sum := h.Sum64()
		for b := 0; b < 64; b++ {
			if sum&(1<<uint(b)) != 0 {
				weights[b]++
			} else {
				weights[b]--
			}
		}
		n++
		if !selfClose && !voidTags[tag] {
			stack = append(stack, tag)
		}
	}
	// Too little structure to call two pages the same template: a small DOM
	// (a wizard step, an error page) differs mostly in text, which SimHash
	// ignores, so such pages never fold (StructID 0).
	if n < minStructElements {
		return 0
	}
	var out uint64
	for b := 0; b < 64; b++ {
		if weights[b] > 0 {
			out |= 1 << uint(b)
		}
	}
	return out
}

// StructHamming is the bit distance between two StructIDs.
func StructHamming(a, b uint64) int { return bits.OnesCount64(a ^ b) }

var idSegmentRe = regexp.MustCompile(`^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$`)

// URLTemplate is rawURL's scheme://host/path with id-like path segments
// replaced by "{}" and the query and fragment dropped, so /users/1 and
// /users/2 share a template.
func URLTemplate(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if s != "" && idSegmentRe.MatchString(s) {
			segs[i] = "{}"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.Join(segs, "/")
}

// structBucket keys the near-duplicate index: URL template plus the top 16
// SimHash bits.
func structBucket(rawURL string, structID uint64) string {
	return URLTemplate(rawURL) + "\x00" + strconv.FormatUint(structID>>48, 16)
}

// SameStructure reports whether a live stripped DOM is the state's page: the
// same stripped DOM, or a structural clone of it.
func SameStructure(liveStripped string, s *State) bool {
	if s == nil {
		return false
	}
	if liveStripped == s.StrippedDOM {
		return true
	}
	return s.StructID != 0 && StructHamming(StructSimHash(liveStripped), s.StructID) <= structMaxHamming
}
