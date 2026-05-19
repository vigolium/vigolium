package terminal

import (
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AsciiMascots is the shared pool of banner prefixes used in place of a
// single glyph (e.g. ϟ). Each call to RandomMascot picks one at random so
// repeat launches feel less monotonous.
var AsciiMascots = []string{
	`\|/(o)\|/`,
	`<\_<o>_/>`,
	`+<\[o]/>+`,
	`:/\(*)/\:`,
	`<-<(o)>->`,
	`:_/(o)\_:`,
	`<\|<o>|/>`,
	`+\_(*)_/+`,
}

// MascotWidth is the visual width that every rendered mascot is padded
// out to — computed as the longest entry in AsciiMascots. ColoredMascot
// right-pads shorter mascots with spaces up to this width so banner text
// after the mascot lines up regardless of which one was picked.
// All mascots are pure ASCII, so byte length == display width.
var MascotWidth = func() int {
	max := 0
	for _, m := range AsciiMascots {
		if len(m) > max {
			max = len(m)
		}
	}
	return max
}()

// MascotEyePattern matches the "eye" in an ASCII mascot — the centerpiece
// that gets the accent color in ColoredMascot. Ordered longest-first so
// `<(o)>` wins over `(o)`.
var MascotEyePattern = regexp.MustCompile(`<\(o\)>|\(o\)|<o>|\[o\]|\(\*\)`)

var (
	mascotRNG   = rand.New(rand.NewSource(time.Now().UnixNano()))
	mascotRNGMu sync.Mutex
)

// RandomMascot returns a random entry from AsciiMascots. Safe for
// concurrent use.
func RandomMascot() string {
	mascotRNGMu.Lock()
	defer mascotRNGMu.Unlock()
	return AsciiMascots[mascotRNG.Intn(len(AsciiMascots))]
}

// ColoredMascot renders m with two colors: `eye` is applied to the
// mascot's centerpiece (matched by MascotEyePattern) and `body` wraps
// the surrounding frame. Keeping it to two colors reads as a coherent
// creature rather than rainbow noise. The output is right-padded with
// plain spaces to MascotWidth so successive renders occupy the same
// visual column.
func ColoredMascot(m string, body, eye func(string) string) string {
	if m == "" {
		return strings.Repeat(" ", MascotWidth)
	}
	var out strings.Builder
	locs := MascotEyePattern.FindAllStringIndex(m, -1)
	if len(locs) == 0 {
		out.WriteString(body(m))
	} else {
		idx := 0
		for _, loc := range locs {
			if loc[0] > idx {
				out.WriteString(body(m[idx:loc[0]]))
			}
			out.WriteString(eye(m[loc[0]:loc[1]]))
			idx = loc[1]
		}
		if idx < len(m) {
			out.WriteString(body(m[idx:]))
		}
	}
	if pad := MascotWidth - len(m); pad > 0 {
		out.WriteString(strings.Repeat(" ", pad))
	}
	return out.String()
}
