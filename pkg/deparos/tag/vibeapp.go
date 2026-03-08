package tag

import (
	"unicode/utf8"
)

// VibeAppMatcher detects emojis in response body.
// Indicates an app-like web page with emoji content.
type VibeAppMatcher struct{}

// NewVibeAppMatcher creates a new VibeApp matcher.
func NewVibeAppMatcher() *VibeAppMatcher {
	return &VibeAppMatcher{}
}

// Tag returns the tag this matcher detects.
func (m *VibeAppMatcher) Tag() Tag {
	return TagVibeApp
}

// Match returns true if response body contains emojis.
func (m *VibeAppMatcher) Match(input *MatchInput) bool {
	if len(input.ResponseBody) == 0 {
		return false
	}

	// Decode UTF-8 directly from bytes - avoids full string allocation
	body := input.ResponseBody
	for i := 0; i < len(body); {
		r, size := utf8.DecodeRune(body[i:])
		if isVibeAppEmoji(r) {
			return true
		}
		i += size
	}
	return false
}

// vibeAppEmojis contains specific emojis commonly used in vibe-coded apps.
// Using a map for O(1) lookup instead of range checks.
var vibeAppEmojis = map[rune]struct{}{
	'✅': {}, // U+2705 - Check mark
	'❌': {}, // U+274C - Cross mark
	'⚠': {}, // U+26A0 - Warning
	'ℹ': {}, // U+2139 - Information
	'🔥': {}, // U+1F525 - Fire (popular)
	'🚀': {}, // U+1F680 - Rocket (deploy/launch)
	'💡': {}, // U+1F4A1 - Light bulb (idea/tip)
	'📦': {}, // U+1F4E6 - Package
	'🎉': {}, // U+1F389 - Party popper (success)
	'👍': {}, // U+1F44D - Thumbs up
	'👎': {}, // U+1F44E - Thumbs down
	'⭐': {}, // U+2B50 - Star
	'❤': {}, // U+2764 - Red heart
	'🔒': {}, // U+1F512 - Lock (security)
	'🔓': {}, // U+1F513 - Unlock
	'⏳': {}, // U+23F3 - Hourglass (loading)
	'✨': {}, // U+2728 - Sparkles
	'💰': {}, // U+1F4B0 - Money bag
	'🛒': {}, // U+1F6D2 - Shopping cart
	'👤': {}, // U+1F464 - User/person
	'⚙': {}, // U+2699 - Gear (settings)
	'🔍': {}, // U+1F50D - Search
	'📝': {}, // U+1F4DD - Memo/note
	'🗑': {}, // U+1F5D1 - Trash
	'📊': {}, // U+1F4CA - Chart
	'🔔': {}, // U+1F514 - Bell (notification)
}

// isVibeAppEmoji returns true if rune is a common vibe-app emoji.
func isVibeAppEmoji(r rune) bool {
	_, ok := vibeAppEmojis[r]
	return ok
}

// Ensure VibeAppMatcher implements TagMatcher
var _ TagMatcher = (*VibeAppMatcher)(nil)
