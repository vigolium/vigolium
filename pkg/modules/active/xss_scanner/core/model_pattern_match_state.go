package core

// PatternMatchState holds the current index and character during pattern matching.
type PatternMatchState struct {
	currentIndex int
	currentChar  byte
}

// Made unexported as it's an internal constructor.
func newPatternMatchStateInternal(currentIndex int, character byte) *PatternMatchState {
	return &PatternMatchState{
		currentIndex: currentIndex,
		currentChar:  character,
	}
}

func GetStateChar(state *PatternMatchState) byte {
	if state == nil {
		// Handle nil instance appropriately, perhaps return a default or panic
		return 0 // Default byte value
	}
	return state.currentChar
}

func GetStateIndex(state *PatternMatchState) int {
	if state == nil {
		return 0 // Default int value
	}
	return state.currentIndex
}

// NewPatternMatchState creates a new PatternMatchState instance.
func NewPatternMatchState(
	currentIndex int,
	character byte,
	ignoredParam interface{},
) *PatternMatchState {
	return newPatternMatchStateInternal(currentIndex, character)
}

// CurrentIndex returns the current index in the pattern match.
func (h *PatternMatchState) CurrentIndex() int {
	return h.currentIndex
}

// CurrentChar returns the current character in the pattern match.
func (h *PatternMatchState) CurrentChar() byte {
	return h.currentChar
}
