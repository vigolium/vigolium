package core

// PatternMatchState is the Go equivalent of the Java class h85.
// It appears to be a simple data holder.
type PatternMatchState struct {
	// Corresponds to 'private final int a'
	currentIndex int
	// Corresponds to 'private final byte b'
	currentChar byte
	// g0c is not used in the logic of h85 based on the provided XML,
	// but was part of one constructor. We can omit it if it's truly unused
	// or add a field if it were used. For now, omitted as per strict porting of current visible logic.
}

// newPatternMatchStateInternal corresponds to the private Java constructor: private h85(int var1, byte var2)
// Made unexported as it's an internal constructor.
func newPatternMatchStateInternal(currentIndex int, character byte) *PatternMatchState {
	return &PatternMatchState{
		currentIndex: currentIndex,
		currentChar:  character,
	}
}

// GetStateChar corresponds to static Java method: static byte b(h85 var0)
func GetStateChar(state *PatternMatchState) byte {
	if state == nil {
		// Handle nil instance appropriately, perhaps return a default or panic
		// For now, assume valid instance as per Java's likely behavior (NPE if nil)
		return 0 // Default byte value
	}
	return state.currentChar
}

// GetStateIndex corresponds to static Java method: static int a(h85 var0)
func GetStateIndex(state *PatternMatchState) int {
	if state == nil {
		return 0 // Default int value
	}
	return state.currentIndex
}

// NewPatternMatchState creates a new H85 instance.
// This corresponds to the package-private constructor: h85(int var1, byte var2, g0c var3)
// which calls this(var1, var2). The g0c parameter is ignored in the chain.
// G0c is not defined further in the provided e8u.xml context for h85's direct usage.
func NewPatternMatchState(
	currentIndex int,
	character byte,
	ignoredParam interface{},
) *PatternMatchState {
	// The g0cVal parameter is present to match the Java signature,
	// but it's not used in the actual initialization based on this(var1, var2).
	return newPatternMatchStateInternal(currentIndex, character)
}

// Helper methods for e8u.java if direct field access is not desired (matching static access style)
// These might be redundant if direct access to H85.valA and H85.valB is preferred after creation.
// However, e8u.java uses h85.b(var9) and h85.a(var9), so these static-like accessors are needed.

// CurrentIndex is an accessor for valA (equivalent to h85.a(instance))
func (h *PatternMatchState) CurrentIndex() int {
	return h.currentIndex
}

// CurrentChar is an accessor for valB (equivalent to h85.b(instance))
func (h *PatternMatchState) CurrentChar() byte {
	return h.currentChar
}
