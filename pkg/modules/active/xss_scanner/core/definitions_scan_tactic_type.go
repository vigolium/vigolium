package core

import (
	"fmt"
)

// Enum constants for Ll, mirroring ll.java
const (
	LlReplace ReflectionTacticType = 0
	LlAppend  ReflectionTacticType = 1
)

// ReflectionTacticType is the Go equivalent of the Java enum burp.ll
type ReflectionTacticType byte // Changed from int to byte

// ByteValue returns the byte value of the Ll enum, mirroring ll.a() in Java.
func (l ReflectionTacticType) ByteValue() byte {
	return byte(l) // Explicit cast back to byte
}

// String returns a string representation of the Ll value.
func (l ReflectionTacticType) String() string {
	switch l {

	case LlReplace: // Covers all Ll*Replace types that are 0
		return "Replace (or equivalent type with value 0)"

	case LlAppend: // Covers all Ll*Append types that are 1
		return "Append (or equivalent type with value 1)"

	default:
		return "UnknownLlValue_" + fmt.Sprintf("%d", byte(l))
	}
}

// Static lists from ll.java
var (
	LlPlainReflectionTypes = []ReflectionTacticType{LlAppend, LlReplace}
)

// GetReflectionTacticFromCollection corresponds to public static ll a(Collection<ll> var0, byte var1)
// Returns the Ll value and a boolean indicating if it was found.
func GetReflectionTacticFromCollection(
	collection []ReflectionTacticType,
	value byte,
) (ReflectionTacticType, bool) {
	// boolean var2 = gji.b(); // In stubs.go, GjiB() is a placeholder, assuming it returns true for now to mimic potential early break.
	// However, if gji.b() always returns false (as per current stub), this loop always iterates fully.
	// Let's assume standard iteration for Go unless gji.b() true logic is critical and defined.
	// Java: static { b(false); } for gji.b, public static boolean b() { return b; }, so gji.b() is false.
	// Thus, the loop in Java iterates through all elements unless a match is found.

	for _, llInstance := range collection {
		if llInstance.ByteValue() == value { // Ll.A() returns the byte value
			return llInstance, true
		}
	}
	// net.portswigger.qe.a(false, net.portswigger.rg.d);
	return ReflectionTacticType(0), false // Return a default Ll (like LlReplace) and false
}
