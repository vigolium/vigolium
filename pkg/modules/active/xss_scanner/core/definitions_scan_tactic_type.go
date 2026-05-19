package core

import (
	"fmt"
)

const (
	TacticReplace ReflectionTacticType = 0
	TacticAppend  ReflectionTacticType = 1
)

type ReflectionTacticType byte

func (l ReflectionTacticType) ByteValue() byte {
	return byte(l)
}

// String returns a string representation of the ReflectionTacticType.
func (l ReflectionTacticType) String() string {
	switch l {
	case TacticReplace:
		return "Replace"
	case TacticAppend:
		return "Append"
	default:
		return "UnknownTacticValue_" + fmt.Sprintf("%d", byte(l))
	}
}

var (
	PlainReflectionTactics = []ReflectionTacticType{TacticAppend, TacticReplace}
)

// GetReflectionTacticFromCollection returns the matching tactic and true if found.
func GetReflectionTacticFromCollection(
	collection []ReflectionTacticType,
	value byte,
) (ReflectionTacticType, bool) {
	for _, tactic := range collection {
		if tactic.ByteValue() == value {
			return tactic, true
		}
	}
	return ReflectionTacticType(0), false
}
