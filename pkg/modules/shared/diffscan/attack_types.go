package diffscan

import "fmt"

// ReflectionCount tracks how many times the injected payload appears in the response.
// Negative values represent special states rather than actual counts.
type ReflectionCount int

const (
	ReflectionCountUninitialized ReflectionCount = -1
	ReflectionCountDynamic       ReflectionCount = -2
	ReflectionCountIncalculable  ReflectionCount = -3
)

func (s ReflectionCount) String() string {
	switch s {
	case ReflectionCountDynamic:
		return "Dynamic"
	case ReflectionCountIncalculable:
		return "Incalculable"
	case ReflectionCountUninitialized:
		return "Uninitialized"
	default:
		return fmt.Sprintf("%v", int(s))
	}
}
