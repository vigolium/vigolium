package core

import "fmt"

type ReflectionLocation byte

const (
	// ReflectionLocationUnknown indicates an undetermined or unspecified location.
	ReflectionLocationUnknown ReflectionLocation = 0
	// ReflectionLocationHeader indicates the reflection was found in the HTTP headers.
	ReflectionLocationHeader ReflectionLocation = 1
	// ReflectionLocationBody indicates the reflection was found in the HTTP response body.
	ReflectionLocationBody ReflectionLocation = 2
)

// String returns a string representation of the InitialReflectionLocation.
func (irl ReflectionLocation) String() string {
	switch irl {
	case ReflectionLocationHeader:
		return "HEADER"
	case ReflectionLocationBody:
		return "BODY"
	case ReflectionLocationUnknown:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("UNSPECIFIED_INITIAL_LOCATION_%d", byte(irl))
	}
}
