package diffscan

import "fmt"

type ReflectType int

const (
	ReflectType_UNINITIALISED ReflectType = -1
	ReflectType_DYNAMIC       ReflectType = -2
	ReflectType_INCALCULABLE  ReflectType = -3
)

func (s ReflectType) String() string {
	switch s {
	case ReflectType_DYNAMIC:
		return "Dynamic"
	case ReflectType_INCALCULABLE:
		return "Incalculable"
	case ReflectType_UNINITIALISED:
		return "Uninitialised"
	default:
		return fmt.Sprintf("%v", int(s))
	}
}
