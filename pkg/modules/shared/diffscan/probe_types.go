package diffscan

type ProbeInjectType int

const (
	InjectType_Undefined ProbeInjectType = iota
	InjectType_Append
	InjectType_Prepend
	InjectType_Replace
)

func (s ProbeInjectType) String() string {
	switch s {
	case InjectType_Append:
		return "append"
	case InjectType_Prepend:
		return "prepend"
	case InjectType_Replace:
		return "replace"
	}
	return ""
}
