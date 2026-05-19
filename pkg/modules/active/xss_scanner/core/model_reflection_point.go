package core

// ReflectionPointCoreInfo holds the core location and context data for a reflection point.
type ReflectionPointCoreInfo struct {
	location          ReflectionLocation
	contextType       ReflectionContext
	startIndexInInput int
	endIndexInInput   int
	canaryBytes       []byte
}

// NewReflectionPointCoreInfo creates a new instance.
func NewReflectionPointCoreInfo(
	location ReflectionLocation,
	contextType ReflectionContext,
	startIndex int,
	endIndex int,
	canary []byte,
) *ReflectionPointCoreInfo {
	return &ReflectionPointCoreInfo{
		location:          location,
		contextType:       contextType,
		startIndexInInput: startIndex,
		endIndexInInput:   endIndex,
		canaryBytes:       canary,
	}
}

func (h *ReflectionPointCoreInfo) GetRedirectionTarget(
	b5k *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	return nil
}
func (h *ReflectionPointCoreInfo) CoreInfo() *ReflectionPointCoreInfo {
	return h
}

func (h *ReflectionPointCoreInfo) Accept(visitor ReflectionDetailVisitor) interface{} {
	// It simply returns null for this generic visitor pattern.
	return nil
}

func (h *ReflectionPointCoreInfo) Location() ReflectionLocation {
	return h.location
}

func (h *ReflectionPointCoreInfo) ContextType() ReflectionContext {
	return h.contextType
}

func (h *ReflectionPointCoreInfo) StartIndex() int {
	return h.startIndexInInput
}

func (h *ReflectionPointCoreInfo) EndIndex() int {
	return h.endIndexInInput
}

func (h *ReflectionPointCoreInfo) Canary() []byte {
	return h.canaryBytes
}

func (h *ReflectionPointCoreInfo) GetStartIndex() int {
	return h.startIndexInInput
}

func (h *ReflectionPointCoreInfo) GetEndIndex() int {
	return h.endIndexInInput
}

func (h *ReflectionPointCoreInfo) GetContextCode() byte {
	return byte(h.contextType)
}
