package core

// ReflectionPointCoreInfo is the Go equivalent of the Java class burp.hpo.
// It implements the Eqx and ReflectionPointCoreInfo interfaces.
type ReflectionPointCoreInfo struct {
	location          ReflectionLocation // Corresponds to 'public final byte d;' (constructor var1)
	contextType       ReflectionContext  // Corresponds to 'public final byte e;' (constructor var2)
	startIndexInInput int                // Corresponds to 'public final int f;' (constructor var3)
	endIndexInInput   int                // Corresponds to 'public final int c;' (constructor var4)
	canaryBytes       []byte             // Corresponds to 'public byte[] g;' (constructor var5)
}

// NewReflectionPointCoreInfo creates a new instance of Hpo.
// Original Java constructor: public hpo(byte var1, byte var2, int var3, int var4, byte[] var5)
// var1: contextIndicator, var2: reflectionType, var3: reflectionStartInInput, var4: reflectionEndInInput, var5: canary
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

// Accept corresponds to Eqx.a(ena<T> var1).
// In hpo.java, this method returns null.
func (h *ReflectionPointCoreInfo) Accept(visitor ReflectionDetailVisitor) interface{} {
	// hpo.java itself does not call any specific visit method on 'ena'.
	// It simply returns null for this generic visitor pattern.
	return nil
}

// Location returns the reflection location. Corresponds to Java hpo.d.
func (h *ReflectionPointCoreInfo) Location() ReflectionLocation {
	return h.location
}

// ContextType returns the reflection type. Corresponds to Java hpo.e.
func (h *ReflectionPointCoreInfo) ContextType() ReflectionContext {
	return h.contextType
}

// StartIndex returns the start offset of the reflection. Corresponds to Java hpo.f.
func (h *ReflectionPointCoreInfo) StartIndex() int {
	return h.startIndexInInput
}

// EndIndex returns the end offset of the reflection. Corresponds to Java hpo.c.
func (h *ReflectionPointCoreInfo) EndIndex() int {
	return h.endIndexInInput
}

// Canary returns the canary bytes. Corresponds to Java hpo.g.
func (h *ReflectionPointCoreInfo) Canary() []byte {
	return h.canaryBytes
}

// --- Getters from stubs.go Hpo interface to match ConcreteHpo ---
// These map to the specific field names in hpo.java (f, c, e)

// GetStartIndex returns ReflectionStartInInput. (Java hpo.f)
func (h *ReflectionPointCoreInfo) GetStartIndex() int {
	return h.startIndexInInput
}

// GetEndIndex returns ReflectionEndInInput. (Java hpo.c)
func (h *ReflectionPointCoreInfo) GetEndIndex() int {
	return h.endIndexInInput
}

// GetContextCode returns ReflectionType. (Java hpo.e)
func (h *ReflectionPointCoreInfo) GetContextCode() byte {
	return byte(h.contextType)
}
