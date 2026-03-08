package core

// IndexedAttackTechniqueIdentifier implements the Cgv interface.
// Original Java class: ekv
type IndexedAttackTechniqueIdentifier struct {
	payloadIndex int // Corresponds to private final int a;
}

// NewIndexedAttackTechniqueIdentifier creates a new instance of Ekv.
// Original Java constructor: ekv(int var1)
func NewIndexedAttackTechniqueIdentifier(payloadIndex int) *IndexedAttackTechniqueIdentifier {
	return &IndexedAttackTechniqueIdentifier{payloadIndex: payloadIndex}
}

// IsAttackTechniqueClassifier marker method for Cgv interface.
func (id *IndexedAttackTechniqueIdentifier) IsAttackTechniqueClassifier() {}

// String is the Go equivalent of public String toString() in ekv.java
func (id *IndexedAttackTechniqueIdentifier) String() string {
	// return fn0.b()[this.a];
	// Fn0GetStaticPayloads() returns a copy of fn0StaticPayloads from fn0.go
	availablePayloads := GetProofOfConceptPayloads()
	if id.payloadIndex >= 0 && id.payloadIndex < len(availablePayloads) {
		return availablePayloads[id.payloadIndex]
	}
	return "UnknownEkvPayload" // Fallback if index is out of bounds
}

// ClassificationCode is the Go equivalent of public int a() in ekv.java (from cgv interface)
func (id *IndexedAttackTechniqueIdentifier) ClassificationCode() int {
	// return this.a != 0 ? 2048 : 0;
	if id.payloadIndex != 0 {
		return 2048
	}
	return 0
}
