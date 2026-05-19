package core

// IndexedAttackTechniqueIdentifier implements the AttackTechniqueClassifier interface.
type IndexedAttackTechniqueIdentifier struct {
	payloadIndex int
}

// NewIndexedAttackTechniqueIdentifier creates a new instance.
func NewIndexedAttackTechniqueIdentifier(payloadIndex int) *IndexedAttackTechniqueIdentifier {
	return &IndexedAttackTechniqueIdentifier{payloadIndex: payloadIndex}
}

// IsAttackTechniqueClassifier marker method for AttackTechniqueClassifier interface.
func (id *IndexedAttackTechniqueIdentifier) IsAttackTechniqueClassifier() {}

func (id *IndexedAttackTechniqueIdentifier) String() string {
	availablePayloads := GetProofOfConceptPayloads()
	if id.payloadIndex >= 0 && id.payloadIndex < len(availablePayloads) {
		return availablePayloads[id.payloadIndex]
	}
	return "UnknownPayload" // Fallback if index is out of bounds
}

func (id *IndexedAttackTechniqueIdentifier) ClassificationCode() int {
	if id.payloadIndex != 0 {
		return 2048
	}
	return 0
}
