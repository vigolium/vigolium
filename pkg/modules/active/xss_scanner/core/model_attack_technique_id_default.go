package core

// DefaultAttackTechniqueIdentifier implements the AttackTechniqueClassifier interface.
type DefaultAttackTechniqueIdentifier struct {
}

// NewDefaultAttackTechniqueIdentifier creates a new instance.
func NewDefaultAttackTechniqueIdentifier() *DefaultAttackTechniqueIdentifier {
	return &DefaultAttackTechniqueIdentifier{}
}

// IsAttackTechniqueClassifier marker method for AttackTechniqueClassifier interface.
func (id *DefaultAttackTechniqueIdentifier) IsAttackTechniqueClassifier() {}

func (id *DefaultAttackTechniqueIdentifier) ClassificationCode() int {
	return 0
}

func (id *DefaultAttackTechniqueIdentifier) String() string {
	return "DefaultAttackTechnique" // Provide a default string representation
}
