package anomaly

import (
	"sync"
)

const (
	// initialWeight is the starting weight for all attributes.
	initialWeight = 1.0

	// degradationFactor is multiplied by the current weight when a novel value is seen.
	// 0.9 means each novel value reduces the weight by 10%.
	degradationFactor = 0.9
)

// AttributeWeightManager manages adaptive weights for attributes.
// Weights are degraded when novel values are encountered, reducing
// the importance of highly variable attributes.
type AttributeWeightManager struct {
	weights map[Type]float64
	mu      sync.RWMutex
}

// NewAttributeWeightManager creates a new AttributeWeightManager.
// All attributes are pre-initialized to weight 1.0.
func NewAttributeWeightManager(attributeTypes []Type) *AttributeWeightManager {
	awm := &AttributeWeightManager{
		weights: make(map[Type]float64, len(attributeTypes)),
	}

	// Pre-initialize all weights to 1.0
	for _, attrType := range attributeTypes {
		awm.weights[attrType] = initialWeight
	}

	return awm
}

// DegradeWeight multiplies the weight for an attribute by the degradation factor.
// Called when a novel value is encountered for the attribute.
func (awm *AttributeWeightManager) DegradeWeight(attrType Type) {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	if currentWeight, exists := awm.weights[attrType]; exists {
		awm.weights[attrType] = currentWeight * degradationFactor
	}
}

// GetWeight returns the current weight for an attribute.
// Returns 1.0 if the attribute doesn't exist (shouldn't happen in normal use).
func (awm *AttributeWeightManager) GetWeight(attrType Type) float64 {
	awm.mu.RLock()
	defer awm.mu.RUnlock()

	if weight, exists := awm.weights[attrType]; exists {
		return weight
	}

	return initialWeight
}

// ResetWeight resets a specific attribute's weight back to 1.0.
func (awm *AttributeWeightManager) ResetWeight(attrType Type) {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	awm.weights[attrType] = initialWeight
}

// ResetAll resets all attribute weights back to 1.0.
func (awm *AttributeWeightManager) ResetAll() {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	for attrType := range awm.weights {
		awm.weights[attrType] = initialWeight
	}
}

// GetAllWeights returns a copy of all current weights.
// Useful for debugging and analysis.
func (awm *AttributeWeightManager) GetAllWeights() map[Type]float64 {
	awm.mu.RLock()
	defer awm.mu.RUnlock()

	copy := make(map[Type]float64, len(awm.weights))
	for k, v := range awm.weights {
		copy[k] = v
	}

	return copy
}
