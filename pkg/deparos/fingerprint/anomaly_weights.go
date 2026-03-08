package fingerprint

import (
	"sync"
)

const (
	// initialWeight is the starting weight for all attributes
	initialWeight = 1.0

	// degradationFactor is multiplied to weight when a novel value is seen.
	// Lower values = faster degradation = less weight for highly variable attributes.
	degradationFactor = 0.9
)

// AttributeWeightManager manages adaptive weights for attributes.
// Weights are degraded when novel values are encountered, reducing
// the impact of highly variable attributes on anomaly scoring.
type AttributeWeightManager struct {
	weights map[Attribute]float64
	mu      sync.RWMutex
}

// NewAttributeWeightManager creates a weight manager with initial weights.
func NewAttributeWeightManager(attributes []Attribute) *AttributeWeightManager {
	awm := &AttributeWeightManager{
		weights: make(map[Attribute]float64, len(attributes)),
	}
	for _, attr := range attributes {
		awm.weights[attr] = initialWeight
	}
	return awm
}

// DegradeWeight reduces weight by degradationFactor.
// Called when a novel value is encountered for an attribute.
func (awm *AttributeWeightManager) DegradeWeight(attr Attribute) {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	if weight, exists := awm.weights[attr]; exists {
		awm.weights[attr] = weight * degradationFactor
	}
}

// GetWeight returns current weight for an attribute.
// Returns 0 if attribute not tracked.
func (awm *AttributeWeightManager) GetWeight(attr Attribute) float64 {
	awm.mu.RLock()
	defer awm.mu.RUnlock()
	return awm.weights[attr]
}

// ResetWeight resets a single attribute to initial weight.
func (awm *AttributeWeightManager) ResetWeight(attr Attribute) {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	if _, exists := awm.weights[attr]; exists {
		awm.weights[attr] = initialWeight
	}
}

// ResetAll resets all weights to initial values.
func (awm *AttributeWeightManager) ResetAll() {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	for attr := range awm.weights {
		awm.weights[attr] = initialWeight
	}
}

// GetAllWeights returns a copy of all weights.
func (awm *AttributeWeightManager) GetAllWeights() map[Attribute]float64 {
	awm.mu.RLock()
	defer awm.mu.RUnlock()

	result := make(map[Attribute]float64, len(awm.weights))
	for attr, weight := range awm.weights {
		result[attr] = weight
	}
	return result
}

// SetWeight sets a specific weight (for testing or custom configuration).
func (awm *AttributeWeightManager) SetWeight(attr Attribute, weight float64) {
	awm.mu.Lock()
	defer awm.mu.Unlock()
	awm.weights[attr] = weight
}
