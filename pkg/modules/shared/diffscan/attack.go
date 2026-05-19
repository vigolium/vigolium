package diffscan

import (
	"github.com/vigolium/vigolium/pkg/anomaly"
)

type Attack struct {
	FirstSnapshot *ResponseSnapshot
	LastSnapshot  *ResponseSnapshot

	LastFingerprint map[string]any

	Payload string
	Anchor  string

	Fingerprint map[string]any

	ResponseFingerprint         *anomaly.Fingerprint
	ResponseKeywordsFingerprint *anomaly.FastResponseKeywords

	ResponseReflections ReflectionCount

	Probe        *Probe
	quantMetrics map[string]*QuantitativeMeasurements
	quantKeys    map[string]struct{}
}

func NewAttack(quantDiffKeys []string, quantileFactor int, customCanary string) *Attack {
	attack := &Attack{
		ResponseReflections:         ReflectionCountUninitialized,
		ResponseFingerprint:         anomaly.NewFingerprint(diffScanFingerprintTypes),
		ResponseKeywordsFingerprint: anomaly.NewFastResponseKeywords(GetCanaryKeys(customCanary)),
	}
	attack.initialiseQuantitativeMeasurements(quantDiffKeys, quantileFactor)
	return attack
}

func NewAttackFromSnapshot(
	snap *ResponseSnapshot,
	probe *Probe,
	payload string,
	anchor string,
	quantDiffKeys []string,
	quantileFactor int,
	customCanary string,
) *Attack {
	attack := &Attack{
		FirstSnapshot:               snap,
		LastSnapshot:                snap,
		Probe:                       probe,
		Payload:                     payload,
		Anchor:                      anchor,
		ResponseReflections:         ReflectionCountUninitialized,
		ResponseKeywordsFingerprint: anomaly.NewFastResponseKeywords(GetCanaryKeys(customCanary)),
		ResponseFingerprint:         anomaly.NewFingerprint(diffScanFingerprintTypes),
	}
	attack.initialiseQuantitativeMeasurements(quantDiffKeys, quantileFactor)
	attack.mergeSnapshot(snap, anchor)
	attack.LastFingerprint = attack.Fingerprint
	return attack
}

func NewAttackFromSnapshotSimple(snap *ResponseSnapshot, anchor string, quantDiffKeys []string, quantileFactor int, customCanary string) *Attack {
	attack := &Attack{
		FirstSnapshot:               snap,
		LastSnapshot:                snap,
		ResponseReflections:         ReflectionCountUninitialized,
		ResponseKeywordsFingerprint: anomaly.NewFastResponseKeywords(GetCanaryKeys(customCanary)),
		ResponseFingerprint:         anomaly.NewFingerprint(diffScanFingerprintTypes),
	}
	attack.initialiseQuantitativeMeasurements(quantDiffKeys, quantileFactor)
	attack.mergeSnapshot(snap, anchor)
	attack.LastFingerprint = attack.Fingerprint
	return attack
}

func (s *Attack) initialiseQuantitativeMeasurements(keys []string, factor int) {
	s.quantKeys = make(map[string]struct{}, len(keys))
	s.quantMetrics = make(map[string]*QuantitativeMeasurements, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		s.quantKeys[key] = struct{}{}
		s.quantMetrics[key] = NewQuantitativeMeasurements(key, factor)
	}
}

func (s *Attack) AddAttack(attack *Attack) {
	if s.FirstSnapshot == nil {
		s.FirstSnapshot = attack.FirstSnapshot
		s.Anchor = attack.Anchor
		s.Probe = attack.Probe
		s.Payload = attack.Payload
		s.mergeSnapshot(attack.FirstSnapshot, s.Anchor)
		s.LastFingerprint = s.Fingerprint
		return
	}

	generatedPrint := make(map[string]any)
	inputPrint := attack.Fingerprint

	for inputKey, inputValue := range inputPrint {
		if currentValue, currentExists := s.Fingerprint[inputKey]; currentExists {
			if _, isQuant := s.quantKeys[inputKey]; isQuant {
				if currentQuantBox, currentIsQuant := currentValue.(*QuantitativeMeasurements); currentIsQuant {
					if inputQuantBox, inputIsQuant := inputValue.(*QuantitativeMeasurements); inputIsQuant {
						currentQuantBox.Merge(inputQuantBox)
						generatedPrint[inputKey] = currentQuantBox
					}
				}
			} else {
				if currentValue == inputValue {
					generatedPrint[inputKey] = currentValue
				}
			}
		}
	}

	s.Fingerprint = generatedPrint
	s.LastSnapshot = attack.LastSnapshot
	s.LastFingerprint = attack.Fingerprint
}

func (s *Attack) Size() int {
	if len(s.quantMetrics) == 0 {
		return 0
	}
	for _, measurements := range s.quantMetrics {
		return len(measurements.Measurements)
	}
	return 0
}

func (s *Attack) AllKeysAreQuantitative(keys []string) bool {
	for _, key := range keys {
		if _, exists := s.quantKeys[key]; !exists {
			return false
		}
	}
	return true
}

func (s *Attack) mergeSnapshot(snap *ResponseSnapshot, anchor string) {
	if s.FirstSnapshot == nil || snap == nil {
		return
	}

	// Full fingerprint: merge snapshot's fingerprint into attack's
	if snap.Fingerprint != nil {
		s.ResponseFingerprint.UpdateWithFingerprint(snap.Fingerprint)
	}

	s.ResponseKeywordsFingerprint.UpdateWith(snap.FilteredResponse)

	// Quantitative: read from the full fingerprint
	if len(s.quantMetrics) > 0 && snap.Fingerprint != nil {
		for key, quant := range s.quantMetrics {
			val, exists := snap.Fingerprint.GetAttributeValue(anomaly.FromString(key))
			if exists {
				quant.UpdateWith(int64(val))
			}
		}
	}

	if anchor == "" {
		s.ResponseReflections = ReflectionCountIncalculable
	} else {
		reflections := ReflectionCount(CountMatches(snap.FilteredResponse, []byte(anchor)))
		if s.ResponseReflections == ReflectionCountUninitialized {
			s.ResponseReflections = reflections
		} else if s.ResponseReflections != reflections && s.ResponseReflections != ReflectionCountIncalculable {
			s.ResponseReflections = ReflectionCountDynamic
		}
	}

	s.rebuildFingerprint()
}

func (s *Attack) rebuildFingerprint() {
	generatedPrint := make(map[string]any)

	// 1. Keywords (unchanged)
	keys := s.ResponseKeywordsFingerprint.GetStaticAttributes()
	for _, key := range keys {
		kv, err := s.ResponseKeywordsFingerprint.GetAttributeValue(key, 0)
		if err != nil {
			continue
		}
		generatedPrint[key] = kv
	}

	// 2. Full fingerprint static attributes
	for _, attr := range s.ResponseFingerprint.GetStaticAttributes() {
		if val, ok := s.ResponseFingerprint.GetAttributeValue(attr); ok {
			generatedPrint[attr.String()] = val
		}
	}

	// 3. Reflections (unchanged)
	if s.ResponseReflections != ReflectionCountDynamic {
		generatedPrint["input_reflections"] = int(s.ResponseReflections)
	}

	// 4. Quantitative (unchanged)
	for key, quant := range s.quantMetrics {
		generatedPrint[key] = quant
	}
	s.Fingerprint = generatedPrint
}

func (s *Attack) Close() {
	s.FirstSnapshot = nil
	s.LastSnapshot = nil
	s.LastFingerprint = nil
	s.Payload = ""
	s.Anchor = ""
	s.Fingerprint = nil
	s.ResponseFingerprint = nil
	s.ResponseKeywordsFingerprint = nil
	s.ResponseReflections = ReflectionCountUninitialized
	s.Probe = nil
	s.quantMetrics = nil
}

// fingerprintValuesEqual compares two fingerprint values, using
// QuantitativeMeasurements.Equals() for quantitative types.
func fingerprintValuesEqual(a, b any) bool {
	if qmA, ok := a.(*QuantitativeMeasurements); ok {
		if qmB, ok := b.(*QuantitativeMeasurements); ok {
			return qmA.Equals(qmB)
		}
		return false
	}
	return a == b
}

func GetNonMatchingFingerprints(attack1, attack2 *Attack) map[string]bool {
	allKeys := make(map[string]bool)
	nonMatching := make(map[string]bool)

	for key := range attack1.LastFingerprint {
		allKeys[key] = true
	}
	for key := range attack2.LastFingerprint {
		allKeys[key] = true
	}

	for key := range allKeys {
		val1, ok1 := attack1.LastFingerprint[key]
		val2, ok2 := attack2.LastFingerprint[key]

		if ok1 != ok2 || (ok1 && ok2 && !fingerprintValuesEqual(val1, val2)) {
			nonMatching[key] = true
		}
	}

	return nonMatching
}
