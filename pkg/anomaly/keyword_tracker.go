package anomaly

import (
	"bytes"
	"sync"
)

type ResponseKeywords struct {
	updatedTimes       int
	dynamicAttributes  map[string]uint32
	staticAttributes   map[string]uint32
	keywordsToAnalysis []string
	mux                sync.RWMutex
}

func NewResponseKeywords(keywordsToAnalysis []string) *ResponseKeywords {
	return &ResponseKeywords{
		keywordsToAnalysis: keywordsToAnalysis,
		dynamicAttributes:  make(map[string]uint32),
		staticAttributes:   make(map[string]uint32),
		updatedTimes:       0,
	}
}

// UpdateWith analysis and update the response keywords
func (s *ResponseKeywords) UpdateWith(responseBody []byte) {
	s.mux.Lock()
	defer s.mux.Unlock()

	currentFingerprint := s.analysis(responseBody)
	s.updatedTimes++

	for key, count := range currentFingerprint {
		if existingCount, exists := s.staticAttributes[key]; exists {
			if existingCount != count {
				// Move to dynamic if count changes
				s.dynamicAttributes[key] = count
				delete(s.staticAttributes, key)
			}
			// Do not update the count if it remains the same
		} else if _, exists := s.dynamicAttributes[key]; !exists {
			// New keyword, assume static initially
			s.staticAttributes[key] = count
		}
		// If it's already in dynamicAttributes, do nothing
	}
}

// GetVariantKeywords Get the fingerprint fields which are changed each requests (not stable)
func (s *ResponseKeywords) GetDynamicKeywords() []string {
	s.mux.RLock()
	defer s.mux.RUnlock()

	var strSlice []string
	for key := range s.dynamicAttributes {
		strSlice = append(strSlice, key)
	}
	return strSlice
}

// GetInvariantKeywords Get the fingerprint fields which are not changed each requests (stable)
func (s *ResponseKeywords) GetStaticKeywords() []string {
	s.mux.RLock()
	defer s.mux.RUnlock()
	var strSlice []string
	for key := range s.staticAttributes {
		strSlice = append(strSlice, key)
	}
	return strSlice
}

// GetKeywordCount Return the amount of keyword
func (s *ResponseKeywords) GetKeywordCount(key string) uint32 {
	s.mux.RLock()
	defer s.mux.RUnlock()

	if count, exists := s.dynamicAttributes[key]; exists {
		return count
	}
	if count, exists := s.staticAttributes[key]; exists {
		return count
	}

	return 0
}

// GetTotalUpdatedFingerprint Return the number of fingerprint updated
func (s *ResponseKeywords) GetTotalUpdatedFingerprint() int {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.updatedTimes
}

func (s *ResponseKeywords) analysis(responseBody []byte) map[string]uint32 {
	tempMap := make(map[string]uint32)
	for _, keyword := range s.keywordsToAnalysis {
		count := bytes.Count(responseBody, []byte(keyword))
		tempMap[keyword] = uint32(count)
	}
	return tempMap
}
