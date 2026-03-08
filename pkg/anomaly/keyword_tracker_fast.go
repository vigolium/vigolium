package anomaly

import (
	"bytes"
	"errors"

	"github.com/samber/lo"
)

type FastResponseKeywords struct {
	attributes        map[string]int
	staticAttributes  map[string]bool
	dynamicAttributes map[string]bool
}

func NewFastResponseKeywords(keys []string) *FastResponseKeywords {
	staticAttributes := make(map[string]bool, len(keys))
	for _, key := range keys {
		staticAttributes[key] = true
	}
	return &FastResponseKeywords{
		staticAttributes:  staticAttributes,
		dynamicAttributes: make(map[string]bool),
		attributes:        make(map[string]int),
	}
}
func (f *FastResponseKeywords) GetDynamicAttributes() []string {
	return lo.Keys(f.dynamicAttributes)
}

func (f *FastResponseKeywords) GetStaticAttributes() []string {
	return lo.Keys(f.staticAttributes)
}

func (f *FastResponseKeywords) GetAttributeValue(s string, i int) (int, error) {
	if i != 0 {
		return 0, errors.New("requested request not stored")
	}
	value, exists := f.attributes[s]
	if !exists {
		return 0, errors.New("attribute not found")
	}
	return value, nil
}

func (f *FastResponseKeywords) UpdateWith(bytes ...[]byte) {
	respBytes := bytes[0]
	if len(f.attributes) == 0 {
		for key := range f.staticAttributes {
			f.attributes[key] = f.calculateAttribute(respBytes, key)
		}
	} else {
		for key := range f.staticAttributes {
			newValue := f.calculateAttribute(respBytes, key)
			if newValue != f.attributes[key] {
				delete(f.staticAttributes, key)
				f.dynamicAttributes[key] = true
			}
		}
	}
}
func (f *FastResponseKeywords) calculateAttribute(rawResponse []byte, attribute string) int {
	bodyStart := getBodyStart(rawResponse)
	body := rawResponse[bodyStart:]
	return bytes.Count(body, []byte(attribute))
}
