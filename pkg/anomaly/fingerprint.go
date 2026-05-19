package anomaly

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/samber/lo"
)

type Fingerprint struct {
	DynamicAttributes []Type
	StaticAttributes  []Type
	HistoryAttributes map[Type][]uint32 // Stores history of values for each attribute

	UpdateCount      int
	FingerprintTypes []Type
	newDataAdded     bool
	mux              sync.RWMutex
}

// NewFingerprint Create empty fingerprint
func NewFingerprint(fingerprintTypes []Type) *Fingerprint {
	f := new(Fingerprint)
	f.DynamicAttributes = []Type{}
	f.StaticAttributes = []Type{}
	f.HistoryAttributes = make(map[Type][]uint32, len(fingerprintTypes))
	f.UpdateCount = 0
	f.FingerprintTypes = fingerprintTypes
	return f
}

// GetResponseFingerprint Return the fingerprint of response
func NewFingerprint2(statusCode int, responseBody string, headers map[string][]string, fingerprintTypes []Type) *Fingerprint {
	f := NewFingerprint(fingerprintTypes)
	f.UpdateWith(statusCode, responseBody, headers)
	return f
}

func NewFingerprint3(statusCode int, responseBody string, headers map[string]string, fingerprintTypes []Type) *Fingerprint {
	f := NewFingerprint(fingerprintTypes)
	f.UpdateWith(statusCode, responseBody, convertMap(headers))
	return f
}

func NewFingerprint4(resp *http.Response, fingerprintTypes []Type) *Fingerprint {
	f := NewFingerprint(fingerprintTypes)
	var body string
	bodyByte, err := io.ReadAll(resp.Body)
	if err == nil {
		body = b2s(bodyByte)
		// reset to read later
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
	}

	f.UpdateWith(resp.StatusCode, body, resp.Header)
	return f
}

// IsSimilar Check if two fingerprints are similar
//
// @return true if the fingerprints are similar, false otherwise
func (f *Fingerprint) IsSimilar(toCompare *Fingerprint) bool {
	staticAttributes := f.GetStaticAttributes()
	for _, attr := range staticAttributes {
		if value, ok := f.GetAttributeValue(attr); ok {
			if toCompareValue, ok := toCompare.GetAttributeValue(attr); ok {
				if value != toCompareValue {
					// fmt.Printf("static attribute %s: %d != %d\n", attr, value, toCompareValue)
					return false
				}
			}
		}
	}
	return true
}

func (f *Fingerprint) SetAttribute(key Type, value uint32) {
	f.mux.Lock()
	defer f.mux.Unlock()
	f.HistoryAttributes[key] = []uint32{value}
}

// GetDynamicAttributes Get the fingerprint fields which are changed across requests (not stable)
func (f *Fingerprint) GetDynamicAttributes() []Type {
	f.mux.Lock()
	defer f.mux.Unlock()
	if f.newDataAdded {
		f.analyze()
		f.newDataAdded = false
	}
	return f.DynamicAttributes
}

// GetStaticAttributes Get the fingerprint fields which are not changed across requests (stable)
func (f *Fingerprint) GetStaticAttributes() []Type {
	f.mux.Lock()
	defer f.mux.Unlock()
	if f.newDataAdded {
		f.analyze()
		f.newDataAdded = false
	}
	return f.StaticAttributes
}

func (f *Fingerprint) analyze() {
	f.DynamicAttributes = []Type{} // Reset dynamic attributes
	f.StaticAttributes = []Type{}  // Reset static attributes

	for _, attr := range f.FingerprintTypes {
		values, found := f.HistoryAttributes[attr]
		if !found || len(values) == 0 {
			continue // Skip if no history is found
		}

		if len(values) > 1 {
			f.DynamicAttributes = append(f.DynamicAttributes, attr) // More than one unique value, dynamic
		} else if len(values) == 1 {
			f.StaticAttributes = append(f.StaticAttributes, attr) // Exactly one unique value, static
		}
	}
}

// GetAttributeValue Return the attribute value of the field
func (f *Fingerprint) GetAttributeValue(key Type) (uint32, bool) {
	f.mux.RLock()
	defer f.mux.RUnlock()
	if value, found := f.HistoryAttributes[key]; found && len(value) > 0 {
		return value[0], true
	}
	return 0, false
}

func (f *Fingerprint) UpdateWithFingerprint(updateFingerprint *Fingerprint) {
	f.mux.Lock()
	defer f.mux.Unlock()
	f.updateFromFingerprint(updateFingerprint)
}

func (f *Fingerprint) UpdateWith(statusCode int, responseBody string, headers map[string][]string) {
	f.mux.Lock()
	defer f.mux.Unlock()
	newFinger := f.getFingerprint(statusCode, responseBody, headers)
	f.update(newFinger)
}

func (f *Fingerprint) getFingerprint(statusCode int, responseBody string, headers map[string][]string) map[Type]uint32 {
	tempMap := make(map[Type]uint32, len(f.FingerprintTypes))

	for _, attr := range f.FingerprintTypes {
		switch attr {
		case STATUS_CODE:
			tempMap[STATUS_CODE] = uint32(statusCode)
		case STATUS_CODE_TEXT:
			tempMap[STATUS_CODE_TEXT] = getStatusCodeText(headers)
		case CONTENT_TYPE:
			tempMap[CONTENT_TYPE] = getContentType(headers)
		case CONTENT_LOCATION:
			tempMap[CONTENT_LOCATION] = getContentLocation(headers)
		case ETAG_HEADER:
			tempMap[ETAG_HEADER] = getEtagHeader(headers)
		case LAST_MODIFIED_HEADER:
			tempMap[LAST_MODIFIED_HEADER] = getLastModifiedHeader(headers)
		case LOCATION:
			tempMap[LOCATION] = getLocation(headers)
		case SERVER_HEADER:
			tempMap[SERVER_HEADER] = getServerHeader(headers)
		case SET_COOKIE_NAMES:
			tempMap[SET_COOKIE_NAMES] = getSetCookieNames(headers)
		case LINE_COUNT:
			tempMap[LINE_COUNT] = getLineCount(responseBody)
		case WORD_COUNT:
			tempMap[WORD_COUNT] = getWordCount(responseBody)
		case WHOLE_BODY_CONTENT:
			tempMap[WHOLE_BODY_CONTENT] = getWholeBodyContent(responseBody)
		case LIMITED_BODY_CONTENT:
			tempMap[LIMITED_BODY_CONTENT] = getLimitedBodyContent(responseBody)
		case INITIAL_BODY_CONTENT:
			tempMap[INITIAL_BODY_CONTENT] = getInitialBodyContent(responseBody)
		case CONTENT_LENGTH:
			// *Disable get content_length from header because when send requests with keep-alive, some server will return 0 content_length
			tempMap[CONTENT_LENGTH] = uint32(len(responseBody))
		}
	}

	if responseBody != "" {
		if detector := NewMimetypeDetector(nil, responseBody); detector.GetInferredMimeType() == ContentTypeHTML || detector.GetStatedMimeType() == ContentTypeHTML {
			htmlAnalyzer, err := NewHTMLAnalyzer(responseBody)
			if err == nil {
				for _, attr := range f.FingerprintTypes {
					if value, err := htmlAnalyzer.GetAttribute(attr); err == nil {
						tempMap[attr] = value
					}
				}
			}
		}
	}

	return tempMap
}

func (f *Fingerprint) String() string {
	sb := strings.Builder{}

	sb.WriteString("DynamicAttributes: \n")
	for _, key := range f.GetDynamicAttributes() {
		if values, ok := f.HistoryAttributes[key]; ok {
			fmt.Fprintf(&sb, "%s: %d\n", key, values)
		} else {
			fmt.Fprintf(&sb, "%s: %d\n", key, 0)
		}
	}

	sb.WriteString("StaticAttributes: \n")
	for _, key := range f.GetStaticAttributes() {
		if values, ok := f.HistoryAttributes[key]; ok {
			fmt.Fprintf(&sb, "%s: %d\n", key, values)
		} else {
			fmt.Fprintf(&sb, "%s: %d\n", key, 0)
		}
	}

	return sb.String()
}

func (f *Fingerprint) GetHash() string {
	f.mux.RLock()
	defer f.mux.RUnlock()
	var toHash []string
	for _, attr := range f.FingerprintTypes {
		if value, ok := f.GetAttributeValue(attr); ok {
			toHash = append(toHash, fmt.Sprintf("%d", value))
		} else {
			toHash = append(toHash, "-1")
		}
	}
	return sha1Encode(strings.Join(toHash, "|"))
}

// update applies a given fingerprint map to the current Fingerprint instance.
//
// It increments the update count, checks each attribute in the provided fingerprint,and updates the attribute values accordingly.
//
// Attributes are classified as dynamic if their values change from the previously stored values.
//
// Once an attribute is classified as dynamic, it remains so across future updates unless explicitly reset.
//
// This method locks the Fingerprint for safe concurrent access and records the last update time.
func (f *Fingerprint) update(updates map[Type]uint32) {
	f.UpdateCount++
	f.newDataAdded = true
	for key, value := range updates {
		if _, exists := f.HistoryAttributes[key]; !exists {
			f.HistoryAttributes[key] = []uint32{value}
			continue
		}
		if !lo.Contains(f.HistoryAttributes[key], value) {
			f.HistoryAttributes[key] = append(f.HistoryAttributes[key], value)
		}
	}
}

// updateFromFingerprint updates the current Fingerprint instance based on another Fingerprint instance.
//
// It processes both static and dynamic attributes from the update fingerprint.
//
// Static attributes are moved to dynamic if their values differ from the current values.
//
// Dynamic attributes are always treated as dynamic.
//
// This method ensures that the fingerprint reflects the most recent
func (f *Fingerprint) updateFromFingerprint(updateFingerprint *Fingerprint) {
	f.UpdateCount++
	f.newDataAdded = true
	for key, newValues := range updateFingerprint.HistoryAttributes {
		if _, exists := f.HistoryAttributes[key]; !exists {
			f.HistoryAttributes[key] = []uint32{}
		}

		// Append only unique new values to the history
		for _, newValue := range newValues {
			if !lo.Contains(f.HistoryAttributes[key], newValue) {
				f.HistoryAttributes[key] = append(f.HistoryAttributes[key], newValue)
			}
		}
	}
}
