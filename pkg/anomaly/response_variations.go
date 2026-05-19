package anomaly

import (
	"bytes"
	"errors"
	"hash/crc32"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/samber/lo"
)

type FastResponseVariations struct {
	attributes        map[string]int
	staticAttributes  map[string]bool
	dynamicAttributes map[string]bool
}

func NewFastResponseVariations() *FastResponseVariations {
	invariantAttributes := map[string]bool{
		// "start": false,
		"code": true,
		// "headers":  true,
		"title":    true,
		"newlines": true,
		"spaces":   true,
		"length":   true,
		// "limited_body_content": true,
	}
	return &FastResponseVariations{
		staticAttributes:  invariantAttributes,
		dynamicAttributes: make(map[string]bool),
		attributes:        make(map[string]int),
	}
}

func (f *FastResponseVariations) GetDynamicAttributes() []string {
	return lo.Keys(f.dynamicAttributes)
}

func (f *FastResponseVariations) GetStaticAttributes() []string {
	return lo.Keys(f.staticAttributes)
}

func (f *FastResponseVariations) GetAttributeValue(s string, i int) (int, error) {
	if i != 0 {
		return 0, errors.New("requested request not stored")
	}
	value, exists := f.attributes[s]
	if !exists {
		return 0, errors.New("attribute not found")
	}
	return value, nil
}

func (f *FastResponseVariations) UpdateWith(bytes ...[]byte) {
	respBytes := bytes[0]
	if len(f.attributes) == 0 {
		for key := range f.staticAttributes {
			f.attributes[key] = calculateAttribute(respBytes, key)
		}
	} else {
		for key := range f.staticAttributes {
			newValue := calculateAttribute(respBytes, key)
			if newValue != f.attributes[key] {
				delete(f.staticAttributes, key)
				f.dynamicAttributes[key] = true
			}
		}
	}
}

func (f *FastResponseVariations) UpdateWithFastResponseVariations(other *FastResponseVariations) {
	if len(f.attributes) == 0 {
		f.attributes = make(map[string]int)
		for k, v := range other.attributes {
			f.attributes[k] = v
		}

		f.staticAttributes = make(map[string]bool)
		for k := range other.staticAttributes {
			f.staticAttributes[k] = true
		}

		f.dynamicAttributes = make(map[string]bool)
		for k := range other.dynamicAttributes {
			f.dynamicAttributes[k] = true
		}
		return
	}

	keysToMakeDynamic := []string{}

	for key := range f.staticAttributes {
		fInitialValue := f.attributes[key]

		if _, isDynamicInOther := other.dynamicAttributes[key]; isDynamicInOther {
			keysToMakeDynamic = append(keysToMakeDynamic, key)
			continue
		}

		otherInitialValue, existsInOtherAttributes := other.attributes[key]
		_, isStaticInOther := other.staticAttributes[key]

		if !existsInOtherAttributes || !isStaticInOther {
			keysToMakeDynamic = append(keysToMakeDynamic, key)
		} else if fInitialValue != otherInitialValue {
			keysToMakeDynamic = append(keysToMakeDynamic, key)
		}
	}

	for _, key := range keysToMakeDynamic {
		delete(f.staticAttributes, key)
		f.dynamicAttributes[key] = true
	}

	for key := range other.dynamicAttributes {
		f.dynamicAttributes[key] = true
	}
}

func calculateAttribute(rawResponse []byte, attribute string) int {
	bodyStart := getBodyStart(rawResponse)

	switch attribute {
	case "length":
		return len(rawResponse) - bodyStart
	case "start":
		return hashString(getStartType(rawResponse, bodyStart))
	case "code":
		return getCode(rawResponse)
	case "headers":
		return characterCount(rawResponse, []byte{'\n'}, 0, bodyStart)
	case "newlines":
		return characterCount(
			rawResponse,
			[]byte{'\r', '\n', 0xE2, 0x80, 0xA8, 0xE2, 0x80, 0xA9}, // \r, \n, LS, PS
			bodyStart,
			len(rawResponse),
		)
	case "spaces":
		return characterCount(
			rawResponse,
			[]byte{' ', '\t', 0xC2, 0xA0},
			bodyStart,
			len(rawResponse),
		)
	case "tags":
		return characterCount(rawResponse, []byte{'<'}, bodyStart, len(rawResponse))
	case "equals":
		return characterCount(rawResponse, []byte{'='}, bodyStart, len(rawResponse))
	case "title":
		return hashString(getTitle(rawResponse, bodyStart))
	case "limited_body_content":
		return getLimitedBodyContent2(rawResponse)
	default:
		return -1
	}
}
func getLimitedBodyContent2(content []byte) int {
	contentLen := len(content)
	sum := crc32.NewIEEE()
	if contentLen < 2048 {
		sum.Write(content)
	} else {
		sum.Write(content[0:1024])                       // first 1024 bytes
		sum.Write(content[contentLen-1024 : contentLen]) // last 1024 bytes
	}
	return int(sum.Sum32())
}

func getBodyStart(response []byte) int {
	i := 0
	newlinesSeen := 0
	for i < len(response) {
		x := response[i]
		if x == '\n' {
			newlinesSeen++
		} else if x != '\r' {
			newlinesSeen = 0
		}

		if newlinesSeen == 2 {
			i++
			break
		}
		i++
	}

	return i
}

func getStartType(response []byte, bodyStart int) string {
	if bodyStart >= len(response) {
		return "[blank]"
	}

	if response[bodyStart] == '<' {
		var builder strings.Builder
		i := bodyStart
		// Read until space, newline, or end tag marker
		for i < len(response) {
			b := response[i]
			if b == ' ' || b == '\n' || b == '\r' || b == '>' {
				break
			}
			builder.WriteByte(b)
			i++
		}
		return builder.String()
	}

	// If not starting with '<', consider it text
	return "text"
}

func hashString(s string) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32())
}

func getCode(resp []byte) int {
	if len(resp) == 0 {
		return 0
	}

	i := 0
	for i < len(resp) && resp[i] != ' ' {
		i++
	}
	i++
	start := i
	for i < len(resp) && resp[i] != ' ' {
		i++
	}

	if start == i {
		return 0
	}

	code, err := strconv.ParseInt(string(resp[start:i]), 10, 16)
	if err != nil {
		return 0
	}

	return int(code)
}

// Function to count occurrences of specific characters (represented as bytes in matches)
// in a slice of bytes (response) from index 'from' to 'to'.
func characterCount(response []byte, matches []byte, from int, to int) int {
	if from < 0 {
		from = 0
	}
	if to > len(response) {
		to = len(response)
	}
	if from >= to {
		return 0
	}

	count := 0
	subSlice := response[from:to]

	// Optimize for small number of matches using direct comparison
	if len(matches) <= 4 { // Heuristic threshold
		for _, b := range subSlice {
			for _, m := range matches {
				if b == m {
					count++
					break // Move to next byte in subSlice once a match is found
				}
			}
		}
	} else {
		// For larger number of matches, map might be slightly better,
		// but direct byte iteration is still the primary optimization.
		matchMap := make(map[byte]bool)
		for _, m := range matches {
			matchMap[m] = true
		}
		for _, b := range subSlice {
			if _, exists := matchMap[b]; exists {
				count++
			}
		}
	}

	return count
}

var (
	titleStartTag    = []byte("<title") // Case-insensitive check added below
	titleStartTagEnd = []byte(">")
)

// getTitle extracts the content of the *first* <title> tag found in the HTML body byte slice.
// It searches only within the body part specified by bodyStart.
func getTitle(response []byte, bodyStart int) string {
	if bodyStart >= len(response) {
		return "" // No body to search in
	}
	bodyBytes := response[bodyStart:]

	// Find the start of the first <title> tag (case-insensitive)
	idxTagStart := bytes.Index(bodyBytes, titleStartTag)
	if idxTagStart == -1 {
		idxTagStart = bytes.Index(bodyBytes, []byte("<TITLE")) // Try uppercase
		if idxTagStart == -1 {
			return "" // No <title> or <TITLE> tag found
		}
	}

	// Find the closing > of the <title...> tag
	// Determine the actual length of the matched start tag ("<title" or "<TITLE")
	matchedStartTagLen := len(titleStartTag)
	if !bytes.Equal(bodyBytes[idxTagStart:idxTagStart+matchedStartTagLen], titleStartTag) {
		matchedStartTagLen = len([]byte("<TITLE")) // It must have matched uppercase
	}
	searchFrom := idxTagStart + matchedStartTagLen // Start searching after the matched tag name
	idxContentStartMarker := bytes.Index(bodyBytes[searchFrom:], titleStartTagEnd)
	if idxContentStartMarker == -1 {
		return "" // No > found after <title...
	}
	// Calculate absolute index relative to bodyBytes
	absoluteIdxContentStart := searchFrom + idxContentStartMarker + len(titleStartTagEnd)

	// Find the next '<' character, assuming it marks the end of the title content
	searchFromEnd := absoluteIdxContentStart
	idxContentEndMarker := bytes.IndexByte(bodyBytes[searchFromEnd:], '<')
	if idxContentEndMarker == -1 {
		return "" // No '<' found after the title content started
	}

	// Calculate absolute index relative to bodyBytes
	absoluteIdxContentEnd := searchFromEnd + idxContentEndMarker

	// Extract the title content
	if absoluteIdxContentStart >= absoluteIdxContentEnd {
		return "" // Invalid indices (e.g., <title></title>)
	}
	titleBytes := bodyBytes[absoluteIdxContentStart:absoluteIdxContentEnd]

	return string(titleBytes)
}
