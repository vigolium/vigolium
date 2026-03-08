package core

import (
	"bytes"
	"fmt"
	"net/url"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// URLEncodingAwareAttackStepExecutor implements the XSSAttackStepExecutor interface.
// Original Java class: ihj
type URLEncodingAwareAttackStepExecutor struct {
	delegateExecutor AttackStepRunner // Corresponds to private final XSSAttackStepExecutor c;
	// doNotEncodeChars map[rune]struct{} // Moved from package level static var
	// encoder *ConfigurableURLEncoder
	specialChars map[rune]struct{}
}

// NewURLEncodingAwareAttackStepExecutor creates a new instance of Ihj.
// Original Java constructor: public ihj(XSSAttackStepExecutor var1)
func NewURLEncodingAwareAttackStepExecutor(
	delegateExecutor AttackStepRunner,
) *URLEncodingAwareAttackStepExecutor {
	// Initialize charSetA for this instance
	specialChars := map[rune]struct{}{
		'=':  {},
		'/':  {},
		':':  {},
		'<':  {},
		'>':  {},
		'|':  {},
		'^':  {},
		'"':  {},
		'`':  {},
		'{':  {},
		'}':  {},
		'\\': {},
	}

	return &URLEncodingAwareAttackStepExecutor{
		delegateExecutor: delegateExecutor,
		specialChars:     specialChars,
	}
}

// IsAttackStepRunner marker method for the XSSAttackStepExecutor interface.
func (executor *URLEncodingAwareAttackStepExecutor) IsAttackStepRunner() {}
func (executor *URLEncodingAwareAttackStepExecutor) isContainsSpecialChars(payload string) bool {
	for _, char := range payload {
		if _, ok := executor.specialChars[char]; ok {
			return true
		}
	}
	return false
}

// RunAttackStep is the Go equivalent of the 'a' method from the XSSAttackStepExecutor interface for class Ihj.
// Original Java method: public PreliminaryXSSFinding a(*mutate.FuzzHTTPRequestParam var1, int var2, String var3, ll var4, byte var5, cgv var6, boolean var7, hnx var8)
func (executor *URLEncodingAwareAttackStepExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint, // var1
	scanFlags int, // var2
	payload string, // var3
	tactic ReflectionTacticType, // var4
	contextCode byte, // var5
	techniqueClassifier AttackTechniqueClassifier, // var6
	useSecondaryCanary bool, // var7
	profile *ScanExecutionProfile, // var8
) PotentialXSSFinding {
	if !executor.isContainsSpecialChars(payload) {
		return nil
	}

	// egpInstance := bnoVal.E_Egp() // httpmsg.InsertionPoint.e() returns egp
	// b2Instance, ok := egpInstance.(B2ModifiableSet)
	// if !ok || b2Instance == nil {
	// 	return nil
	// }

	// for charToRegister := range i.charSetA { // Use instance field
	// 	b2Instance.AddCharToInternalSet(charToRegister) // Corresponds
	// }

	// var resultBgf PreliminaryXSSFinding
	// defer func() {
	// 	for charToUnregister := range i.charSetA { // Use instance field
	// 		b2Instance.RemoveCharFromInternalSet(charToUnregister)
	// 	}
	// }()

	// if i.valCI2j == nil { // Defensive check for nil delegate
	// 	return nil
	// }
	// //TODO: check if this is correct
	// encodedPayload, err := executor.encoder.ProcessBytesWithOffsets(
	// 	[]byte(payload),
	// 	[]int{0, len(payload)},
	// )
	// if err != nil {
	// 	return nil
	// }

	// encodedPayload:= url.QueryEscape()

	resultBgf := executor.delegateExecutor.RunAttackStep(
		injectionPoint,
		scanFlags,
		payload,
		tactic,
		contextCode,
		techniqueClassifier,
		useSecondaryCanary,
		profile,
	)

	return resultBgf
}

// --- B2Processor Implementation (Equivalent of Java's b_2) ---

// ConfigurableURLEncoder implements Egp and B2ModifiableSet.
// It handles URL encoding and decoding, with a configurable set of characters
// that should not be encoded.
type ConfigurableURLEncoder struct {
	// doNotEncodeSet stores characters that should not be URL-encoded
	// by ProcessBytesWithOffsets.
	doNotEncodeSet map[rune]struct{}
}

// NewConfigurableURLEncoder creates a new B2Processor.
func NewConfigurableURLEncoder() *ConfigurableURLEncoder {
	return &ConfigurableURLEncoder{
		doNotEncodeSet: make(map[rune]struct{}),
	}
}
func NewConfigurableURLEncoderIgnoreSpecialChars(
	specialCharsToIgnore []rune,
) *ConfigurableURLEncoder {
	encoder := NewConfigurableURLEncoder()
	for _, char := range specialCharsToIgnore {
		encoder.AddSkipEncodeChar(char)
	}
	return encoder
}

// AddSkipEncodeChar adds a character to the set of characters that will not be URL-encoded.
// Implements B2ModifiableSet.
func (encoder *ConfigurableURLEncoder) AddSkipEncodeChar(char rune) {
	if encoder.doNotEncodeSet == nil {
		encoder.doNotEncodeSet = make(map[rune]struct{})
	}
	encoder.doNotEncodeSet[char] = struct{}{}
}

// RemoveSkipEncodeChar removes a character from the set.
// Implements B2ModifiableSet.
func (encoder *ConfigurableURLEncoder) RemoveSkipEncodeChar(char rune) {
	if encoder.doNotEncodeSet != nil {
		delete(encoder.doNotEncodeSet, char)
	}
}

// isSpecialChar checks if a byte is a special character that needs encoding
// (unless it's in doNotEncodeSet).
// This logic is derived from the switch statement in Java's b_2.a(byte[], int[]).
func (encoder *ConfigurableURLEncoder) shouldEncodeByte(b byte) bool {
	if _, isSkipped := encoder.doNotEncodeSet[rune(b)]; isSkipped {
		return false // Do not encode if in the set
	}
	switch b {
	case ' ',
		'"',
		'#',
		'%',
		'&',
		'+',
		',',
		'/',
		':',
		';',
		'<',
		'=',
		'>',
		'?',
		'\\',
		'^',
		'`',
		'{',
		'|',
		'}':
		return true
	default:
		// Bytes < 32 or >= 127 (ASCII control characters and extended)
		return b < 32 || b >= 127
	}
}

// ProcessBytesWithOffsets URL-encodes data. Characters in doNotEncodeSet are skipped.
// Updates offsets based on encoding changes.
// Implements Egp. Corresponds to Java's b_2.a(byte[] var1, int[] var2).
func (encoder *ConfigurableURLEncoder) ProcessBytesWithOffsets(
	data []byte,
	offsets []int,
) ([]byte, error) {
	if len(offsets) != 2 {
		return nil, fmt.Errorf("offsets array must have length 2")
	}

	var out bytes.Buffer
	originalStartOffset := offsets[0]
	originalEndOffset := offsets[1]
	newStartOffset := -1
	newEndOffset := -1

	for i, b := range data {
		// Update new offsets if current input index matches original offsets
		if i == originalStartOffset {
			newStartOffset = out.Len()
		}
		if i == originalEndOffset {
			newEndOffset = out.Len()
		}

		// fmt.Sprintf("%%%02x", byte('#')) = %23
		// https://go.dev/play/p/c6KQ7HQLBeH
		if encoder.shouldEncodeByte(b) {
			fmt.Fprintf(&out, "%%%02x", b) // Lowercase hex, like Java's nc.c
		} else {
			out.WriteByte(b)
		}
	}

	// Final check for end offset if it was at the end of input data
	if originalEndOffset == len(data) {
		newEndOffset = out.Len()
	}
	// If start offset was also at the end (e.g. empty selection at end)
	if originalStartOffset == len(data) {
		newStartOffset = out.Len()
	}

	// Update the passed-in offsets slice
	if newStartOffset != -1 {
		offsets[0] = newStartOffset
	} else {
		offsets[0] = 0 // Default if original offset was out of bounds or not found
	}

	if newEndOffset != -1 {
		offsets[1] = newEndOffset
	} else {
		// If original end offset was not met, it implies it might be beyond current data length
		// or the output is shorter. Default to end of output.
		offsets[1] = out.Len()
	}

	return out.Bytes(), nil
}

// ProcessBytes URL-decodes data.
// Implements Egp. Corresponds to Java's b_2.a(byte[] var1) which uses nc.c.
func (encoder *ConfigurableURLEncoder) ProcessBytes(data []byte) ([]byte, error) {
	// net/url.QueryUnescape handles '+' as space and %XX.
	// Java's nc.c also handles %uXXXX, which QueryUnescape does not.
	// If %uXXXX is critical, a custom unescape or a more specific library might be needed.
	// For now, QueryUnescape is a close approximation for common URL decoding.
	s, err := url.QueryUnescape(string(data))
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
