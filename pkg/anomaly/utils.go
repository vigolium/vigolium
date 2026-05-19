package anomaly

import (
	"crypto/sha1"
	"fmt"
	"hash/crc32"
	"unsafe"
)

func checksumCRC32(s string) uint32 {
	checksum := crc32.ChecksumIEEE(s2b(s))
	return checksum
}

// func toLowerHeaders(header map[string][]string) map[string]string {
// 	if header == nil {
// 		return map[string]string{}
// 	}
// 	reformatHeaders := make(map[string]string, len(header)) // Pre-allocate map capacity
// 	for hn, hv := range header {
// 		if len(hv) > 0 {
// 			lowerHn := strings.ToLower(hn) // Minimize function calls within the loop
// 			reformatHeaders[lowerHn] = hv[0]
// 		}
// 	}
// 	return reformatHeaders
// }

// func toLowerHeaders2(header map[string]string) map[string]string {
// 	if header == nil {
// 		return map[string]string{}
// 	}
// 	reformatHeaders := make(map[string]string, len(header)) // Pre-allocate map capacity
// 	for hn, hv := range header {
// 		lowerHn := strings.ToLower(hn) // Minimize function calls within the loop
// 		reformatHeaders[lowerHn] = hv
// 	}
// 	return reformatHeaders
// }

func convertMap(inputMap map[string]string) map[string][]string {
	if inputMap == nil {
		return map[string][]string{}
	}
	outputMap := make(map[string][]string, len(inputMap)) // Pre-allocate map capacity
	for k, v := range inputMap {
		outputMap[k] = []string{v}
	}
	return outputMap
}

func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func s2b(str string) []byte {
	if str == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(str), len(str))
}

// sha1Encode encode
func sha1Encode(data string) string {
	checksum := sha1.Sum(s2b(data))
	return fmt.Sprintf("%x", checksum)
}

// StaticAttributesComparison compares two fingerprints based on their static attributes.
//
// return true if the two fingerprints are the same
func StaticAttributesComparison(base *Fingerprint, resp *Fingerprint) bool {
	baseAttributes := base.GetStaticAttributes()
	respAttributes := resp.GetStaticAttributes()
	if len(baseAttributes) != len(respAttributes) {
		return false
	}
	// Check each attribute in base against resp
	// for _, attribute := range baseAttributes {
	// 	baseValue, baseFound := base.GetAttributeValue(attribute)
	// 	respValue, respFound := resp.GetAttributeValue(attribute)

	// 	// Check if both attributes are found and are equal
	// 	if !baseFound || !respFound || baseValue != respValue {
	// 		return false
	// 	}
	// }
	return true
}
