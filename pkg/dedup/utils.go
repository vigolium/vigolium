package dedup

import (
	"hash/fnv"
	"strconv"
)

// FNVHash returns FNV-1a 64-bit hash as hex string.
func FNVHash(input string) string {
	h := fnv.New64a()
	h.Write([]byte(input))
	return strconv.FormatUint(h.Sum64(), 16)
}
