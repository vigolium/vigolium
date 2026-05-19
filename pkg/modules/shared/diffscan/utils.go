package diffscan

import "bytes"

func CountMatches(response, match []byte) int {
	matches := 0

	start := 0
	for start < len(response) {
		index := bytes.Index(response[start:], match)
		if index == -1 {
			break
		}
		matches++
		start += index + len(match)
	}

	return matches
}
