package anomaly

import (
	"hash/crc32"
	"sort"
	"strings"
)

// line_count
func getLineCount(content string) uint32 {
	return uint32(strings.Count(content, "\n"))
}

func getWordCount(content string) uint32 {
	return uint32(strings.Count(content, " "))
}

// content_type
// Input with headers map lower case
// This only get the type "text/html;charset=utf-8" => text/html
func getContentType(headers map[string][]string) uint32 {
	if value, found := headers["Content-Type"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

func getContentTypeValue(headers map[string][]string) string {
	if value, found := headers["Content-Type"]; found {
		if len(value) > 0 {
			split := strings.SplitN(value[0], ";", 2)
			if len(split) > 0 {
				return split[0]
			}
		}
	}
	return ""
}

func getContentLocation(headers map[string][]string) uint32 {
	if value, found := headers["Content-Location"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

// etag_header
func getEtagHeader(headers map[string][]string) uint32 {
	if value, found := headers["Etag"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

// last_modified_header
func getLastModifiedHeader(headers map[string][]string) uint32 {
	if value, found := headers["Last-Modified"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

// content_length
// func getContentLength(headers map[string]string) uint32 {
// 	if value, found := headers["content-length"]; found {
// 		return ChecksumCRC32(value)
// 	}
// 	return 0
// }

// location
func getLocation(headers map[string][]string) uint32 {
	if value, found := headers["Location"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

// server
func getServerHeader(headers map[string][]string) uint32 {
	if value, found := headers["Server"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

func getStatusCodeText(headers map[string][]string) uint32 {
	if value, found := headers["status_code_text"]; found {
		if len(value) > 0 {
			return checksumCRC32(value[0])
		}
	}
	return 0
}

// set_cookie_names
func getSetCookieNames(headers map[string][]string) uint32 {
	var raw string
	keys := make([]string, 0)
	if value, found := headers["Set-Cookie"]; found {
		for _, v := range value {
			// replit value by =
			split := strings.SplitN(v, "=", 2)
			if len(split) == 2 {
				keys = append(keys, split[0])
			}
		}
	}
	sort.Strings(keys)

	for _, key := range keys {
		raw += key
		raw += "|"
	}
	return checksumCRC32(raw)
}

// whole_body_content
func getWholeBodyContent(content string) uint32 {
	return checksumCRC32(content)
}

// limited_body_content
func getLimitedBodyContent(content string) uint32 {
	contentByte := s2b(content)
	contentLen := len(contentByte)
	sum := crc32.NewIEEE()
	if contentLen < 2048 {
		sum.Write(contentByte)
	} else {
		sum.Write(contentByte[0:1024])                       // first 1024 bytes
		sum.Write(contentByte[contentLen-1024 : contentLen]) // last 1024 bytes
	}
	return sum.Sum32()
}

// initial_body_content
// get first 32 bytes only
func getInitialBodyContent(content string) uint32 {
	limit := 32
	if len(content) < limit {
		limit = len(content)
	}
	return checksumCRC32(content[:limit])
}
