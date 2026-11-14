package httpmsg

// PreEncodedBuilder is implemented by insertion points that can inject a
// payload which is already encoded the way it must reach the server (see
// ParameterInsertionPoint.BuildRequestPreEncoded). Payload tables mark such
// entries explicitly (preEncoded) and build them through BuildPreEncoded.
type PreEncodedBuilder interface {
	BuildRequestPreEncoded(payload []byte) []byte
}

// BuildPreEncoded builds ip's request with a pre-encoded payload. Insertion
// points without a percent layer of their own (nested, base64/encoded
// wrappers, …) fall back to BuildRequest: their encoder is the transformation
// the payload has to pass through anyway.
func BuildPreEncoded(ip InsertionPoint, payload []byte) []byte {
	if pe, ok := ip.(PreEncodedBuilder); ok {
		return pe.BuildRequestPreEncoded(payload)
	}
	return ip.BuildRequest(payload)
}

// BuildPayload builds ip's request with payload, through BuildPreEncoded when
// preEncoded is set and BuildRequest otherwise — the one call payload-table
// loops make.
func BuildPayload(ip InsertionPoint, payload []byte, preEncoded bool) []byte {
	if preEncoded {
		return BuildPreEncoded(ip, payload)
	}
	return ip.BuildRequest(payload)
}

// appendMinimalEncoded appends src to dst escaping only what cannot appear
// literally in a request line or URL-encoded body: control bytes (< 0x20 and
// 0x7f), space, '#' and bytes >= 0x80. '%' and every other printable byte
// pass through, so a payload's own percent-encoding survives.
func appendMinimalEncoded(dst, src []byte) []byte {
	for _, ch := range src {
		if ch < 0x20 || ch == 0x7f || ch == ' ' || ch == '#' || ch >= 0x80 {
			dst = append(dst, '%', hexUpper[ch>>4], hexUpper[ch&0x0F])
			continue
		}
		dst = append(dst, ch)
	}
	return dst
}

// appendCTLEscaped percent-escapes only control bytes (CR, LF, NUL, …).
func appendCTLEscaped(dst, src []byte) []byte {
	for _, ch := range src {
		if ch < 0x20 || ch == 0x7f {
			dst = append(dst, '%', hexUpper[ch>>4], hexUpper[ch&0x0F])
			continue
		}
		dst = append(dst, ch)
	}
	return dst
}
