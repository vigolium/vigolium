package modkit

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// StripCredentialHeaders returns a copy of a raw HTTP request without headers
// that commonly identify a user or carry an API/session credential. Pair it
// with http.Requester.CloneWithoutCredentials: the raw copy removes credentials
// captured in traffic, while the isolated requester prevents configured headers
// or cookie-jar state from being re-applied during transmission.
func StripCredentialHeaders(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	req := httpmsg.NewHttpRequest(raw)
	for _, header := range req.Headers() {
		if !credentialHeaderName(header.Name) {
			continue
		}
		var err error
		clean, err = httpmsg.RemoveHeader(clean, header.Name)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func credentialHeaderName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	switch normalized {
	case "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
		"x-api-token", "x-auth-token", "x-access-token", "x-session-token":
		return true
	}
	return strings.Contains(normalized, "credential") ||
		strings.HasSuffix(normalized, "-token") ||
		strings.HasSuffix(normalized, "-api-key") ||
		strings.HasSuffix(normalized, "-session-id")
}
