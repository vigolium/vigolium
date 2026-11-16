package modkit

import (
	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// StripCredentialHeaders returns a copy of a raw HTTP request without headers
// that commonly identify a user or carry an API/session credential
// (redact.IsSensitiveHeader). Pair it with
// http.Requester.CloneWithoutCredentials: the raw copy removes credentials
// captured in traffic, while the isolated requester prevents configured headers
// or cookie-jar state from being re-applied during transmission.
func StripCredentialHeaders(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	req := httpmsg.NewHttpRequest(raw)
	for _, header := range req.Headers() {
		if !redact.IsSensitiveHeader(header.Name) {
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
