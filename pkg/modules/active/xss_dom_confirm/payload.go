package xss_dom_confirm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const canaryLen = 6

// Payload is a single XSS attempt with a unique canary token. The canary
// appears verbatim inside the alert() argument so a fired dialog can be
// distinguished from any pre-existing alerts on the page.
type Payload struct {
	Canary string
	Body   string // injected into the insertion point
	Hash   string // appended to the URL fragment for DOM-source paths
}

func NewPayload() (*Payload, error) {
	buf := make([]byte, canaryLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	canary := "vig-x-" + hex.EncodeToString(buf)
	body := fmt.Sprintf(`"'><svg/onload=alert(%q)>//`, canary)
	hash := fmt.Sprintf(`<svg/onload=alert(%q)>`, canary)
	return &Payload{Canary: canary, Body: body, Hash: hash}, nil
}
