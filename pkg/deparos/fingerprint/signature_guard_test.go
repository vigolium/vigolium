package fingerprint

import (
	"testing"
)

// A baseline learned during a 429 burst, with an unstable status, or
// from bodies too varied to leave 3 stable attributes is refused; an empty
// signature never matches.
func TestNewSignatureRefusesUnusableBaselines(t *testing.T) {
	mk := func(status uint32, throttled bool, bodyLen int, body uint32) *Sample {
		return &Sample{
			attributes: map[Attribute]uint32{StatusCode: status, BodyContent: body, ContentType: 7},
			throttled:  throttled,
			bodyLen:    bodyLen,
		}
	}
	if _, err := NewSignature([]*Sample{mk(429, true, 10, 1), mk(429, true, 10, 1), mk(429, true, 10, 1)}); err == nil {
		t.Error("throttled samples must not become a baseline")
	}
	if _, err := NewSignature([]*Sample{mk(404, false, 10, 1), mk(200, false, 10, 1), mk(404, false, 10, 1)}); err == nil {
		t.Error("unstable status must not become a baseline")
	}
	// Status and content type stable, body varies: 2 stable attributes.
	if _, err := NewSignature([]*Sample{mk(200, false, 10, 1), mk(200, false, 12, 2), mk(200, false, 14, 3)}); err == nil {
		t.Error("a near-empty signature over bodied samples must be refused")
	}
	if sig, err := NewSignature([]*Sample{mk(404, false, 10, 1), mk(404, false, 10, 1), mk(404, false, 10, 1)}); err != nil || sig == nil {
		t.Errorf("a stable baseline must still be learned: %v", err)
	}

	empty := &Signature{stable: map[Attribute]uint32{}}
	if empty.Matches(mk(200, false, 10, 1)) {
		t.Error("an empty signature must not match")
	}
}
