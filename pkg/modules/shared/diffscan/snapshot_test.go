package diffscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/anomaly"
)

func TestResponseSnapshot_IsRedirect(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{200, false},
		{299, false},
		{300, true},
		{301, true},
		{302, true},
		{307, true},
		{308, true},
		{399, true},
		{400, false},
		{403, false},
		{500, false},
	}
	for _, c := range cases {
		s := &ResponseSnapshot{StatusCode: c.status}
		assert.Equalf(t, c.want, s.IsRedirect(), "status %d", c.status)
	}

	var nilSnap *ResponseSnapshot
	assert.False(t, nilSnap.IsRedirect(), "nil snapshot is not a redirect")
}

func TestResponseSnapshot_IsSuccess(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{199, false},
		{200, true},
		{204, true},
		{299, true},
		{300, false},
		{301, false},
		{400, false},
		{403, false},
		{404, false},
		{500, false},
	}
	for _, c := range cases {
		s := &ResponseSnapshot{StatusCode: c.status}
		assert.Equalf(t, c.want, s.IsSuccess(), "status %d", c.status)
	}

	var nilSnap *ResponseSnapshot
	assert.False(t, nilSnap.IsSuccess(), "nil snapshot is not a success")
}

func TestAllRedirects(t *testing.T) {
	redirect := func(code int) *Attack {
		return &Attack{FirstSnapshot: &ResponseSnapshot{StatusCode: code}}
	}

	assert.False(t, allRedirects(nil), "empty set is not all-redirects")
	assert.True(t, allRedirects([]*Attack{redirect(301), redirect(302)}))
	assert.False(t, allRedirects([]*Attack{redirect(301), {FirstSnapshot: &ResponseSnapshot{StatusCode: 200}}}),
		"a 200 alongside redirects breaks the all-redirects condition (real status transition)")
	assert.False(t, allRedirects([]*Attack{redirect(301), nil}), "nil attack breaks the condition")
	assert.False(t, allRedirects([]*Attack{{FirstSnapshot: nil}}), "missing snapshot breaks the condition")
}

// TestDiffScanFingerprintExcludesReflectionProne is the regression guard for the
// diff-based SSTI false positives: the reflection-prone header attributes
// (Location / Content-Location / canonical link) must NOT be part of the
// comparison set, otherwise a payload echoed into the redirect target makes
// break and escape responses differ without any template evaluation.
func TestDiffScanFingerprintExcludesReflectionProne(t *testing.T) {
	excluded := map[anomaly.Type]bool{
		// reflection-prone header attributes
		anomaly.LOCATION:         true,
		anomaly.CONTENT_LOCATION: true,
		anomaly.CANONICAL_LINK:   true,
		// per-request volatile attributes
		anomaly.SET_COOKIE_NAMES: true,
	}
	for _, attr := range diffScanFingerprintTypes {
		assert.Falsef(t, excluded[attr], "reflection-prone / volatile attribute %q must be excluded from diffScanFingerprintTypes", attr.String())
	}

	// Sanity: a non-reflection structural attribute is still present, so we did
	// not accidentally empty the set.
	var hasStatus, hasBody bool
	for _, attr := range diffScanFingerprintTypes {
		switch attr {
		case anomaly.STATUS_CODE:
			hasStatus = true
		case anomaly.WHOLE_BODY_CONTENT:
			hasBody = true
		}
	}
	assert.True(t, hasStatus, "status_code must remain in the comparison set")
	assert.True(t, hasBody, "whole_body_content must remain in the comparison set")
	assert.Len(t, diffScanFingerprintTypes, len(anomaly.AllFingerprintAttributes)-len(excluded),
		"exactly the reflection-prone and volatile attributes should be removed")
}

func TestExcludeAttributes(t *testing.T) {
	all := []anomaly.Type{anomaly.STATUS_CODE, anomaly.LOCATION, anomaly.WORD_COUNT}
	got := excludeAttributes(all, anomaly.LOCATION)
	assert.Equal(t, []anomaly.Type{anomaly.STATUS_CODE, anomaly.WORD_COUNT}, got)

	// Excluding nothing returns the same elements in order.
	assert.Equal(t, all, excludeAttributes(all))
}
