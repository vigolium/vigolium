package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterCredentialHeaders(t *testing.T) {
	t.Parallel()
	headers := []string{
		"Authorization: Bearer secret",
		"Cookie: session=secret",
		"X-Api-Key: secret",
		"X-Custom-Token: secret",
		"Accept-Language: en",
		"X-Tenant: public-routing-context",
	}
	assert.Equal(t, []string{
		"Accept-Language: en",
		"X-Tenant: public-routing-context",
	}, filterCredentialHeaders(headers))
}

func TestCredentialHeaderNameDoesNotDropUnrelatedAuthWords(t *testing.T) {
	t.Parallel()
	assert.False(t, credentialHeaderName("X-Author-Name"))
	assert.False(t, credentialHeaderName("Authentication-Info-Preference"))
	assert.True(t, credentialHeaderName("X-Session-Token"))
}
