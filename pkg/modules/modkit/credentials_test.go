package modkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripCredentialHeaders(t *testing.T) {
	t.Parallel()
	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secret\r\nCookie: sid=secret\r\nX-Custom-Token: secret\r\nAccept: text/html\r\n\r\n")

	clean, err := StripCredentialHeaders(raw)
	require.NoError(t, err)
	assert.Equal(t, "GET / HTTP/1.1\r\nHost: example.test\r\nAccept: text/html\r\n\r\n", string(clean))
}

func TestStripCredentialHeadersSecretAndSignatureShapes(t *testing.T) {
	t.Parallel()
	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\nX-Client-Secret: s\r\nX-Signature: sig\r\nX-Auth: a\r\nApi-Secret: s\r\nX-Trace: keep\r\n\r\n")

	clean, err := StripCredentialHeaders(raw)
	require.NoError(t, err)
	assert.Equal(t, "GET / HTTP/1.1\r\nHost: example.test\r\nX-Trace: keep\r\n\r\n", string(clean))
}
