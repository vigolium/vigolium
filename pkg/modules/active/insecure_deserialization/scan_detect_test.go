package insecure_deserialization

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// javaDeserErrorHandler simulates a backend that deserializes attacker input and
// leaks a Java ObjectInputStream stack trace — the error signature the module's
// error-based detection keys on.
func javaDeserErrorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Exception in thread: java.io.ObjectInputStream.readObject failed: " +
			"java.io.InvalidClassException local class incompatible"))
	}
}

// TestScanPerInsertionPoint_DetectsDeserError drives the real scan method against
// a server that leaks a deserialization error on a body parameter.
func TestScanPerInsertionPoint_DetectsDeserError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(javaDeserErrorHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=eyJhIjoxfQ==")
	ip := modtest.InsertionPoint(t, rr, "data")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a deserialization finding when a Java ObjectInputStream error is leaked")
	assert.Equal(t, "data", res[0].FuzzingParameter)
	assert.Contains(t, res[0].Info.Description, "Java")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never emits a
// deserialization error yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=eyJhIjoxfQ==")
	ip := modtest.InsertionPoint(t, rr, "data")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never leaks a deser error must not yield a finding")
}

// TestCheckDeserError exercises the pure error-matching helper, including the
// baseline-suppression branch and per-framework classification.
func TestCheckDeserError(t *testing.T) {
	t.Parallel()

	fw, ok := checkDeserError("java.io.ObjectInputStream.readObject", "")
	require.True(t, ok)
	assert.Equal(t, "Java", fw)

	fw, ok = checkDeserError(`PHP Fatal error in unserialize() at O:8:"stdClass"`, "")
	require.True(t, ok)
	assert.Equal(t, "PHP", fw)

	_, ok = checkDeserError("nothing interesting here", "")
	assert.False(t, ok, "benign body must not match")

	// Error already present in the baseline is suppressed.
	_, ok = checkDeserError("java.io.ObjectInputStream", "java.io.ObjectInputStream")
	assert.False(t, ok, "error present in baseline must be suppressed")
}
