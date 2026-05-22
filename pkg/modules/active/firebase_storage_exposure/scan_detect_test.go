package firebase_storage_exposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// NEEDS-PHASE-3: positive detection probes the real
// firebasestorage.googleapis.com and storage.googleapis.com REST endpoints for
// a bucket extracted from the seed response. Those raw requests target fixed
// external Google hosts with no service/host override, so detection cannot be
// driven against an in-process httptest server; it requires a live (or
// DNS-mocked) GCS/Firebase Storage endpoint returning a public listing.

// TestNew_Metadata verifies module construction and identity.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.NotEmpty(t, m.Name())
	assert.NotEmpty(t, m.ModuleTags)
}

// TestCanProcess covers the response-required guard.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no response attached should be rejected")

	withResp := modtest.Response(rr, "text/html", "<html></html>")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerRequest_NoBucket ensures a body with no Firebase storage bucket
// references short-circuits with no finding and no outbound probe.
func TestScanPerRequest_NoBucket(t *testing.T) {
	t.Parallel()
	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, "http://example.com/"),
		"text/html",
		"<html><body>no buckets here</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no storage bucket in body must yield no finding")
}

// TestStorageBucketRegex confirms bucket extraction from a Firebase config blob.
func TestStorageBucketRegex(t *testing.T) {
	t.Parallel()
	m := storageBucketRe.FindStringSubmatch(`"storageBucket":"demo-app.appspot.com"`)
	require.Len(t, m, 2)
	assert.Equal(t, "demo-app.appspot.com", m[1])

	m2 := storageBucketRe2.FindStringSubmatch("https://firebasestorage.googleapis.com/v0/b/demo-app.appspot.com")
	require.Len(t, m2, 2)
	assert.Equal(t, "demo-app.appspot.com", m2[1])
}
