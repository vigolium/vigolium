package http

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/types"
)

// The anonymous view strips every header the shared classifier
// (redact.IsSensitiveHeader) flags, including the -secret/-signature and auth
// shapes, and keeps request-shape headers.
func TestStripCredentialHeaderMapUsesSharedClassifier(t *testing.T) {
	t.Parallel()
	got := stripCredentialHeaderMap(map[string]string{
		"X-Session-Token": "t", "X-Client-Secret": "s", "X-Signature": "sig", "X-Auth": "a",
		"Api-Secret": "s", "Content-Type": "application/json", "X-Trace": "keep",
	})
	assert.Equal(t, map[string]string{"Content-Type": "application/json", "X-Trace": "keep"}, got)
}

// TestCloneWithoutCredentials_SharesTransportIsolatesCreds verifies the anonymous
// view shares the scan-scoped transport and observation state (so probes reuse the
// pool and stay visible to scan-wide corroboration/pacing) while isolating only the
// credential surface — a fresh cookie jar and credential-stripped headers (CR-04).
func TestCloneWithoutCredentials_SharesTransportIsolatesCreds(t *testing.T) {
	opts := types.DefaultOptions()
	opts.Headers = []string{"Authorization: Bearer secret", "X-Trace: keep"}
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r, err := NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}

	view, err := r.CloneWithoutCredentials()
	if err != nil {
		t.Fatalf("CloneWithoutCredentials: %v", err)
	}

	// Shares the scan-scoped transport + observation state.
	if view.client.HTTPClient.Transport != r.client.HTTPClient.Transport {
		t.Error("view must share the parent transport (connection pool)")
	}
	if view.clientNoRedir.HTTPClient.Transport != r.clientNoRedir.HTTPClient.Transport {
		t.Error("view must share the no-redirect transport too")
	}
	if view.edgePacer != r.edgePacer {
		t.Error("view must share the edge-pacing dedup")
	}
	if view.respObserver != r.respObserver {
		t.Error("view must share the response observer (scan-wide 5xx corroboration)")
	}
	if view.blockNotifier != r.blockNotifier {
		t.Error("view must share the block notifier")
	}
	if view.rawClient != r.rawClient {
		t.Error("view must share the raw client")
	}

	// Isolates the credential surface.
	if view.client.HTTPClient.Jar == r.client.HTTPClient.Jar {
		t.Error("view must have its own cookie jar, not the authenticated one")
	}
	if _, ok := view.customHeaders["Authorization"]; ok {
		t.Error("view must drop the Authorization header")
	}
	if view.customHeaders["X-Trace"] != "keep" {
		t.Error("view must keep non-credential headers")
	}
	// The parent keeps its credential header.
	if r.customHeaders["Authorization"] != "Bearer secret" {
		t.Error("parent requester must retain its Authorization header")
	}
}
