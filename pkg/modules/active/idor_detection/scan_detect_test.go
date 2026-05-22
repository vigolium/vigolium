package idor_detection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// objectBody renders a fixed-width object body for the given id so that the
// baseline and neighbor responses are structurally identical (same status, near
// identical length) yet have different content — exactly the IDOR signal the
// module looks for. The "email" field guarantees the body is well over the
// module's 50-byte floor.
func objectBody(id string) string {
	return fmt.Sprintf("{\"user_id\":\"%5s\",\"email\":\"user%5s@example.com\",\"pad\":%q}",
		id, id, strings.Repeat("x", 200))
}

// TestScanPerInsertionPoint_DetectsIDOR drives the real scan method against a
// backend that serves a valid object for any neighbor user_id. The module
// classifies user_id=12345 as a predictable object id, probes 12344/12346/...,
// and reports because the neighbor returns a structurally similar 200 with
// different content.
func TestScanPerInsertionPoint_DetectsIDOR(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("user_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(id)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an IDOR finding when neighbor user_ids return distinct, structurally similar objects")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a backend that enforces
// authorization (403 for any id but the owner's) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("user_id") != "12345" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody("12345")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "403 for neighbor user_ids means authorization is enforced — no finding")
}
