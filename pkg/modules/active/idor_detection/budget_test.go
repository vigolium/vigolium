package idor_detection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The per-host budget is charged only for points that are probed (MISS-18):
// sixty non-ID parameters seen first must not use up the 50-probe budget before
// the real id parameter gets its turn.
func TestBudgetChargedOnlyForObjectIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(r.URL.Query().Get("user_id"))))
	}))
	defer srv.Close()

	mgr := dedup.NewManager()
	t.Cleanup(mgr.Close)
	sc := &modkit.ScanContext{DedupManager: mgr}
	client := modtest.Requester(t)
	m := New()

	var q []string
	for i := 0; i < 60; i++ {
		q = append(q, fmt.Sprintf("note%d=hello", i))
	}
	q = append(q, "user_id=12345")
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/profile?"+strings.Join(q, "&")),
		"application/json", objectBody("12345"))

	for i := 0; i < 60; i++ {
		ip := modtest.InsertionPoint(t, rr, fmt.Sprintf("note%d", i))
		_, err := m.ScanPerInsertionPoint(rr, ip, client, sc)
		require.NoError(t, err)
	}
	res, err := m.ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "user_id"), client, sc)
	require.NoError(t, err)
	require.NotEmpty(t, res, "the id parameter after 60 non-ID parameters must still be tested")
}
