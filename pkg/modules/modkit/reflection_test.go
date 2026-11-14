package modkit_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// One shared canary probe per point: it reports body/header
// reflection, is memoised (two asks, one request), and keeps a numeric value
// numeric.
func TestReflectionProfile(t *testing.T) {
	var hits atomic.Int64
	numeric := regexp.MustCompile(`^7\d{9}$`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		q := r.URL.Query()
		if id := q.Get("id"); id != "" && id != "5" && !numeric.MatchString(id) {
			t.Errorf("numeric parameter got non-numeric canary %q", id)
		}
		w.Header().Set("X-Echo", q.Get("h"))
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body><p>"+q.Get("q")+"</p></body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/s?q=hello&h=x&id=5&n=z")
	sc := &modkit.ScanContext{}
	ctx := context.Background()

	pq, err := sc.ReflectionProfile(ctx, rr, modtest.InsertionPoint(t, rr, "q"), client)
	if err != nil || pq == nil || !pq.InBody || pq.InHeaders {
		t.Fatalf("q profile = %+v, %v", pq, err)
	}
	before := hits.Load()
	if again, _ := sc.ReflectionProfile(ctx, rr, modtest.InsertionPoint(t, rr, "q"), client); again != pq || hits.Load() != before {
		t.Fatal("profile not memoised per point")
	}
	ph, _ := sc.ReflectionProfile(ctx, rr, modtest.InsertionPoint(t, rr, "h"), client)
	if ph == nil || !ph.InHeaders || ph.InBody {
		t.Fatalf("h profile = %+v", ph)
	}
	pn, _ := sc.ReflectionProfile(ctx, rr, modtest.InsertionPoint(t, rr, "n"), client)
	if pn == nil || pn.Reflected() || pn.Satisfies(modkit.ReflectAny) {
		t.Fatalf("n profile = %+v", pn)
	}
	if _, err := sc.ReflectionProfile(ctx, rr, modtest.InsertionPoint(t, rr, "id"), client); err != nil {
		t.Fatal(err)
	}
}
