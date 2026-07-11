package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func saveJSResp(t *testing.T, repo *Repository, projectUUID, host, path, contentType, body string) {
	t.Helper()
	ctx := context.Background()
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	rr = rr.WithResponse(httpmsg.NewHttpResponse(
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\n\r\n" + body)))
	if _, err := repo.SaveRecord(ctx, rr, "spider", projectUUID); err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
}

// TestWalkJavaScriptRecords backs the browser→JSTangle discovery bridge: the DB
// query must surface JavaScript captured for the in-scope host (by content-type
// OR .js/.mjs URL), decode its body, and never leak the HTML page or another
// host's JS.
func TestWalkJavaScriptRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	saveJSResp(t, repo, DefaultProjectUUID, "app.example.com", "/assets/app.bundle", "application/javascript", "fetch('/api/users')")
	saveJSResp(t, repo, DefaultProjectUUID, "app.example.com", "/static/vendor.js", "text/plain", "axios.get('/api/orders')") // JS by URL suffix
	saveJSResp(t, repo, DefaultProjectUUID, "app.example.com", "/index.html", "text/html", "<html>not js</html>")             // skip
	saveJSResp(t, repo, DefaultProjectUUID, "other.example.com", "/x.js", "application/javascript", "fetch('/leak')")         // out of scope

	var got []string
	bodies := map[string]string{}
	err := repo.WalkJavaScriptRecords(ctx, DefaultProjectUUID, "app.example.com", 100,
		func(recordURL, contentType string, body []byte) error {
			got = append(got, recordURL)
			bodies[recordURL] = string(body)
			return nil
		})
	if err != nil {
		t.Fatalf("WalkJavaScriptRecords: %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 {
		t.Fatalf("walked %d JS records, want 2: %v", len(got), got)
	}
	for _, u := range got {
		if !strings.Contains(u, "app.example.com") {
			t.Errorf("out-of-scope URL walked: %s", u)
		}
	}
	joined := bodies[got[0]] + "\n" + bodies[got[1]]
	if !strings.Contains(joined, "fetch('/api/users')") || !strings.Contains(joined, "axios.get('/api/orders')") {
		t.Errorf("decoded JS bodies missing expected source: %v", bodies)
	}

	// A callback error stops the walk and propagates.
	sentinel := fmt.Errorf("stop")
	if err := repo.WalkJavaScriptRecords(ctx, DefaultProjectUUID, "app.example.com", 100,
		func(string, string, []byte) error { return sentinel }); err != sentinel {
		t.Fatalf("callback error not propagated: %v", err)
	}

	// Empty host and nil callback are safe no-ops.
	if err := repo.WalkJavaScriptRecords(ctx, DefaultProjectUUID, "", 100, func(string, string, []byte) error { return nil }); err != nil {
		t.Fatalf("empty host should be a no-op: %v", err)
	}
	if err := repo.WalkJavaScriptRecords(ctx, DefaultProjectUUID, "app.example.com", 100, nil); err != nil {
		t.Fatalf("nil callback should be a no-op: %v", err)
	}
}
