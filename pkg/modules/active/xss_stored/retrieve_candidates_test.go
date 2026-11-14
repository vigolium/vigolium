package xss_stored

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestRetrieveCandidates(t *testing.T) {
	raw := "POST /posts/17/comments/new HTTP/1.1\r\nHost: app.test\r\nReferer: https://app.test/posts/17\r\n\r\n"
	rr := httpmsg.NewRequestResponseRaw([]byte(raw), httpmsg.NewServiceSecure("app.test", 443, true))
	got := retrieveCandidates(rr, nil)
	want := []string{
		"https://app.test/posts/17/comments/new",
		"https://app.test/posts/17",
		"https://app.test/posts/17/comments/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}

	// An out-of-scope Referer is never read.
	raw = "POST /c HTTP/1.1\r\nHost: app.test\r\nReferer: https://evil.test/x\r\n\r\n"
	rr = httpmsg.NewRequestResponseRaw([]byte(raw), httpmsg.NewServiceSecure("app.test", 443, true))
	for _, c := range retrieveCandidates(rr, func(string) bool { return false }) {
		if c == "https://evil.test/x" {
			t.Fatal("out-of-scope Referer used as a retrieval page")
		}
	}
}

// A comment posted to /comments/new renders on the collection page /comments/
// only; the old submit-URL-only retrieval never saw it.
func TestStoredXSS_RendersOnCollectionPage(t *testing.T) {
	var mu sync.Mutex
	var stored string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/comments/new":
			mu.Lock()
			stored = r.PostFormValue("c")
			mu.Unlock()
			_, _ = w.Write([]byte("<html>saved</html>"))
		case r.URL.Path == "/comments/":
			mu.Lock()
			s := stored
			mu.Unlock()
			_, _ = w.Write([]byte("<html><body>" + s + "</body></html>"))
		default:
			_, _ = w.Write([]byte("<html>form</html>"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/comments/new", "c=hello")
	ip := modtest.InsertionPoint(t, rr, "c")
	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected a stored-XSS finding via the collection page, got %d", len(res))
	}
}
