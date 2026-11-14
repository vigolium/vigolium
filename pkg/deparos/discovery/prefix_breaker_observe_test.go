package discovery

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/tracker"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

func breakerRC(t *testing.T, status int, ct, body string) *responsechain.ResponseChain {
	t.Helper()
	resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {ct}}, Body: io.NopCloser(strings.NewReader(body))}
	rc := responsechain.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rc.Close)
	return rc
}

// Ordinary 404s under /api must not trip the prefix breaker — brute-
// forcing /api/ on a server that answers 404 for misses sends the whole list.
// A uniform soft-403 subtree still trips.
func TestObservePrefixBreakerSkipsHardMisses(t *testing.T) {
	b := tracker.NewPrefixBreaker(tracker.DefaultBreakerConfig())
	for i := 0; i < 200; i++ {
		u, _ := url.Parse("http://h/api/w" + strconv.Itoa(i))
		observePrefixBreaker(b, u, breakerRC(t, 404, "text/html", "<html>Not Found</html>"))
	}
	if u, _ := url.Parse("http://h/api/users"); b.IsDead(u) {
		t.Fatal("/api must stay alive after ordinary 404 misses")
	}

	for i := 0; i < 20; i++ {
		u, _ := url.Parse("http://h/ftp/w" + strconv.Itoa(i))
		observePrefixBreaker(b, u, breakerRC(t, 403, "text/html", "<html>Forbidden</html>"))
	}
	if u, _ := url.Parse("http://h/ftp/x"); !b.IsDead(u) {
		t.Fatal("a uniform soft-403 subtree should trip")
	}
}
