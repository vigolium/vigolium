package httpmsg

import (
	"strings"
	"sync"
	"testing"
)

func newRespWithBody(body string) *HttpResponse {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
		intToString(len(body)) + "\r\n\r\n" + body
	return NewHttpResponse([]byte(raw))
}

func TestBodyMemo_Correctness(t *testing.T) {
	const body = "Hello WORLD <Script>AbC</Script>"
	r := newRespWithBody(body)

	if got := r.BodyToString(); got != body {
		t.Fatalf("BodyToString = %q, want %q", got, body)
	}
	// Repeated call returns the same content (memoized).
	if got := r.BodyToString(); got != body {
		t.Fatalf("BodyToString (2nd) = %q, want %q", got, body)
	}
	wantLower := strings.ToLower(body)
	if got := r.BodyLowerString(); got != wantLower {
		t.Fatalf("BodyLowerString = %q, want %q", got, wantLower)
	}
}

func TestBodyMemo_InvalidatedByTruncate(t *testing.T) {
	const body = "ABCDEFghij"
	r := newRespWithBody(body)

	// Populate the caches.
	if r.BodyToString() != body || r.BodyLowerString() != strings.ToLower(body) {
		t.Fatal("setup: unexpected pre-truncate body")
	}

	r.TruncateBody(3) // keep "ABC"

	if got := r.BodyToString(); got != "ABC" {
		t.Fatalf("BodyToString after truncate = %q, want %q", got, "ABC")
	}
	if got := r.BodyLowerString(); got != "abc" {
		t.Fatalf("BodyLowerString after truncate = %q, want %q", got, "abc")
	}
}

func TestBodyMemo_ConcurrentReadsRaceFree(t *testing.T) {
	const body = "Concurrent BODY content For Race Testing"
	r := newRespWithBody(body)
	wantLower := strings.ToLower(body)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.BodyToString() != body {
				t.Error("BodyToString mismatch under concurrency")
			}
			if r.BodyLowerString() != wantLower {
				t.Error("BodyLowerString mismatch under concurrency")
			}
		}()
	}
	wg.Wait()
}
