package httpmsg

import (
	"sync"
	"testing"
)

// The parsed document is computed once per response and shared (ECON-14);
// TruncateBody invalidates it.
func TestHTMLDocumentMemoised(t *testing.T) {
	r := NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><a href=/x>x</a></body></html>"))
	var wg sync.WaitGroup
	docs := make([]any, 8)
	for i := range docs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, err := r.HTMLDocument()
			if err != nil {
				t.Error(err)
			}
			docs[i] = d
		}(i)
	}
	wg.Wait()
	for _, d := range docs[1:] {
		if d != docs[0] {
			t.Fatal("HTMLDocument returned different trees for one response")
		}
	}
	first, _ := r.HTMLDocument()
	r.TruncateBody(5)
	again, _ := r.HTMLDocument()
	if again == first {
		t.Fatal("TruncateBody did not invalidate the parsed document")
	}
}
