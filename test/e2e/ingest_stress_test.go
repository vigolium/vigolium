//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/server"
)

func TestAPI_Ingest_BurpBase64_10000Concurrent(t *testing.T) {
	env := newAPITestEnv(t, "")

	const totalRequests = 10000
	const maxConcurrency = 50

	// Pre-build all payloads to keep timing focused on the HTTP path.
	type payload struct {
		body string
	}
	payloads := make([]payload, totalRequests)
	for i := 0; i < totalRequests; i++ {
		rawReq := fmt.Sprintf("POST /api/endpoint-%d HTTP/1.1\r\nHost: target.example.com\r\nContent-Type: application/json\r\n\r\n{\"id\":%d,\"action\":\"test\"}", i, i)
		rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"id\":%d}", i)
		b64Req := base64.StdEncoding.EncodeToString([]byte(rawReq))
		b64Resp := base64.StdEncoding.EncodeToString([]byte(rawResp))

		payloads[i] = payload{
			body: fmt.Sprintf(`{"input_mode":"burp_base64","http_request_base64":"%s","http_response_base64":"%s","url":"https://target.example.com:443"}`, b64Req, b64Resp),
		}
	}

	// Semaphore to limit in-flight HTTP connections.
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64

	start := time.Now()

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		sem <- struct{}{} // acquire
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }() // release

			req, err := http.NewRequest(http.MethodPost, env.url+"/api/ingest-http", strings.NewReader(payloads[idx].body))
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			var body server.IngestHTTPResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			if body.Imported != 1 {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			atomic.AddInt64(&successCount, 1)
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("Completed %d requests in %s (%.0f req/s)", totalRequests, elapsed, float64(totalRequests)/elapsed.Seconds())
	t.Logf("Success: %d, Errors: %d", successCount, errorCount)

	// All requests must succeed.
	assert.Equal(t, int64(0), errorCount, "expected zero HTTP errors")
	assert.Equal(t, int64(totalRequests), successCount, "expected all requests to return imported=1")

	// All records must be in the DB.
	dbCount := env.countRecords(t)
	assert.Equal(t, totalRequests, dbCount, "expected %d records in DB, got %d", totalRequests, dbCount)

	// Verify URL override applied correctly on all records.
	var records []database.HTTPRecord
	err := env.db.NewSelect().
		Model(&records).
		Column("scheme", "hostname", "port").
		Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, records, totalRequests)

	for i, rec := range records {
		assert.Equal(t, "https", rec.Scheme, "record %d: expected scheme=https", i)
		assert.Equal(t, "target.example.com", rec.Hostname, "record %d: expected hostname=target.example.com", i)
		assert.Equal(t, 443, rec.Port, "record %d: expected port=443", i)
	}
}
