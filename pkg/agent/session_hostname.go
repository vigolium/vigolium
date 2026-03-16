package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// AgentSessionConfigToSessionHostnames converts an AgentSessionConfig (from source analysis output)
// into a slice of database.SessionHostname rows ready for persistence.
func AgentSessionConfigToSessionHostnames(cfg *AgentSessionConfig, projectUUID, scanUUID, hostname, source string) []*database.SessionHostname {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return nil
	}

	rows := make([]*database.SessionHostname, 0, len(cfg.Sessions))
	for i, entry := range cfg.Sessions {
		sh := &database.SessionHostname{
			ProjectUUID: projectUUID,
			ScanUUID:    scanUUID,
			Hostname:    hostname,
			SessionName: entry.Name,
			SessionRole: entry.Role,
			Position:    i,
			Headers:     entry.Headers,
			Source:      source,
		}

		if entry.Login != nil {
			sh.LoginURL = entry.Login.URL
			sh.LoginMethod = entry.Login.Method
			sh.LoginContentType = entry.Login.ContentType
			sh.LoginBody = entry.Login.Body

			if len(entry.Login.Extract) > 0 {
				if data, err := json.Marshal(entry.Login.Extract); err == nil {
					sh.ExtractRules = string(data)
				}
			}
		}

		rows = append(rows, sh)
	}

	return rows
}

// SessionConfigToHTTPRecords converts login flows from an AgentSessionConfig into
// AgentHTTPRecord entries suitable for ingestion into the http_records table.
// Each session entry with a login flow produces one HTTP record for the login URL.
func SessionConfigToHTTPRecords(cfg *AgentSessionConfig) []AgentHTTPRecord {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var records []AgentHTTPRecord

	for _, entry := range cfg.Sessions {
		if entry.Login == nil || entry.Login.URL == "" {
			continue
		}

		// Deduplicate by method+url (multiple sessions may share the same login endpoint)
		key := entry.Login.Method + " " + entry.Login.URL
		if seen[key] {
			continue
		}
		seen[key] = true

		method := entry.Login.Method
		if method == "" {
			method = "POST"
		}

		rec := AgentHTTPRecord{
			Method: method,
			URL:    entry.Login.URL,
			Notes:  "login endpoint for session: " + entry.Name,
		}

		if entry.Login.ContentType != "" {
			rec.Headers = map[string]string{
				"Content-Type": entry.Login.ContentType,
			}
		}

		if entry.Login.Body != "" {
			rec.Body = entry.Login.Body
		}

		records = append(records, rec)
	}

	return records
}

// AuthHeadersFromSessionHostnames extracts auth headers from DB SessionHostname rows.
// It prefers the row with role "primary"; if none exists, it falls back to the first
// row that has non-empty Headers.
func AuthHeadersFromSessionHostnames(rows []*database.SessionHostname) map[string]string {
	if len(rows) == 0 {
		return nil
	}

	// Look for a "primary" role row with headers first.
	for _, r := range rows {
		if r.SessionRole == "primary" && len(r.Headers) > 0 {
			return r.Headers
		}
	}

	// Fallback: first row with non-empty headers.
	for _, r := range rows {
		if len(r.Headers) > 0 {
			return r.Headers
		}
	}

	return nil
}

// authHeaderNames are the header names treated as authentication headers.
var authHeaderNames = map[string]bool{
	"authorization": true,
	"cookie":        true,
}

// isAuthHeader returns true if the header name (case-insensitive) is an auth header.
func isAuthHeader(name string) bool {
	return authHeaderNames[strings.ToLower(name)]
}

// ReplaceAuthHeadersInRecords replaces Authorization and Cookie headers in AgentHTTPRecord
// slices with headers from session_hostnames DB rows. Only replaces if sessionHeaders
// is non-empty; otherwise returns records unchanged.
func ReplaceAuthHeadersInRecords(records []AgentHTTPRecord, sessionHeaders map[string]string) []AgentHTTPRecord {
	if len(sessionHeaders) == 0 {
		return records
	}

	// Build a map of session auth headers keyed by lowercase name.
	sessionAuth := make(map[string]string) // lowercase name -> value
	sessionAuthOriginal := make(map[string]string) // lowercase name -> original cased name
	for k, v := range sessionHeaders {
		lower := strings.ToLower(k)
		if isAuthHeader(lower) {
			sessionAuth[lower] = v
			sessionAuthOriginal[lower] = k
		}
	}
	if len(sessionAuth) == 0 {
		return records
	}

	replaced := 0
	for i, rec := range records {
		if len(rec.Headers) == 0 {
			continue
		}

		// Check if this record has any auth headers to replace.
		hasStaleAuth := false
		for k := range rec.Headers {
			if isAuthHeader(k) {
				hasStaleAuth = true
				break
			}
		}
		if !hasStaleAuth {
			continue
		}

		// Copy headers, replacing auth headers with session values.
		newHeaders := make(map[string]string, len(rec.Headers))
		for k, v := range rec.Headers {
			if isAuthHeader(k) {
				// Skip — will be replaced by session header below.
				continue
			}
			newHeaders[k] = v
		}
		for lower, val := range sessionAuth {
			newHeaders[sessionAuthOriginal[lower]] = val
		}

		records[i].Headers = newHeaders
		replaced++
	}

	if replaced > 0 {
		zap.L().Info("Replaced auth headers in agent records from session",
			zap.Int("replaced", replaced), zap.Int("total", len(records)))
	}

	return records
}

// ReplaceAuthHeadersInHTTPRR replaces Authorization and Cookie headers in
// httpmsg.HttpRequestResponse slices with headers from session data.
// Modifies records in place.
func ReplaceAuthHeadersInHTTPRR(records []*httpmsg.HttpRequestResponse, sessionHeaders map[string]string) {
	if len(sessionHeaders) == 0 || len(records) == 0 {
		return
	}

	// Build a map of session auth headers keyed by lowercase name.
	sessionAuth := make(map[string]string) // lowercase name -> value
	sessionAuthOriginal := make(map[string]string) // lowercase name -> original cased name
	for k, v := range sessionHeaders {
		lower := strings.ToLower(k)
		if isAuthHeader(lower) {
			sessionAuth[lower] = v
			sessionAuthOriginal[lower] = k
		}
	}
	if len(sessionAuth) == 0 {
		return
	}

	replaced := 0
	for i, rr := range records {
		if rr.Request() == nil {
			continue
		}

		// Check if this record has any auth headers that need replacing.
		hasStaleAuth := false
		for _, h := range rr.Request().Headers() {
			if isAuthHeader(h.Name) {
				hasStaleAuth = true
				break
			}
		}
		if !hasStaleAuth {
			continue
		}

		// Remove existing auth headers and add session ones.
		newReq := rr.Request()
		for _, h := range rr.Request().Headers() {
			if isAuthHeader(h.Name) {
				newReq = newReq.WithRemovedHeader(h.Name)
			}
		}
		for lower, val := range sessionAuth {
			newReq = newReq.WithAddedHeader(sessionAuthOriginal[lower], val)
		}

		records[i] = httpmsg.NewHttpRequestResponse(newReq, rr.Response())
		replaced++
	}

	if replaced > 0 {
		zap.L().Info("Replaced auth headers in HTTP records from session",
			zap.Int("replaced", replaced), zap.Int("total", len(records)))
	}
}

// ReprobeUnprobedRecords queries the database for HTTP records that have no response
// (has_response=false) for the given source and hostname, then probes them concurrently
// to populate status codes and response bodies.
func ReprobeUnprobedRecords(ctx context.Context, repo *database.Repository, projectUUID, hostname string, authHeaders map[string]string, source string) {
	if repo == nil {
		return
	}

	unprobed, err := repo.GetUnprobedRecordsBySource(ctx, projectUUID, source, hostname, 200)
	if err != nil {
		zap.L().Debug("Failed to query unprobed records", zap.String("source", source), zap.Error(err))
		return
	}
	if len(unprobed) == 0 {
		return
	}

	zap.L().Info("Re-probing unprobed records", zap.String("source", source), zap.Int("count", len(unprobed)))

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var updated atomic.Int64

	for _, rec := range unprobed {
		if rec.URL == "" || rec.Method == "" {
			continue
		}

		wg.Add(1)
		go func(rec *database.HTTPRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			httpReq, reqErr := http.NewRequestWithContext(ctx, rec.Method, rec.URL, nil)
			if reqErr != nil {
				return
			}

			// Apply auth headers to re-probe requests.
			for k, v := range authHeaders {
				httpReq.Header.Set(k, v)
			}

			resp, doErr := client.Do(httpReq)
			if doErr != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()

			const maxBody = 2 * 1024 * 1024
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			if readErr != nil {
				return
			}

			// Build raw HTTP response.
			var rawResp bytes.Buffer
			fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
			for k, vals := range resp.Header {
				for _, v := range vals {
					fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
				}
			}
			rawResp.WriteString("\r\n")
			rawResp.Write(body)

			contentType := resp.Header.Get("Content-Type")
			headers := resp.Header.Clone()

			update := &database.RecordResponseUpdate{
				StatusCode:            resp.StatusCode,
				StatusPhrase:          resp.Status,
				ResponseHTTPVersion:   resp.Proto,
				ResponseHeaders:       headers,
				ResponseContentType:   contentType,
				ResponseContentLength: int64(len(body)),
				RawResponse:           rawResp.Bytes(),
				ResponseBody:          body,
			}

			if updateErr := repo.UpdateRecordResponse(ctx, rec.UUID, update); updateErr != nil {
				zap.L().Debug("Failed to update re-probed record", zap.Error(updateErr))
				return
			}

			updated.Add(1)
		}(rec)
	}

	wg.Wait()
	if n := updated.Load(); n > 0 {
		zap.L().Info("Re-probed records", zap.String("source", source), zap.Int64("updated", n), zap.Int("total", len(unprobed)))
	}
}

