package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/authsession"
	"github.com/vigolium/vigolium/pkg/httpmsg"

	"go.uber.org/zap"
)

// probeRecords sends HTTP requests for records that don't have responses,
// enriching them with live response data. This ensures records saved to the
// database have response bodies, status codes, and headers for the scanner
// modules to analyze. Records are probed concurrently with a bounded worker pool.
// validateProbeAndSave filters records with valid URLs, injects auth headers,
// probes them for live responses, and saves them to the database.
// Records that fail the first probe are retried once.
// The optional notes slice (aligned 1:1 with records) is persisted as remarks.
func (s *SwarmRunner) validateProbeAndSave(ctx context.Context, records []*httpmsg.HttpRequestResponse, notes []string, authHeaders map[string]string, source, projectUUID string, pc ProbeConfig) []string {
	if len(records) == 0 {
		return nil
	}

	var valid []*httpmsg.HttpRequestResponse
	var validNotes []string
	for i, rr := range records {
		if rr.Request() == nil {
			continue
		}
		if u, urlErr := rr.URL(); urlErr != nil || u == nil || u.Host == "" {
			zap.L().Debug("Skipping record with invalid URL", zap.String("source", source), zap.Error(urlErr))
			continue
		}
		valid = append(valid, rr)
		if i < len(notes) {
			validNotes = append(validNotes, notes[i])
		} else {
			validNotes = append(validNotes, "")
		}
	}

	if len(authHeaders) > 0 {
		injectAuthHeaders(valid, authHeaders)
	}
	if len(valid) > 0 {
		probeRecordsWithConfig(ctx, valid, pc)

		// Retry probe for records that still have no response (transient failures).
		var unprobed []int
		for i, rr := range valid {
			if !rr.HasResponse() {
				unprobed = append(unprobed, i)
			}
		}
		if len(unprobed) > 0 {
			zap.L().Info("Retrying probe for records with no response",
				zap.Int("count", len(unprobed)))
			retry := make([]*httpmsg.HttpRequestResponse, len(unprobed))
			for j, idx := range unprobed {
				retry[j] = valid[idx]
			}
			probeRecordsWithConfig(ctx, retry, pc)
			for j, idx := range unprobed {
				valid[idx] = retry[j]
			}
		}
	}
	if s.repo != nil && len(valid) > 0 {
		var savedCount int
		var savedUUIDs []string
		remarksMap := make(map[string][]string)
		for i, rr := range valid {
			savedUUID, saveErr := s.repo.SaveRecord(ctx, rr, source, projectUUID)
			if saveErr != nil {
				zap.L().Debug("Failed to save record", zap.String("source", source), zap.Error(saveErr))
			} else {
				savedCount++
				savedUUIDs = append(savedUUIDs, savedUUID)
				if i < len(validNotes) && validNotes[i] != "" && savedUUID != "" {
					remarksMap[savedUUID] = []string{validNotes[i]}
				}
			}
		}
		if savedCount > 0 {
			zap.L().Info("Saved records to database", zap.String("source", source), zap.Int("count", savedCount))
		}
		if len(remarksMap) > 0 {
			if err := s.repo.AppendRemarks(ctx, remarksMap); err != nil {
				zap.L().Warn("Failed to append remarks from agent notes", zap.Error(err))
			}
		}
		return savedUUIDs
	}
	return nil
}

// ProbeConfig holds tuning parameters for HTTP record probing.
type ProbeConfig struct {
	Concurrency int                        // max parallel probe requests; 0 = default 10
	Timeout     time.Duration              // per-request probe timeout; 0 = default 10s
	MaxBodySize int                        // max response body bytes; 0 = default 2MB
	OnProgress  func(completed, total int) // optional progress callback
}

func (pc ProbeConfig) effectiveConcurrency() int {
	if pc.Concurrency <= 0 {
		return 10
	}
	return pc.Concurrency
}

func (pc ProbeConfig) effectiveTimeout() time.Duration {
	if pc.Timeout <= 0 {
		return 10 * time.Second
	}
	return pc.Timeout
}

func (pc ProbeConfig) effectiveMaxBodySize() int {
	if pc.MaxBodySize <= 0 {
		return 2 * 1024 * 1024
	}
	return pc.MaxBodySize
}

func probeRecordsWithConfig(ctx context.Context, records []*httpmsg.HttpRequestResponse, pc ProbeConfig) {
	maxConcurrency := pc.effectiveConcurrency()
	probeTimeout := pc.effectiveTimeout()
	maxBody := pc.effectiveMaxBodySize()

	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Don't follow redirects — capture the redirect response itself
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	// Count probeable records for progress reporting
	var probeable int
	for _, rr := range records {
		if !rr.HasResponse() && rr.Request() != nil && rr.Target() != "" {
			probeable++
		}
	}

	var completed atomic.Int64 // atomic counter for progress
	for i, rr := range records {
		if rr.HasResponse() {
			continue
		}
		if rr.Request() == nil {
			continue
		}
		targetURL := rr.Target()
		if targetURL == "" {
			continue
		}

		wg.Add(1)
		idx := i
		go func(rec *httpmsg.HttpRequestResponse, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probed := probeSingleRecordWithLimit(ctx, client, rec, target, maxBody)
			if probed != nil {
				records[idx] = probed
			}
			done := int(completed.Add(1))
			if pc.OnProgress != nil {
				pc.OnProgress(done, probeable)
			}
		}(rr, targetURL)
	}

	wg.Wait()
}

// probeSingleRecordWithLimit sends an HTTP request with a configurable body size limit.
func probeSingleRecordWithLimit(ctx context.Context, client *http.Client, rr *httpmsg.HttpRequestResponse, targetURL string, maxBody int) *httpmsg.HttpRequestResponse {
	method := "GET"
	if rr.Request() != nil {
		method = rr.Request().Method()
	}

	var bodyReader io.Reader
	if rr.Request() != nil && len(rr.Request().Body()) > 0 {
		bodyReader = bytes.NewReader(rr.Request().Body())
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		zap.L().Debug("Failed to build probe request", zap.String("url", targetURL), zap.Error(err))
		return nil
	}

	// Copy headers from the original request
	if rr.Request() != nil {
		for _, h := range rr.Request().Headers() {
			httpReq.Header.Add(h.Name, h.Value)
		}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		zap.L().Debug("Probe request failed", zap.String("url", targetURL), zap.Error(err))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body (limit size to avoid memory issues)
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)))
	if err != nil {
		zap.L().Debug("Failed to read probe response", zap.String("url", targetURL), zap.Error(err))
		return nil
	}

	// Build raw HTTP response
	var rawResp bytes.Buffer
	fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(body)

	httpResp := httpmsg.NewHttpResponse(rawResp.Bytes())
	return rr.WithResponse(httpResp)
}

// reprobeUnprobedRecords queries records without responses from the DB and
// probes them using a simple HTTP client. This acts as a fallback for records
// that earlier probes failed to fetch.
func (s *SwarmRunner) reprobeUnprobedRecords(ctx context.Context, projectUUID, hostname string, authHeaders map[string]string, source string) {
	authsession.ReprobeUnprobedRecords(ctx, s.repo, projectUUID, hostname, authHeaders, source)
}
