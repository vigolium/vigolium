package firebase_storage_exposure

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Extract storage bucket from response body
	storageBucketRe  = regexp.MustCompile(`["']storageBucket["']\s*:\s*["']([a-z0-9][a-z0-9.-]+\.appspot\.com)["']`)
	storageBucketRe2 = regexp.MustCompile(`firebasestorage\.googleapis\.com/v0/b/([a-z0-9][a-z0-9.-]+\.appspot\.com)`)
)

// Common storage prefixes to probe
var storagePrefixes = []string{
	"",
	"users/",
	"uploads/",
	"exports/",
	"backups/",
	"private/",
	"documents/",
	"images/",
	"files/",
	"data/",
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("firebase_storage_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Extract bucket names from response
	buckets := make(map[string]struct{})
	for _, re := range []*regexp.Regexp{storageBucketRe, storageBucketRe2} {
		for _, match := range re.FindAllStringSubmatch(body, 10) {
			if len(match) > 1 {
				buckets[match[1]] = struct{}{}
			}
		}
	}
	if len(buckets) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for bucket := range buckets {
		if diskSet != nil && diskSet.IsSeen(bucket) {
			continue
		}

		// Probe Firebase Storage REST API
		for _, prefix := range storagePrefixes {
			if result := m.probeFirebaseStorage(httpClient, bucket, prefix); result != nil {
				results = append(results, result)
				if prefix == "" {
					break // Root listing works, skip prefix-specific probes
				}
			}
		}

		// Probe Google Cloud Storage endpoint
		if result := m.probeGCSEndpoint(httpClient, bucket); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) probeFirebaseStorage(
	httpClient *http.Requester,
	bucket string,
	prefix string,
) *output.ResultEvent {
	targetURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o?maxResults=20&delimiter=/", bucket)
	if prefix != "" {
		targetURL += "&prefix=" + prefix
	}

	host := "firebasestorage.googleapis.com"
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n\r\n",
		targetURL, host)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	respBody := resp.Body().String()

	// Check for actual items or prefixes in response
	hasItems := strings.Contains(respBody, `"items"`)
	hasPrefixes := strings.Contains(respBody, `"prefixes"`)
	if !hasItems && !hasPrefixes {
		return nil
	}

	name := "Firebase Storage Public Listing (Root)"
	desc := fmt.Sprintf("Firebase Storage bucket %s allows public object listing at root", bucket)
	sev := severity.High
	if prefix != "" {
		name = fmt.Sprintf("Firebase Storage Public Listing (/%s)", prefix)
		desc = fmt.Sprintf("Firebase Storage bucket %s allows public object listing at prefix /%s", bucket, prefix)
		sev = severity.High
	}

	responseStr := resp.FullResponseString()
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		URL:      targetURL,
		Matched:  targetURL,
		Request:  rawReq,
		Response: responseStr,
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        []string{"firebase", "storage", "data-exposure"},
		},
		Metadata: map[string]any{
			"bucket":      bucket,
			"prefix":      prefix,
			"hasItems":    hasItems,
			"hasPrefixes": hasPrefixes,
		},
	}
}

func (m *Module) probeGCSEndpoint(
	httpClient *http.Requester,
	bucket string,
) *output.ResultEvent {
	targetURL := fmt.Sprintf("https://storage.googleapis.com/%s/", bucket)
	host := "storage.googleapis.com"
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n\r\n",
		targetURL, host)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	respBody := resp.Body().String()

	// GCS XML listing contains <ListBucketResult>
	if !strings.Contains(respBody, "ListBucketResult") && !strings.Contains(respBody, "<Contents>") {
		return nil
	}

	responseStr := resp.FullResponseString()
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		URL:      targetURL,
		Matched:  targetURL,
		Request:  rawReq,
		Response: responseStr,
		Info: output.Info{
			Name:        "Firebase Storage Bucket Public via GCS",
			Description: fmt.Sprintf("Firebase Storage bucket %s is publicly accessible via Google Cloud Storage endpoint, allowing object enumeration", bucket),
			Severity:    severity.High,
			Confidence:  severity.Certain,
			Tags:        []string{"firebase", "storage", "gcs", "data-exposure"},
		},
		Metadata: map[string]any{
			"bucket":   bucket,
			"endpoint": "gcs",
		},
	}
}
