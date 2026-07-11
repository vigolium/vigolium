package source

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// captureSaver is a RecordSaver test double that records how many records were
// saved under each source label and hands back deterministic UUIDs.
type captureSaver struct {
	mu        sync.Mutex
	bySource  map[string]int
	artifacts []capturedArtifact
}

type capturedArtifact struct {
	recordUUID, kind, filename, mediaType, sha256, metadata string
	content                                                 []byte
}

func newCaptureSaver() *captureSaver {
	return &captureSaver{bySource: map[string]int{}}
}

func (c *captureSaver) SaveRecord(_ context.Context, _ *httpmsg.HttpRequestResponse, source, _ string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bySource[source]++
	return fmt.Sprintf("%s-%d", source, c.bySource[source]-1), nil
}

func (c *captureSaver) SaveRecordBatch(_ context.Context, records []*httpmsg.HttpRequestResponse, source, _ string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bySource[source] += len(records)
	uuids := make([]string, len(records))
	for i := range uuids {
		uuids[i] = fmt.Sprintf("%s-%d", source, i)
	}
	return uuids, nil
}

func (c *captureSaver) SaveAnalysisArtifact(_ context.Context, recordUUID, kind, filename, mediaType, sha256 string, content []byte, metadata string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.artifacts = append(c.artifacts, capturedArtifact{
		recordUUID: recordUUID, kind: kind, filename: filename, mediaType: mediaType,
		sha256: sha256, content: append([]byte(nil), content...), metadata: metadata,
	})
	return nil
}

func newTestDiscoverySource(saver RecordSaver) *DeparosDiscoverySource {
	return &DeparosDiscoverySource{
		cfg:   DeparosDiscoveryConfig{Repository: saver, ProjectUUID: "proj"},
		items: make(chan *work.WorkItem, 64),
		done:  make(chan struct{}),
	}
}

// minimalSpec is a small but valid OpenAPI/Swagger spec yielding >1 endpoint.
var minimalSpec = []byte(`swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: api.example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      responses:
        200:
          description: OK
  /items:
    post:
      responses:
        201:
          description: Created
`)

// crawledSpecRecord builds a crawled discovery record whose 200 response body is
// an OpenAPI spec (as deparos would capture when it fetches /spec).
func crawledSpecRecord() *httpmsg.HttpRequestResponse {
	svc := httpmsg.NewServiceSecure("api.example.com", 443, true)
	req := httpmsg.NewHttpRequestWithService(svc, []byte("GET /spec HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
	resp := httpmsg.NewHttpResponse(append(
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\n\r\n"), minimalSpec...))
	return httpmsg.NewHttpRequestResponse(req, resp).WithService(svc)
}

// TestExtractSpecEndpoints_ProducesRequestOnlyStubs locks in the invariant the
// executor backfill depends on: spec-derived endpoints come out as request-only
// stubs (no response), so they must later be fetched + backfilled to show traffic.
func TestExtractSpecEndpoints_ProducesRequestOnlyStubs(t *testing.T) {
	endpoints := extractSpecEndpoints([]*httpmsg.HttpRequestResponse{crawledSpecRecord()})

	assert.NotEmpty(t, endpoints, "a discovered OpenAPI spec must yield endpoints")
	for i, rr := range endpoints {
		assert.Nilf(t, rr.Response(), "spec endpoint %d must be a request-only stub (no response)", i)
	}
}

// TestSaveAndEmit_TagsRecordsWithSource proves crawled vs spec records are
// persisted under DISTINCT sources — the safeguard that keeps the deparos
// dedup/status passes (scoped to source='deparos') from deleting documented
// API-spec endpoints once they carry real (often uniform 401) responses.
func TestSaveAndEmit_TagsRecordsWithSource(t *testing.T) {
	saver := newCaptureSaver()
	d := newTestDiscoverySource(saver)
	ctx := context.Background()

	crawled := []*httpmsg.HttpRequestResponse{crawledSpecRecord()}
	specEndpoints := extractSpecEndpoints(crawled)
	if len(specEndpoints) == 0 {
		t.Fatal("expected spec endpoints from the fixture")
	}

	if err := d.saveAndEmit(ctx, crawled, crawlRecordSource); err != nil {
		t.Fatalf("saveAndEmit(crawled): %v", err)
	}
	if err := d.saveAndEmit(ctx, specEndpoints, specRecordSource); err != nil {
		t.Fatalf("saveAndEmit(spec): %v", err)
	}

	assert.NotEqual(t, crawlRecordSource, specRecordSource, "crawl and spec sources must differ")
	assert.Equal(t, len(crawled), saver.bySource[crawlRecordSource], "crawled records saved under the crawl source")
	assert.Equal(t, len(specEndpoints), saver.bySource[specRecordSource], "spec endpoints saved under the spec source")

	// Every emitted WorkItem must carry the persisted RecordUUID so the executor
	// can backfill the right row.
	emitted := drainWorkItems(d.items, len(crawled)+len(specEndpoints))
	assert.Len(t, emitted, len(crawled)+len(specEndpoints))
	for i, it := range emitted {
		assert.NotEmptyf(t, it.RecordUUID, "emitted item %d must carry a RecordUUID", i)
	}
}

// TestSaveAndEmit_EmitsWithoutUUIDsOnSaveFailure verifies a DB save failure
// doesn't drop records: they are still emitted (without UUIDs) so scanning runs.
func TestSaveAndEmit_EmitsWithoutUUIDsOnSaveFailure(t *testing.T) {
	d := newTestDiscoverySource(&failingSaver{})
	ctx := context.Background()

	recs := []*httpmsg.HttpRequestResponse{crawledSpecRecord(), crawledSpecRecord()}
	if err := d.saveAndEmit(ctx, recs, specRecordSource); err != nil {
		t.Fatalf("saveAndEmit: %v", err)
	}

	emitted := drainWorkItems(d.items, len(recs))
	assert.Len(t, emitted, len(recs), "records must still be emitted when the DB save fails")
	for i, it := range emitted {
		assert.Emptyf(t, it.RecordUUID, "item %d should have no UUID after a failed save", i)
	}
}

func TestPersistJSTangleSourceArtifactsPromotesEphemeralContent(t *testing.T) {
	saver := newCaptureSaver()
	d := newTestDiscoverySource(saver)
	siteMap, err := deparosstorage.NewSiteMap(deparosstorage.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = siteMap.Close() }()
	generatedURL := "https://example.test/assets/app.js"
	if err := siteMap.Extractions().StoreJSTangleSourceArtifact(&deparosstorage.JSTangleSourceArtifactModel{
		SourceNodeID: 1, SessionID: siteMap.SessionDBID(), GeneratedURL: generatedURL,
		VirtualURL: generatedURL + "#source=src%2Fapi.ts", SourcePath: "src/api.ts",
		Language: "ts", ContentSHA256: "abc123", Content: `fetch('/api/from-map')`,
	}); err != nil {
		t.Fatal(err)
	}
	record, err := httpmsg.GetRawRequestFromURL(generatedURL)
	if err != nil {
		t.Fatal(err)
	}
	d.persistJSTangleSourceArtifacts(context.Background(), siteMap,
		map[string]string{record.Target(): "record-uuid"})
	if len(saver.artifacts) != 1 {
		t.Fatalf("promoted %d artifacts, want 1", len(saver.artifacts))
	}
	artifact := saver.artifacts[0]
	assert.Equal(t, "record-uuid", artifact.recordUUID)
	assert.Equal(t, "source-map-original", artifact.kind)
	assert.Equal(t, "src/api.ts", artifact.filename)
	assert.Equal(t, `fetch('/api/from-map')`, string(artifact.content))
	assert.Contains(t, artifact.metadata, generatedURL)
}

type failingSaver struct{}

func (failingSaver) SaveRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, error) {
	return "", fmt.Errorf("save failed")
}
func (failingSaver) SaveRecordBatch(context.Context, []*httpmsg.HttpRequestResponse, string, string) ([]string, error) {
	return nil, fmt.Errorf("batch save failed")
}

func drainWorkItems(ch <-chan *work.WorkItem, n int) []*work.WorkItem {
	out := make([]*work.WorkItem, 0, n)
	for i := 0; i < n; i++ {
		select {
		case it := <-ch:
			out = append(out, it)
		default:
			return out
		}
	}
	return out
}
