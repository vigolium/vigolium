package api_spec_detect

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if !m.ScanScopes().Has(modkit.ScanScopeRequest) {
		t.Error("expected ScanScopeRequest to be set")
	}
	if m.Scope() != modkit.PassiveScanScopeResponse {
		t.Error("expected PassiveScanScopeResponse")
	}
}

func TestScanPerRequest_NoResponse(t *testing.T) {
	m := New()
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rr := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequest(rawReq), nil)

	results, err := m.ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for nil response, got %d", len(results))
	}
}

func TestScanPerRequest_NonJSON(t *testing.T) {
	m := New()
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>")
	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequest(rawReq),
		httpmsg.NewHttpResponse(rawResp),
	)

	results, err := m.ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for non-JSON content, got %d", len(results))
	}
}

func TestScanPerRequest_SwaggerSpec(t *testing.T) {
	spec := `{
		"swagger": "2.0",
		"info": {"title": "Test API", "version": "1.0"},
		"host": "example.com",
		"basePath": "/api",
		"paths": {
			"/users": {
				"get": {
					"responses": {"200": {"description": "OK"}}
				}
			},
			"/items": {
				"post": {
					"responses": {"201": {"description": "Created"}}
				}
			}
		}
	}`

	rawReq := []byte("GET /swagger.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rawResp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n%s", spec))

	service := httpmsg.NewServiceSecure("example.com", 443, true)
	req := httpmsg.NewHttpRequestWithService(service, rawReq)
	rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse(rawResp))

	feeder := &mockFeeder{}
	scanCtx := &modkit.ScanContext{
		RequestFeeder: feeder,
	}

	m := New()
	results, err := m.ScanPerRequest(rr, scanCtx)
	if err != nil {
		t.Fatalf("ScanPerRequest() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result for valid swagger spec")
	}

	if len(feeder.items) == 0 {
		t.Fatal("expected feeder to receive endpoints")
	}

	t.Logf("Detected %d endpoints from swagger spec", len(feeder.items))
}

func TestScanPerRequest_Non2xxStatus(t *testing.T) {
	spec := `{"swagger": "2.0", "info": {"title": "Test"}}`

	rawReq := []byte("GET /swagger.json HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rawResp := []byte(fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n%s", spec))

	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequest(rawReq),
		httpmsg.NewHttpResponse(rawResp),
	)

	m := New()
	results, err := m.ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for 404 response, got %d", len(results))
	}
}

func TestScanPerRequest_TooSmallBody(t *testing.T) {
	rawReq := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")

	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequest(rawReq),
		httpmsg.NewHttpResponse(rawResp),
	)

	m := New()
	results, err := m.ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for tiny body, got %d", len(results))
	}
}

type mockFeeder struct {
	items []*httpmsg.HttpRequestResponse
}

func (f *mockFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	f.items = append(f.items, rr)
	return true
}
