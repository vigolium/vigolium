package specutil

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestDetectSpecType_OpenAPI(t *testing.T) {
	data := []byte(`{"swagger": "2.0", "info": {"title": "Test"}, "paths": {}}`)
	if got := DetectSpecType(data); got != OpenAPI {
		t.Errorf("DetectSpecType(swagger json) = %d, want OpenAPI (%d)", got, OpenAPI)
	}

	yamlData := []byte("swagger: \"2.0\"\ninfo:\n  title: Test\npaths: {}\n")
	if got := DetectSpecType(yamlData); got != OpenAPI {
		t.Errorf("DetectSpecType(swagger yaml) = %d, want OpenAPI (%d)", got, OpenAPI)
	}
}

func TestDetectSpecType_Postman(t *testing.T) {
	data := []byte(`{"info": {"_postman_id": "abc123", "name": "Test"}, "item": []}`)
	if got := DetectSpecType(data); got != Postman {
		t.Errorf("DetectSpecType(postman) = %d, want Postman (%d)", got, Postman)
	}

	data2 := []byte(`{"info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}`)
	if got := DetectSpecType(data2); got != Postman {
		t.Errorf("DetectSpecType(postman schema) = %d, want Postman (%d)", got, Postman)
	}
}

func TestDetectSpecType_Unknown(t *testing.T) {
	data := []byte(`{"name": "not a spec"}`)
	if got := DetectSpecType(data); got != Unknown {
		t.Errorf("DetectSpecType(unknown) = %d, want Unknown (%d)", got, Unknown)
	}
}

func TestIsSpecContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/yaml", true},
		{"text/yaml", true},
		{"application/x-yaml", true},
		{"text/json", true},
		{"text/html", false},
		{"image/png", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsSpecContentType(tt.ct); got != tt.want {
			t.Errorf("IsSpecContentType(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

// mockFeeder collects fed requests for testing.
type mockFeeder struct {
	items []*httpmsg.HttpRequestResponse
}

func (f *mockFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	f.items = append(f.items, rr)
	return true
}

var _ modkit.RequestFeeder = (*mockFeeder)(nil)

func TestParseAndFeed_OpenAPISwagger(t *testing.T) {
	spec := []byte(`swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      summary: Get users
      responses:
        200:
          description: OK
  /items:
    post:
      summary: Create item
      responses:
        201:
          description: Created
`)

	feeder := &mockFeeder{}
	service := httpmsg.NewServiceSecure("example.com", 443, true)

	count, err := ParseAndFeed(spec, "https://example.com", service, feeder)
	if err != nil {
		t.Fatalf("ParseAndFeed() error = %v", err)
	}
	if count == 0 {
		t.Fatal("ParseAndFeed() returned 0 endpoints, expected > 0")
	}
	if len(feeder.items) != count {
		t.Errorf("feeder received %d items, count returned %d", len(feeder.items), count)
	}
}

func TestParseAndFeed_NilFeeder(t *testing.T) {
	spec := []byte(`{"swagger": "2.0", "info": {"title": "Test"}, "paths": {"/a": {"get": {}}}}`)
	count, err := ParseAndFeed(spec, "https://example.com", nil, nil)
	if err != nil {
		t.Fatalf("ParseAndFeed() error = %v", err)
	}
	if count != 0 {
		t.Errorf("ParseAndFeed(nil feeder) = %d, want 0", count)
	}
}

func TestParseAndFeed_UnknownSpec(t *testing.T) {
	data := []byte(`{"not": "a spec"}`)
	feeder := &mockFeeder{}
	count, err := ParseAndFeed(data, "", nil, feeder)
	if err != nil {
		t.Fatalf("ParseAndFeed() error = %v", err)
	}
	if count != 0 {
		t.Errorf("ParseAndFeed(unknown) = %d, want 0", count)
	}
}

func TestParseSpec_OpenAPI(t *testing.T) {
	spec := []byte(`swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      summary: Get users
      responses:
        200:
          description: OK
  /items:
    post:
      summary: Create item
      responses:
        201:
          description: Created
`)

	service := httpmsg.NewServiceSecure("example.com", 443, true)
	endpoints, err := ParseSpec(spec, "https://example.com", service)
	if err != nil {
		t.Fatalf("ParseSpec() error = %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("ParseSpec() returned 0 endpoints, expected > 0")
	}
	// Each endpoint should have service set
	for i, rr := range endpoints {
		if rr.Service() == nil {
			t.Errorf("endpoint %d has nil service", i)
		}
	}
}

func TestParseSpec_Unknown(t *testing.T) {
	data := []byte(`{"not": "a spec"}`)
	endpoints, err := ParseSpec(data, "", nil)
	if err != nil {
		t.Fatalf("ParseSpec() error = %v", err)
	}
	if len(endpoints) != 0 {
		t.Errorf("ParseSpec(unknown) returned %d endpoints, want 0", len(endpoints))
	}
}
