package file_upload_scan

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestReplaceFilePart(t *testing.T) {
	raw := []byte("POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n" +
		"abc123\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n" +
		"Content-Type: image/jpeg\r\n\r\n" +
		"binary-image-data\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n")

	probe := uploadProbe{
		name:        "Direct PHP",
		filename:    "test.php",
		contentType: "application/x-php",
		body:        "<?php echo 'marker'; ?>",
	}

	modified, err := replaceFilePart(raw, probe)
	if err != nil {
		t.Fatalf("replaceFilePart() error: %v", err)
	}

	modifiedStr := string(modified)

	// Should contain the new filename
	if !strings.Contains(modifiedStr, `filename="test.php"`) {
		t.Error("modified request should contain new filename 'test.php'")
	}

	// Should contain the new content type
	if !strings.Contains(modifiedStr, "application/x-php") {
		t.Error("modified request should contain new content type")
	}

	// Should contain the probe body
	if !strings.Contains(modifiedStr, "<?php echo 'marker'; ?>") {
		t.Error("modified request should contain the PHP probe body")
	}

	// Should preserve CSRF token
	if !strings.Contains(modifiedStr, "csrf_token") {
		t.Error("modified request should preserve csrf_token field")
	}
	if !strings.Contains(modifiedStr, "abc123") {
		t.Error("modified request should preserve csrf_token value")
	}

	// Should NOT contain original filename
	if strings.Contains(modifiedStr, "photo.jpg") {
		t.Error("modified request should not contain original filename")
	}
}

func TestReplaceFilePart_NoBoundary(t *testing.T) {
	raw := []byte("POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"hello")

	probe := uploadProbe{filename: "test.php", contentType: "text/plain", body: "test"}
	_, err := replaceFilePart(raw, probe)
	if err == nil {
		t.Error("expected error for request without multipart boundary")
	}
}

func TestExtractUploadPath(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "JSON url field",
			body: `{"url":"/uploads/test.php","status":"ok"}`,
			want: "/uploads/test.php",
		},
		{
			name: "JSON file_path field",
			body: `{"file_path":"/files/test.php"}`,
			want: "/files/test.php",
		},
		{
			name: "HTML link with upload in path",
			body: `<a href="/uploads/test.php">View file</a>`,
			want: "/uploads/test.php",
		},
		{
			name: "no path found",
			body: `<html>File uploaded successfully</html>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUploadPath(tt.body)
			if got != tt.want {
				t.Errorf("extractUploadPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanProcess(t *testing.T) {
	m := New()

	// Should accept multipart with filename
	raw := []byte("POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: multipart/form-data; boundary=----boundary\r\n\r\n" +
		"------boundary\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\n\r\n" +
		"data\r\n" +
		"------boundary--\r\n")

	ctx, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}

	if !m.CanProcess(ctx) {
		t.Error("CanProcess should return true for multipart with filename")
	}

	// Should reject non-multipart
	raw2 := []byte("POST /api/data HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"key":"value"}`)

	ctx2, _ := httpmsg.ParseRawRequest(string(raw2))
	if m.CanProcess(ctx2) {
		t.Error("CanProcess should return false for non-multipart requests")
	}
}

func TestGenerateMarker(t *testing.T) {
	marker1 := generateMarker()
	marker2 := generateMarker()

	if !strings.HasPrefix(marker1, "vigolium-upload-test-") {
		t.Errorf("marker should start with 'vigolium-upload-test-', got %q", marker1)
	}

	if marker1 == marker2 {
		t.Error("markers should be unique")
	}

	if len(marker1) != len("vigolium-upload-test-")+16 {
		t.Errorf("marker should be %d chars, got %d", len("vigolium-upload-test-")+16, len(marker1))
	}
}

func TestBuildProbes(t *testing.T) {
	marker := "test-marker-123"
	probes := buildProbes(marker)

	if len(probes) != 11 {
		t.Fatalf("expected 11 probes, got %d", len(probes))
	}

	// Check that probes contain the marker (except .htaccess which has fixed content)
	for _, probe := range probes {
		if probe.filename != ".htaccess" && !strings.Contains(probe.body, marker) {
			t.Errorf("probe %q body should contain marker", probe.name)
		}
		if probe.filename == "" {
			t.Errorf("probe %q should have a filename", probe.name)
		}
		if probe.contentType == "" {
			t.Errorf("probe %q should have a content type", probe.name)
		}
	}

	// Check specific probes
	if probes[0].filename != "test.php" {
		t.Errorf("first probe should be direct PHP, got %q", probes[0].filename)
	}
	if probes[1].filename != "test.php.jpg" {
		t.Errorf("second probe should be double extension, got %q", probes[1].filename)
	}
	if probes[5].filename != "test.svg" {
		t.Errorf("sixth probe should be SVG XXE, got %q", probes[5].filename)
	}
}
