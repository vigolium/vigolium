package httpmsg

import (
	"strings"
	"testing"
)

// TestExtractBoundary tests boundary extraction from Content-Type headers.
func TestExtractBoundary(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{
			name:        "Standard boundary",
			contentType: "multipart/form-data; boundary=----WebKitFormBoundary",
			want:        "----WebKitFormBoundary",
		},
		{
			name:        "Boundary with extra spaces",
			contentType: "multipart/form-data; boundary=  ----WebKit  ",
			want:        "----WebKit",
		},
		{
			name:        "Boundary at start",
			contentType: "boundary=----WebKitFormBoundary",
			want:        "----WebKitFormBoundary",
		},
		{
			name:        "No boundary",
			contentType: "multipart/form-data",
			want:        "",
		},
		{
			name:        "Empty string",
			contentType: "",
			want:        "",
		},
		{
			name:        "Complex boundary",
			contentType: "multipart/form-data; boundary=----WebKitFormBoundaryABC123xyz",
			want:        "----WebKitFormBoundaryABC123xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractBoundary(tt.contentType)
			if got != tt.want {
				t.Errorf("ExtractBoundary() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseMultipartBody_SimpleField tests parsing a simple text field.
func TestParseMultipartBody_SimpleField(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"field\"\r\n\r\n" +
			"value\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 1", len(params))
	}

	param := params[0]
	if param.Type() != ParamBodyMultipart {
		t.Errorf("param.Type() = %v, want %v", param.Type(), ParamBodyMultipart)
	}
	if param.Name() != "field" {
		t.Errorf("param.Name() = %q, want %q", param.Name(), "field")
	}
	if param.Value() != "value" {
		t.Errorf("param.Value() = %q, want %q", param.Value(), "value")
	}

	// Verify offsets
	if param.NameStart() <= 0 {
		t.Errorf("param.NameStart() = %d, want > 0", param.NameStart())
	}
	if param.NameEnd() <= param.NameStart() {
		t.Errorf("param.NameEnd() = %d, want > %d", param.NameEnd(), param.NameStart())
	}
	if param.ValueStart() <= param.NameEnd() {
		t.Errorf("param.ValueStart() = %d, want > %d", param.ValueStart(), param.NameEnd())
	}
	if param.ValueEnd() <= param.ValueStart() {
		t.Errorf("param.ValueEnd() = %d, want > %d", param.ValueEnd(), param.ValueStart())
	}

	// Verify extracted values match offsets
	extractedName := string(request[param.NameStart():param.NameEnd()])
	if extractedName != "field" {
		t.Errorf("Extracted name from offsets = %q, want %q", extractedName, "field")
	}

	extractedValue := string(request[param.ValueStart():param.ValueEnd()])
	if extractedValue != "value" {
		t.Errorf("Extracted value from offsets = %q, want %q", extractedValue, "value")
	}
}

// TestParseMultipartBody_FileUpload tests parsing a file upload with filename attribute.
func TestParseMultipartBody_FileUpload(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
			"Content-Type: text/plain\r\n\r\n" +
			"file content here\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	// Should return 2 parameters: the file field and the filename attribute
	if len(params) != 2 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 2", len(params))
	}

	// First parameter is the file field
	fileParam := params[0]
	if fileParam.Type() != ParamBodyMultipart {
		t.Errorf("fileParam.Type = %v, want %v", fileParam.Type(), ParamBodyMultipart)
	}
	if fileParam.Name() != "file" {
		t.Errorf("fileParam.Name = %q, want %q", fileParam.Name(), "file")
	}
	if fileParam.Value() != "file content here" {
		t.Errorf("fileParam.Value = %q, want %q", fileParam.Value(), "file content here")
	}

	// Verify metadata contains Content-Type header
	if !strings.Contains(fileParam.Metadata(), "Content-Type") {
		t.Errorf("fileParam.Metadata should contain Content-Type header, got %q", fileParam.Metadata())
	}

	// Second parameter is the filename attribute
	filenameParam := params[1]
	if filenameParam.Type() != ParamMultipartAttr {
		t.Errorf("filenameParam.Type = %v, want %v", filenameParam.Type(), ParamMultipartAttr)
	}
	if filenameParam.Name() != "filename" {
		t.Errorf("filenameParam.Name = %q, want %q", filenameParam.Name(), "filename")
	}
	if filenameParam.Value() != "test.txt" {
		t.Errorf("filenameParam.Value = %q, want %q", filenameParam.Value(), "test.txt")
	}
}

// TestParseMultipartBody_MultipleParts tests parsing multiple form fields.
func TestParseMultipartBody_MultipleParts(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"field1\"\r\n\r\n" +
			"value1\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"field2\"\r\n\r\n" +
			"value2\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"field3\"\r\n\r\n" +
			"value3\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	if len(params) != 3 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 3", len(params))
	}

	expectedFields := map[string]string{
		"field1": "value1",
		"field2": "value2",
		"field3": "value3",
	}

	for i, param := range params {
		expectedValue, ok := expectedFields[param.Name()]
		if !ok {
			t.Errorf("param[%d].Name = %q, unexpected field name", i, param.Name())
			continue
		}

		if param.Value() != expectedValue {
			t.Errorf("param[%d].Value = %q, want %q", i, param.Value(), expectedValue)
		}

		if param.Type() != ParamBodyMultipart {
			t.Errorf("param[%d].Type = %v, want %v", i, param.Type(), ParamBodyMultipart)
		}
	}
}

// TestParseMultipartBody_EmptyValue tests parsing a field with empty value.
func TestParseMultipartBody_EmptyValue(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"empty\"\r\n\r\n" +
			"\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 1", len(params))
	}

	param := params[0]
	if param.Name() != "empty" {
		t.Errorf("param.Name() = %q, want %q", param.Name(), "empty")
	}
	if param.Value() != "" {
		t.Errorf("param.Value() = %q, want empty string", param.Value())
	}
}

// TestParseMultipartBody_SpecialCharacters tests parsing values with special characters.
func TestParseMultipartBody_SpecialCharacters(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	specialValue := "Hello\nWorld\r\nWith special chars: <>&\""
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"special\"\r\n\r\n" +
			specialValue + "\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 1", len(params))
	}

	param := params[0]
	if param.Name() != "special" {
		t.Errorf("param.Name() = %q, want %q", param.Name(), "special")
	}
	if param.Value() != specialValue {
		t.Errorf("param.Value() = %q, want %q", param.Value(), specialValue)
	}
}

// TestParseMultipartBody_NoBoundary tests error handling when boundary is empty.
func TestParseMultipartBody_NoBoundary(t *testing.T) {
	request := []byte("POST / HTTP/1.1\r\n\r\n")
	bodyOffset := FindBodyOffset(request)

	params, err := ParseMultipartBody(request, bodyOffset, "")

	if err == nil {
		t.Fatal("ParseMultipartBody() expected error for empty boundary, got nil")
	}

	if params != nil {
		t.Errorf("ParseMultipartBody() returned %d parameters, want nil on error", len(params))
	}
}

// TestParseMultipartBody_InvalidRequest tests handling of invalid request data.
func TestParseMultipartBody_InvalidRequest(t *testing.T) {
	boundary := "----WebKitFormBoundary"

	tests := []struct {
		name       string
		request    []byte
		bodyOffset int
		wantError  bool
	}{
		{
			name:       "Nil request",
			request:    nil,
			bodyOffset: 0,
			wantError:  false, // Returns empty slice
		},
		{
			name:       "Body offset out of bounds",
			request:    []byte("POST / HTTP/1.1\r\n\r\n"),
			bodyOffset: 1000,
			wantError:  false, // Returns empty slice
		},
		{
			name:       "Negative body offset",
			request:    []byte("POST / HTTP/1.1\r\n\r\n"),
			bodyOffset: -1,
			wantError:  false, // Returns empty slice
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseMultipartBody(tt.request, tt.bodyOffset, boundary)

			if tt.wantError && err == nil {
				t.Error("ParseMultipartBody() expected error, got nil")
			}

			if !tt.wantError && err != nil {
				t.Errorf("ParseMultipartBody() unexpected error = %v", err)
			}

			if !tt.wantError && len(params) != 0 {
				t.Errorf("ParseMultipartBody() returned %d parameters, want 0", len(params))
			}
		})
	}
}

// TestParseMultipartBody_LFOnly tests parsing with LF-only line endings (Unix style).
func TestParseMultipartBody_LFOnly(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST / HTTP/1.1\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\n\n" +
			"------WebKitFormBoundary\n" +
			"Content-Disposition: form-data; name=\"field\"\n\n" +
			"value\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 1", len(params))
	}

	param := params[0]
	if param.Name() != "field" {
		t.Errorf("param.Name() = %q, want %q", param.Name(), "field")
	}
	if param.Value() != "value" {
		t.Errorf("param.Value() = %q, want %q", param.Value(), "value")
	}
}

// TestParseMultipartRequest tests the convenience function that extracts boundary automatically.
func TestParseMultipartRequest(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"auto\"\r\n\r\n" +
			"automatic\r\n" +
			"------WebKitFormBoundary--")

	params, err := ParseMultipartRequest(request)

	if err != nil {
		t.Fatalf("ParseMultipartRequest() error = %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("ParseMultipartRequest() returned %d parameters, want 1", len(params))
	}

	param := params[0]
	if param.Name() != "auto" {
		t.Errorf("param.Name() = %q, want %q", param.Name(), "auto")
	}
	if param.Value() != "automatic" {
		t.Errorf("param.Value() = %q, want %q", param.Value(), "automatic")
	}
}

// TestParseMultipartRequest_MissingContentType tests error handling when Content-Type is missing.
func TestParseMultipartRequest_MissingContentType(t *testing.T) {
	request := []byte("POST / HTTP/1.1\r\n\r\nbody")

	params, err := ParseMultipartRequest(request)

	if err == nil {
		t.Fatal("ParseMultipartRequest() expected error for missing Content-Type, got nil")
	}

	if params != nil {
		t.Errorf("ParseMultipartRequest() returned %d parameters, want nil on error", len(params))
	}
}

// TestParseMultipartBody_ByteOffsetVerification tests that byte offsets are accurate.
func TestParseMultipartBody_ByteOffsetVerification(t *testing.T) {
	boundary := "----WebKit"
	request := []byte(
		"POST /upload HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKit\r\n" +
			"Content-Disposition: form-data; name=\"username\"\r\n\r\n" +
			"john_doe\r\n" +
			"------WebKit\r\n" +
			"Content-Disposition: form-data; name=\"avatar\"; filename=\"pic.jpg\"\r\n" +
			"Content-Type: image/jpeg\r\n\r\n" +
			"binary_data_here\r\n" +
			"------WebKit--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	// Should have 3 params: username field, avatar field, filename attribute
	if len(params) < 2 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want at least 2", len(params))
	}

	// Verify each parameter's offsets by extracting from request
	for i, param := range params {
		t.Run(param.Name(), func(t *testing.T) {
			// Extract name from request using offsets
			if param.NameStart() >= 0 && param.NameEnd() > param.NameStart() && param.NameEnd() <= len(request) {
				extractedName := string(request[param.NameStart():param.NameEnd()])
				if extractedName != param.Name() {
					t.Errorf("param[%d]: extracted name %q != param.Name() %q (offsets: %d-%d)",
						i, extractedName, param.Name(), param.NameStart(), param.NameEnd())
				}
			}

			// Extract value from request using offsets
			if param.ValueStart() >= 0 && param.ValueEnd() >= param.ValueStart() && param.ValueEnd() <= len(request) {
				extractedValue := string(request[param.ValueStart():param.ValueEnd()])
				if extractedValue != param.Value() {
					t.Errorf("param[%d]: extracted value %q != param.Value() %q (offsets: %d-%d)",
						i, extractedValue, param.Value(), param.ValueStart(), param.ValueEnd())
				}
			}
		})
	}
}

// TestParseMultipartBody_MultilineValue tests parsing values that span multiple lines.
func TestParseMultipartBody_MultilineValue(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	multilineValue := "Line 1\r\nLine 2\r\nLine 3"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"multiline\"\r\n\r\n" +
			multilineValue + "\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want 1", len(params))
	}

	param := params[0]
	if param.Value() != multilineValue {
		t.Errorf("param.Value() = %q, want %q", param.Value(), multilineValue)
	}
}

// TestParseMultipartBody_ComplexRealWorld tests a realistic complex multipart request.
func TestParseMultipartBody_ComplexRealWorld(t *testing.T) {
	boundary := "----WebKitFormBoundaryXYZ123"
	request := []byte(
		"POST /api/upload HTTP/1.1\r\n" +
			"Host: api.example.com\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n" +
			"Content-Length: 500\r\n\r\n" +
			"------WebKitFormBoundaryXYZ123\r\n" +
			"Content-Disposition: form-data; name=\"userId\"\r\n\r\n" +
			"12345\r\n" +
			"------WebKitFormBoundaryXYZ123\r\n" +
			"Content-Disposition: form-data; name=\"description\"\r\n\r\n" +
			"This is a test upload\r\nwith multiple lines\r\n" +
			"------WebKitFormBoundaryXYZ123\r\n" +
			"Content-Disposition: form-data; name=\"file\"; filename=\"document.pdf\"\r\n" +
			"Content-Type: application/pdf\r\n\r\n" +
			"%PDF-1.4 binary content here...\r\n" +
			"------WebKitFormBoundaryXYZ123--")

	bodyOffset := FindBodyOffset(request)
	params, err := ParseMultipartBody(request, bodyOffset, boundary)

	if err != nil {
		t.Fatalf("ParseMultipartBody() error = %v", err)
	}

	// Should have 4 params: userId, description, file, and filename attribute
	if len(params) < 3 {
		t.Fatalf("ParseMultipartBody() returned %d parameters, want at least 3", len(params))
	}

	// Verify userId
	var foundUserId, foundDescription, foundFile bool
	for _, param := range params {
		switch param.Name() {
		case "userId":
			foundUserId = true
			if param.Value() != "12345" {
				t.Errorf("userId value = %q, want %q", param.Value(), "12345")
			}
		case "description":
			foundDescription = true
			if !strings.Contains(param.Value(), "multiple lines") {
				t.Errorf("description should contain 'multiple lines', got %q", param.Value())
			}
		case "file":
			foundFile = true
			if !strings.Contains(param.Value(), "PDF") {
				t.Errorf("file value should contain 'PDF', got %q", param.Value())
			}
		}
	}

	if !foundUserId {
		t.Error("userId parameter not found")
	}
	if !foundDescription {
		t.Error("description parameter not found")
	}
	if !foundFile {
		t.Error("file parameter not found")
	}
}
