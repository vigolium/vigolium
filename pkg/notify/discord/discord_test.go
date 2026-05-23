package discord

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// newTestBackend returns a Backend whose webhookURL points at the given test
// server. NewBackend validates that the URL contains "discord.com/api/webhooks/",
// so it cannot be pointed at httptest directly; instead we build the struct
// literal (the webhookURL field is package-private but reachable from an internal
// test). This is the URL-override seam used throughout these tests.
func newTestBackend(url string) *Backend {
	return &Backend{
		webhookURL: url,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func sampleResult() *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: "sqli",
		Info: output.Info{
			Name:        "SQL Injection",
			Severity:    severity.High,
			Description: "A SQL injection was detected",
		},
		Host:             "example.com",
		URL:              "https://example.com/?id=1",
		FuzzingParameter: "id",
		Request:          "GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
}

// --- NewBackend validation -------------------------------------------------

func TestNewBackend_Validation(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty", "", true},
		{"whitespace", "   ", true},
		{"missing-path", "https://example.com/foo", true},
		{"valid", "https://discord.com/api/webhooks/123/abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := NewBackend(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if b == nil || b.httpClient == nil {
				t.Fatal("expected non-nil backend with http client")
			}
		})
	}
}

func TestBackend_Close_NoPanic(t *testing.T) {
	b := newTestBackend("http://x")
	b.Close() // no-op, must not panic
}

// --- Send (embed JSON path) ------------------------------------------------

func TestBackend_Send_EmbedJSON(t *testing.T) {
	var (
		gotPath        string
		gotMethod      string
		gotContentType string
		gotUA          string
		gotBody        []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	if err := b.Send(sampleResult()); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/api/webhooks/1/token" {
		t.Errorf("unexpected path %q", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("expected application/json, got %q", gotContentType)
	}
	if gotUA != "Vigolium-Scanner/1.0" {
		t.Errorf("unexpected user-agent %q", gotUA)
	}

	var msg WebhookMessage
	if err := json.Unmarshal(gotBody, &msg); err != nil {
		t.Fatalf("decode body: %v\nbody=%s", err, gotBody)
	}
	if len(msg.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(msg.Embeds))
	}
	embed := msg.Embeds[0]
	if !strings.Contains(embed.Title, "SQL Injection") {
		t.Errorf("title missing module name: %q", embed.Title)
	}
	if embed.Color != GetSeverityColor("high") {
		t.Errorf("unexpected color %d", embed.Color)
	}
	// Field values should contain the host, severity and parameter.
	body := string(gotBody)
	for _, want := range []string{"example.com", "HIGH", `"id"`, "https://example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("payload missing %q\nbody: %s", want, body)
		}
	}
}

// --- Send (multipart overflow path) ----------------------------------------

func TestBackend_Send_OverflowMultipart(t *testing.T) {
	var (
		gotContentType string
		payloadJSON    string
		fileContent    string
		fileName       string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(gotContentType)
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			t.Errorf("expected multipart content-type, got %q", gotContentType)
			w.WriteHeader(http.StatusOK)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("read part: %v", err)
				break
			}
			data, _ := io.ReadAll(part)
			switch part.FormName() {
			case "payload_json":
				payloadJSON = string(data)
			case "files[0]":
				fileContent = string(data)
				fileName = part.FileName()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := sampleResult()
	// Force overflow by making the request larger than MaxRequestPreview.
	result.Request = strings.Repeat("A", MaxRequestPreview+200)

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	if err := b.Send(result); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if payloadJSON == "" {
		t.Fatal("missing payload_json part")
	}
	if !strings.Contains(payloadJSON, "truncated") {
		t.Errorf("expected truncation marker in embed, got: %s", payloadJSON)
	}
	if !strings.HasSuffix(fileName, ".txt") {
		t.Errorf("expected .txt attachment, got %q", fileName)
	}
	if fileContent != result.Request {
		t.Errorf("file content should equal full request; got %d bytes want %d", len(fileContent), len(result.Request))
	}
}

// --- SendRaw ---------------------------------------------------------------

func TestBackend_SendRaw_Content(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	if err := b.SendRaw("hello *world*"); err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}

	var msg WebhookMessage
	if err := json.Unmarshal(gotBody, &msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// EscapeMarkdown should have escaped the asterisks.
	if !strings.Contains(msg.Content, `\*world\*`) {
		t.Errorf("content not escaped: %q", msg.Content)
	}
}

func TestBackend_SendRaw_OversizedBecomesFile(t *testing.T) {
	var gotContentType string
	var fileName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(gotContentType)
		if err == nil && strings.HasPrefix(mediaType, "multipart/") {
			mr := multipart.NewReader(r.Body, params["boundary"])
			for {
				part, err := mr.NextPart()
				if err != nil {
					break
				}
				if part.FormName() == "files[0]" {
					fileName = part.FileName()
				}
				_, _ = io.ReadAll(part)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	big := strings.Repeat("x", MaxMessageContent+1)
	if err := b.SendRaw(big); err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}
	if !strings.HasPrefix(gotContentType, "multipart/") {
		t.Errorf("expected multipart upload for oversized message, got %q", gotContentType)
	}
	if fileName != "message.txt" {
		t.Errorf("expected message.txt, got %q", fileName)
	}
}

// --- error paths -----------------------------------------------------------

func TestBackend_Send_ErrorOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	err := b.Send(sampleResult())
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestBackend_Send_ErrorOn4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	if err := b.SendRaw("hi"); err == nil {
		t.Fatal("expected error on 400")
	}
}

func TestBackend_Send_RateLimited429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	err := b.Send(sampleResult())
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should mention rate limit: %v", err)
	}
}

func TestBackend_Send_TransportError(t *testing.T) {
	// Point at a server that is immediately closed -> connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL + "/api/webhooks/1/token"
	srv.Close()

	b := newTestBackend(url)
	if err := b.Send(sampleResult()); err == nil {
		t.Fatal("expected transport error against closed server")
	}
}

func TestBackend_SendFileOnly_OverflowMultipartError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	b := newTestBackend(srv.URL + "/api/webhooks/1/token")
	// Oversized request triggers sendWithFile, which should surface the 5xx.
	result := sampleResult()
	result.Request = strings.Repeat("A", MaxRequestPreview+50)
	if err := b.Send(result); err == nil {
		t.Fatal("expected error from multipart send on 5xx")
	}
}

// --- formatting / payload helpers ------------------------------------------

func TestEscapeMarkdown(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"*bold*", `\*bold\*`},
		{"_under_", `\_under\_`},
		{"~strike~", `\~strike\~`},
		{"a|b", `a\|b`},
		{"`code`", "\\`code\\`"},
		{"@user", `\@user`},
		{"#tag", `\#tag`},
		{`back\slash`, `back\\slash`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := EscapeMarkdown(tc.in); got != tc.want {
				t.Errorf("EscapeMarkdown(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGetSeverityColor(t *testing.T) {
	cases := map[string]int{
		"critical": 10038562,
		"high":     15158332,
		"medium":   16753920,
		"low":      16776960,
		"info":     3447003,
		"HIGH":     15158332, // case-insensitive
		"unknown":  9807270,  // default gray
		"":         9807270,
	}
	for sev, want := range cases {
		t.Run(sev, func(t *testing.T) {
			if got := GetSeverityColor(sev); got != want {
				t.Errorf("GetSeverityColor(%q) = %d, want %d", sev, got, want)
			}
		})
	}
}

func TestFormatEmbed_NoOverflowBasics(t *testing.T) {
	msg, overflow := FormatEmbed(sampleResult())
	if overflow != nil {
		t.Fatalf("did not expect overflow for small request")
	}
	if len(msg.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(msg.Embeds))
	}
	embed := msg.Embeds[0]
	if embed.Footer == nil || embed.Footer.Text != "Vigolium Scanner" {
		t.Errorf("missing footer: %+v", embed.Footer)
	}
	if embed.Description == "" {
		t.Errorf("expected description to be set")
	}
	// Required core fields present.
	names := map[string]bool{}
	for _, f := range embed.Fields {
		names[f.Name] = true
	}
	for _, want := range []string{"Module", "Severity", "Host", "Date", "Parameter", "URL", "Request"} {
		if !names[want] {
			t.Errorf("missing field %q", want)
		}
	}
}

func TestFormatEmbed_OverflowAndDescriptionTruncation(t *testing.T) {
	result := sampleResult()
	result.Request = strings.Repeat("R", MaxRequestPreview+10)
	result.Info.Description = strings.Repeat("D", MaxDescription+100)

	msg, overflow := FormatEmbed(result)
	if overflow == nil {
		t.Fatal("expected overflow for oversized request")
	}
	if len(overflow.Content) != len(result.Request) {
		t.Errorf("overflow should carry full request: got %d want %d", len(overflow.Content), len(result.Request))
	}
	if !strings.HasSuffix(overflow.Filename, ".txt") {
		t.Errorf("overflow filename should be .txt: %q", overflow.Filename)
	}
	if len(msg.Embeds[0].Description) > MaxDescription {
		t.Errorf("description not truncated: %d", len(msg.Embeds[0].Description))
	}
	if !strings.HasSuffix(msg.Embeds[0].Description, "...") {
		t.Errorf("truncated description should end with ellipsis")
	}
}

func TestFormatEmbed_LongURLTruncated(t *testing.T) {
	result := sampleResult()
	result.URL = "https://example.com/" + strings.Repeat("a", 600)
	msg, _ := FormatEmbed(result)
	var urlField *Field
	for i := range msg.Embeds[0].Fields {
		if msg.Embeds[0].Fields[i].Name == "URL" {
			urlField = &msg.Embeds[0].Fields[i]
		}
	}
	if urlField == nil {
		t.Fatal("missing URL field")
	}
	if !strings.HasSuffix(urlField.Value, "...") {
		t.Errorf("long URL should be truncated with ellipsis: %q", urlField.Value)
	}
}

func TestFormatEmbed_MinimalResult(t *testing.T) {
	// No optional fields -> Parameter/URL/Request omitted, no overflow.
	result := &output.ResultEvent{
		Info: output.Info{Name: "X", Severity: severity.Low},
		Host: "h",
	}
	msg, overflow := FormatEmbed(result)
	if overflow != nil {
		t.Error("no overflow expected")
	}
	names := map[string]bool{}
	for _, f := range msg.Embeds[0].Fields {
		names[f.Name] = true
	}
	if names["Parameter"] || names["URL"] || names["Request"] {
		t.Errorf("did not expect optional fields: %v", names)
	}
}

func TestTruncateField(t *testing.T) {
	short := "short"
	if got := truncateField(short); got != short {
		t.Errorf("short string changed: %q", got)
	}
	long := strings.Repeat("y", MaxFieldValue+50)
	got := truncateField(long)
	if len(got) > MaxFieldValue {
		t.Errorf("truncateField returned %d chars, exceeds %d", len(got), MaxFieldValue)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected ellipsis suffix")
	}
}
