package cli

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

func TestParseHeaderEntriesPreservesOrderAndDuplicates(t *testing.T) {
	block := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Set-Cookie: a=1; Path=/\r\n" +
		"Set-Cookie: b=2; HttpOnly\r\n" +
		"Set-Cookie: c=3\r\n" +
		"X-Trailing: last"

	got := parseHeaderEntries(block)

	// A map would have collapsed three Set-Cookie headers into one. In a security
	// read the two that vanish are as likely to be the interesting ones — the
	// session cookie set alongside a tracking cookie, say.
	if len(got) != 5 {
		t.Fatalf("got %d entries, want 5: %+v", len(got), got)
	}
	if got[0].Name != "Content-Type" || got[0].Value != "text/html" {
		t.Errorf("first entry = %+v", got[0])
	}
	wantCookies := []string{"a=1; Path=/", "b=2; HttpOnly", "c=3"}
	for i, want := range wantCookies {
		e := got[i+1]
		if e.Name != "Set-Cookie" || e.Value != want {
			t.Errorf("cookie %d = %+v, want Set-Cookie: %s", i, e, want)
		}
	}
	if got[4].Name != "X-Trailing" {
		t.Errorf("a final header with no trailing CRLF was dropped: %+v", got)
	}
}

// The start line is not a header and must not be parsed as one — "HTTP/1.1 200
// OK" contains no colon, but "GET /a?x=1 HTTP/1.1" does not either, while a
// request line like "GET http://h/p HTTP/1.1" does.
func TestParseHeaderEntriesSkipsStartLine(t *testing.T) {
	block := "GET http://example.invalid/p HTTP/1.1\r\nHost: example.invalid"

	got := parseHeaderEntries(block)

	if len(got) != 1 || got[0].Name != "Host" {
		t.Fatalf("absolute-form request line leaked into the headers: %+v", got)
	}
	if line := headerStartLine(block); line != "GET http://example.invalid/p HTTP/1.1" {
		t.Errorf("headerStartLine = %q", line)
	}
}

func TestParseHeaderEntriesFoldsContinuations(t *testing.T) {
	block := "HTTP/1.1 200 OK\r\nX-Long: first part\r\n\tsecond part\r\nX-Next: value"

	got := parseHeaderEntries(block)

	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	// Appended to the entry it continues rather than dropped: a folded value that
	// silently loses its tail is a wrong answer, not a missing one.
	if got[0].Value != "first part second part" {
		t.Errorf("folded value = %q", got[0].Value)
	}
}

func TestParseHeaderEntriesHandlesLFOnly(t *testing.T) {
	got := parseHeaderEntries("HTTP/1.1 204 No Content\nX-A: 1\nX-B: 2")
	if len(got) != 2 {
		t.Fatalf("LF-separated headers not parsed: %+v", got)
	}
}

func TestFilterHeaderEntriesIsCaseInsensitiveAndReturnsAll(t *testing.T) {
	entries := []headerEntry{
		{"Set-Cookie", "a=1"},
		{"Content-Type", "text/html"},
		{"set-cookie", "b=2"},
	}

	got := filterHeaderEntries(entries, "SET-COOKIE")

	if len(got) != 2 {
		t.Fatalf("got %d matches, want both spellings: %+v", len(got), got)
	}
	if got[0].Value != "a=1" || got[1].Value != "b=2" {
		t.Errorf("matches = %+v", got)
	}

	if absent := filterHeaderEntries(entries, "authorization"); len(absent) != 0 {
		t.Errorf("an absent header returned %+v", absent)
	}
}

func TestSelectedSideDefaultsToResponse(t *testing.T) {
	t.Cleanup(func() { extractRequestSide = false })

	extractRequestSide = false
	if got := selectedSide(); got != sideResponse {
		t.Errorf("default side = %q, want response", got)
	}
	extractRequestSide = true
	if got := selectedSide(); got != sideRequest {
		t.Errorf("--request side = %q", got)
	}
}

func TestLooksGzipMatchesDecoderMagic(t *testing.T) {
	if !looksGzip([]byte{0x1f, 0x8b, 0x08, 0x00}) {
		t.Error("gzip magic not recognized")
	}
	for _, b := range [][]byte{nil, {0x1f}, []byte("{\"json\":true}")} {
		if looksGzip(b) {
			t.Errorf("%q reported as gzip", b)
		}
	}
}

// The codes are what a caller branches on, so they are asserted as literals
// rather than compared to themselves.
func TestExtractionErrorCodesAreStable(t *testing.T) {
	for name, pair := range map[string][2]string{
		"record not found": {string(apicontract.CodeRecordNotFound), "record_not_found"},
		"body unavailable": {string(apicontract.CodeBodyUnavailable), "body_unavailable"},
		"decode failed":    {string(apicontract.CodeBodyDecodeFailed), "body_decode_failed"},
		"incomplete":       {string(apicontract.CodeBodyIncomplete), "body_incomplete"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: code is %q, want %q", name, pair[0], pair[1])
		}
	}
}

func TestCodedErrorClassifies(t *testing.T) {
	err := codedErrorf(apicontract.CodeRecordNotFound, "no stored record has uuid %q", "abc")

	if got := classifyErrorCode(err, ExitError); got != apicontract.CodeRecordNotFound {
		t.Errorf("classifyErrorCode = %q, want %q", got, apicontract.CodeRecordNotFound)
	}
	if !strings.Contains(err.Error(), `uuid "abc"`) {
		t.Errorf("message lost its detail: %q", err.Error())
	}
	// A usage error still outranks a code: the exit status is the contract there.
	if got := classifyErrorCode(err, ExitUsageError); got != apicontract.CodeUsageError {
		t.Errorf("usage exit code = %q, want %q", got, apicontract.CodeUsageError)
	}
}
