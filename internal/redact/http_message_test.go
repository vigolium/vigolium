package redact

import (
	"strings"
	"testing"
)

func TestHTTPMessage(t *testing.T) {
	req := "GET /api/me?id=7&access_token=SEKRET1 HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"Authorization: Bearer SEKRET2\r\n" +
		"Cookie: session=SEKRET3; theme=dark\r\n" +
		"X-Tenant-Key: SEKRET4\r\n" +
		"X-Custom-Op: SEKRET5\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"q":"body stays"}`
	got := HTTPMessage(req, map[string]struct{}{"x-custom-op": {}})
	for _, secret := range []string{"SEKRET1", "SEKRET2", "SEKRET3", "SEKRET4", "SEKRET5"} {
		if strings.Contains(got, secret) {
			t.Errorf("%s survived redaction:\n%s", secret, got)
		}
	}
	for _, keep := range []string{"id=7", "session=" + Placeholder, "theme=" + Placeholder, "Content-Type: application/json", `{"q":"body stays"}`, "Host: app.test"} {
		if !strings.Contains(got, keep) {
			t.Errorf("missing %q in:\n%s", keep, got)
		}
	}
	resp := "HTTP/1.1 200 OK\nSet-Cookie: sid=SEKRET6; Path=/; HttpOnly\nContent-Length: 2\n\nok"
	gotResp := HTTPMessage(resp, nil)
	if strings.Contains(gotResp, "SEKRET6") || !strings.Contains(gotResp, "sid="+Placeholder+"; Path=/; HttpOnly") {
		t.Errorf("Set-Cookie not redacted correctly:\n%s", gotResp)
	}
	if plain := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi"; HTTPMessage(plain, nil) != plain {
		t.Error("a message with nothing sensitive must be returned unchanged")
	}
}
