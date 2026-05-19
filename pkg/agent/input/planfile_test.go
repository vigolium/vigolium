package input

import (
	"strings"
	"testing"
)

func TestParsePlanFile_ProseThenSingleRequest(t *testing.T) {
	// The exact shape an operator pastes: prose guidance, then one raw
	// HTTP/2 request carrying a session Cookie.
	raw := `Here are the list of order ID like 0254685 and 0254774

do the testing with the request below with a focus on IDOR

GET /order/details?orderId=0254809 HTTP/2
Host: ginandjuice.shop
Cookie: TrackingId=abc==; session=deadbeef
User-Agent: Mozilla/5.0
Accept: text/html
`

	instruction, requests := ParsePlanFile(raw)

	if !strings.Contains(instruction, "focus on IDOR") {
		t.Fatalf("instruction missing prose guidance: %q", instruction)
	}
	if strings.Contains(instruction, "GET /order/details") {
		t.Fatalf("instruction should not contain the request line: %q", instruction)
	}
	if len(requests) != 1 {
		t.Fatalf("want 1 request, got %d: %#v", len(requests), requests)
	}
	if !strings.HasPrefix(requests[0], "GET /order/details?orderId=0254809 HTTP/2") {
		t.Fatalf("request[0] not the raw request: %q", requests[0])
	}
	if !strings.Contains(requests[0], "Cookie: TrackingId=abc==; session=deadbeef") {
		t.Fatalf("request[0] dropped the Cookie header: %q", requests[0])
	}
}

func TestParsePlanFile_MultiRequestRuleSeparated(t *testing.T) {
	raw := `focus on IDOR across these orders

GET /order/details?orderId=0254809 HTTP/2
Host: ginandjuice.shop

---

GET /order/details?orderId=0254685 HTTP/2
Host: ginandjuice.shop

---

GET /order/details?orderId=0254774 HTTP/2
Host: ginandjuice.shop
`

	instruction, requests := ParsePlanFile(raw)

	if instruction != "focus on IDOR across these orders" {
		t.Fatalf("unexpected instruction: %q", instruction)
	}
	if len(requests) != 3 {
		t.Fatalf("want 3 requests, got %d: %#v", len(requests), requests)
	}
	for i, want := range []string{"0254809", "0254685", "0254774"} {
		if !strings.Contains(requests[i], want) {
			t.Fatalf("request[%d] missing %s: %q", i, want, requests[i])
		}
		if !strings.HasPrefix(requests[i], "GET /order/details") {
			t.Fatalf("request[%d] not trimmed to the request line: %q", i, requests[i])
		}
	}
}

func TestParsePlanFile_FencedBlocks(t *testing.T) {
	raw := "test these two endpoints for IDOR\n\n" +
		"```http\n" +
		"GET /a?id=1 HTTP/2\nHost: x.test\n" +
		"```\n\n" +
		"some more notes\n\n" +
		"```request\n" +
		"GET /b?id=2 HTTP/2\nHost: x.test\n" +
		"```\n"

	instruction, requests := ParsePlanFile(raw)

	if !strings.Contains(instruction, "test these two endpoints") || !strings.Contains(instruction, "some more notes") {
		t.Fatalf("instruction lost prose: %q", instruction)
	}
	if strings.Contains(instruction, "GET /a") || strings.Contains(instruction, "GET /b") {
		t.Fatalf("instruction leaked request bodies: %q", instruction)
	}
	if len(requests) != 2 {
		t.Fatalf("want 2 requests, got %d: %#v", len(requests), requests)
	}
	if !strings.HasPrefix(requests[0], "GET /a?id=1 HTTP/2") || !strings.HasPrefix(requests[1], "GET /b?id=2 HTTP/2") {
		t.Fatalf("fenced requests not extracted cleanly: %#v", requests)
	}
}

func TestParsePlanFile_NonRequestFenceFallsThroughToAutoSplit(t *testing.T) {
	// A ```bash fence in the prose must not suppress auto-split detection
	// of the real request that follows it.
	raw := "setup:\n\n```bash\necho hello\n```\n\nnow test:\n\nGET /x HTTP/2\nHost: x.test\n"

	instruction, requests := ParsePlanFile(raw)

	if len(requests) != 1 {
		t.Fatalf("want 1 request, got %d: %#v", len(requests), requests)
	}
	if !strings.HasPrefix(requests[0], "GET /x HTTP/2") {
		t.Fatalf("request not detected via auto-split: %q", requests[0])
	}
	if !strings.Contains(instruction, "echo hello") {
		t.Fatalf("non-request fence should remain in instruction: %q", instruction)
	}
}

func TestParsePlanFile_InstructionOnly(t *testing.T) {
	raw := "just audit the auth flow, no seed request provided"

	instruction, requests := ParsePlanFile(raw)

	if instruction != "just audit the auth flow, no seed request provided" {
		t.Fatalf("unexpected instruction: %q", instruction)
	}
	if requests != nil {
		t.Fatalf("want nil requests, got %#v", requests)
	}
}

func TestParsePlanFile_RequestOnly(t *testing.T) {
	raw := "POST /login HTTP/1.1\nHost: x.test\nContent-Type: application/json\n\n{\"u\":\"a\"}\n"

	instruction, requests := ParsePlanFile(raw)

	if instruction != "" {
		t.Fatalf("want empty instruction, got %q", instruction)
	}
	if len(requests) != 1 {
		t.Fatalf("want 1 request, got %d", len(requests))
	}
	if !strings.Contains(requests[0], `{"u":"a"}`) {
		t.Fatalf("request body dropped: %q", requests[0])
	}
}

func TestParsePlanFile_CRLFNormalized(t *testing.T) {
	raw := "focus IDOR\r\n\r\nGET /a?id=1 HTTP/2\r\nHost: x.test\r\n"

	instruction, requests := ParsePlanFile(raw)

	if instruction != "focus IDOR" {
		t.Fatalf("CRLF not normalized in instruction: %q", instruction)
	}
	if len(requests) != 1 || strings.Contains(requests[0], "\r") {
		t.Fatalf("CRLF not normalized in request: %#v", requests)
	}
}

func TestParsePlanFile_LenientFoldsJunkBlockIntoInstruction(t *testing.T) {
	raw := `note here

GET /a?id=1 HTTP/2
Host: x.test

---

this block has no request line, fold it back

---

GET /b?id=2 HTTP/2
Host: x.test
`

	instruction, requests := ParsePlanFile(raw)

	if len(requests) != 2 {
		t.Fatalf("want 2 requests, got %d: %#v", len(requests), requests)
	}
	if !strings.Contains(instruction, "note here") {
		t.Fatalf("instruction lost leading prose: %q", instruction)
	}
	if !strings.Contains(instruction, "fold it back") {
		t.Fatalf("junk block not folded into instruction: %q", instruction)
	}
}
