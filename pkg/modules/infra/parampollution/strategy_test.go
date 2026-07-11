package parampollution

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// requestLine returns the first line (METHOD target HTTP/x) of a raw request.
func requestLine(raw []byte) string {
	if i := bytes.IndexByte(raw, '\r'); i >= 0 {
		return string(raw[:i])
	}
	return string(raw)
}

// body returns the body section (after the CRLFCRLF separator) of a raw request.
func body(raw []byte) string {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return string(raw[i+4:])
	}
	return ""
}

// countSub counts non-overlapping occurrences of sub in s.
func countSub(s, sub string) int { return strings.Count(s, sub) }

func TestQueryDuplicate_OrderingAndNoDedup(t *testing.T) {
	rr := modtest.Request(t, "http://acme.test/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	vars := queryDuplicate{}.Variants(rr, ip, "PAYLOAD")
	if len(vars) != 2 {
		t.Fatalf("expected 2 query-duplicate variants, got %d", len(vars))
	}

	var last, first *Variant
	for i := range vars {
		switch vars[i].Name {
		case "query-dup-payload-last":
			last = &vars[i]
		case "query-dup-payload-first":
			first = &vars[i]
		}
	}
	if last == nil || first == nil {
		t.Fatalf("missing expected variant names, got %+v", vars)
	}

	// The crafted request line must contain the exact duplicate sequence, in order.
	lastLine := requestLine(last.Raw)
	if !strings.Contains(lastLine, "id=1&id=PAYLOAD") {
		t.Errorf("payload-last must place the payload after the safe value: %q", lastLine)
	}
	firstLine := requestLine(first.Raw)
	if !strings.Contains(firstLine, "id=PAYLOAD&id=1") {
		t.Errorf("payload-first must place the payload before the safe value: %q", firstLine)
	}

	// The two orderings must differ.
	if bytes.Equal(last.Raw, first.Raw) {
		t.Error("payload-last and payload-first variants must differ")
	}

	// No dedup/collapse: both id occurrences survive on the wire.
	if got := countSub(lastLine, "id="); got != 2 {
		t.Errorf("expected 2 id= occurrences (no dedup), got %d in %q", got, lastLine)
	}

	// Ordering metadata sanity.
	if last.Ordering != OrderingSafeFirst || first.Ordering != OrderingPayloadFirst {
		t.Errorf("unexpected ordering metadata: last=%q first=%q", last.Ordering, first.Ordering)
	}
	if last.Channels != ChannelQuery {
		t.Errorf("query-duplicate must be a query-channel variant, got %q", last.Channels)
	}
}

func TestBodyDuplicate_OrderingAndNoDedup(t *testing.T) {
	rr := modtest.RequestMethod(t, "POST", "http://acme.test/login", "id=1")
	ip := modtest.InsertionPoint(t, rr, "id")
	if ip.Type() != httpmsg.INS_PARAM_BODY {
		t.Fatalf("expected a body insertion point, got %v", ip.Type())
	}

	vars := bodyDuplicate{}.Variants(rr, ip, "PAYLOAD")
	if len(vars) != 2 {
		t.Fatalf("expected 2 body-duplicate variants, got %d", len(vars))
	}

	var last *Variant
	for i := range vars {
		if vars[i].Name == "body-dup-payload-last" {
			last = &vars[i]
		}
	}
	if last == nil {
		t.Fatalf("missing body-dup-payload-last, got %+v", vars)
	}

	b := body(last.Raw)
	if !strings.Contains(b, "id=1&id=PAYLOAD") {
		t.Errorf("body payload-last must be id=1&id=PAYLOAD, got body %q", b)
	}
	if got := countSub(b, "id="); got != 2 {
		t.Errorf("expected 2 id= occurrences in body (no dedup), got %d in %q", got, b)
	}
	// The query-only strategy must NOT apply to a body parameter.
	if (queryDuplicate{}).Applicable(rr, ip) {
		t.Error("queryDuplicate must not be applicable to a body parameter")
	}
}

func TestQueryBodySplit_PlacesPayloadInCorrectChannel(t *testing.T) {
	// A POST with a query parameter — a body is allowed, so the split applies.
	rr := modtest.RequestMethod(t, "POST", "http://acme.test/item?id=1", "x=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	if !(queryBodySplit{}).Applicable(rr, ip) {
		t.Fatal("queryBodySplit should apply to a URL param on a body-allowed method")
	}
	vars := queryBodySplit{}.Variants(rr, ip, "PAYLOAD")
	if len(vars) != 2 {
		t.Fatalf("expected 2 split variants, got %d", len(vars))
	}

	var inBody, inQuery *Variant
	for i := range vars {
		switch vars[i].Name {
		case "split-payload-in-body":
			inBody = &vars[i]
		case "split-payload-in-query":
			inQuery = &vars[i]
		}
	}
	if inBody == nil || inQuery == nil {
		t.Fatalf("missing split variant names, got %+v", vars)
	}

	// payload-in-body: safe rides the query line, payload rides the body.
	if !strings.Contains(requestLine(inBody.Raw), "id=1") {
		t.Errorf("split-payload-in-body must keep safe value in query: %q", requestLine(inBody.Raw))
	}
	if !strings.Contains(body(inBody.Raw), "id=PAYLOAD") {
		t.Errorf("split-payload-in-body must place payload in body: %q", body(inBody.Raw))
	}

	// payload-in-query: payload rides the query line, safe rides the body.
	if !strings.Contains(requestLine(inQuery.Raw), "id=PAYLOAD") {
		t.Errorf("split-payload-in-query must place payload in query: %q", requestLine(inQuery.Raw))
	}
	if !strings.Contains(body(inQuery.Raw), "id=1") {
		t.Errorf("split-payload-in-query must keep safe value in body: %q", body(inQuery.Raw))
	}

	if inBody.Channels != ChannelQueryBody {
		t.Errorf("split must be a query+body variant, got %q", inBody.Channels)
	}
}

func TestQueryBodySplit_NotApplicableToPlainGET(t *testing.T) {
	rr := modtest.Request(t, "http://acme.test/item?id=1") // GET, no body
	ip := modtest.InsertionPoint(t, rr, "id")
	if (queryBodySplit{}).Applicable(rr, ip) {
		t.Error("queryBodySplit must not apply to a plain GET with no body")
	}
}

func TestBracketArray_FormsAndOrder(t *testing.T) {
	rr := modtest.Request(t, "http://acme.test/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	vars := bracketArray{}.Variants(rr, ip, "PAYLOAD")
	if len(vars) != 2 {
		t.Fatalf("expected 2 bracket-array variants, got %d", len(vars))
	}

	var brackets, indexed *Variant
	for i := range vars {
		switch vars[i].Name {
		case "array-brackets":
			brackets = &vars[i]
		case "array-indexed":
			indexed = &vars[i]
		}
	}
	if brackets == nil || indexed == nil {
		t.Fatalf("missing bracket-array variant names, got %+v", vars)
	}

	if !strings.Contains(requestLine(brackets.Raw), "id[]=1&id[]=PAYLOAD") {
		t.Errorf("array-brackets must be id[]=1&id[]=PAYLOAD, got %q", requestLine(brackets.Raw))
	}
	if !strings.Contains(requestLine(indexed.Raw), "id[0]=1&id[1]=PAYLOAD") {
		t.Errorf("array-indexed must be id[0]=1&id[1]=PAYLOAD, got %q", requestLine(indexed.Raw))
	}
	// The original bare parameter must be replaced by the array form (no dedup of
	// the array occurrences themselves, but the scalar is gone).
	if strings.Contains(requestLine(brackets.Raw), "id=1") {
		t.Errorf("array form should not keep the bare scalar id=1: %q", requestLine(brackets.Raw))
	}
}

func TestAllVariants_BoundedAndUnion(t *testing.T) {
	rr := modtest.Request(t, "http://acme.test/item?id=1") // GET URL param
	ip := modtest.InsertionPoint(t, rr, "id")

	vars := AllVariants(rr, ip, "PAYLOAD")
	if len(vars) == 0 {
		t.Fatal("AllVariants returned nothing for a URL parameter")
	}
	if len(vars) > maxVariants {
		t.Errorf("AllVariants must be bounded at %d, got %d", maxVariants, len(vars))
	}
	// The union must include the query-duplicate family (queryBodySplit does not
	// apply to a plain GET; bracketArray does).
	names := map[string]bool{}
	for _, v := range vars {
		names[v.Name] = true
	}
	if !names["query-dup-payload-last"] {
		t.Errorf("AllVariants should include the query-duplicate family, got %v", names)
	}
}

func TestCleanControl_BenignDuplicate(t *testing.T) {
	rr := modtest.Request(t, "http://acme.test/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	raw, ok := CleanControl(rr, ip)
	if !ok {
		t.Fatal("CleanControl must be available for a URL parameter")
	}
	line := requestLine(raw)
	if !strings.Contains(line, "id=1&id=1") {
		t.Errorf("clean control must duplicate the param with two benign values: %q", line)
	}
	if got := countSub(line, "id="); got != 2 {
		t.Errorf("clean control must carry exactly two occurrences, got %d in %q", got, line)
	}
}

func TestPayloadEncoding_KeepsWireWellFormed(t *testing.T) {
	rr := modtest.Request(t, "http://acme.test/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	// A payload with a space, quote and '=' must be percent-encoded so the request
	// line stays parseable, while still surviving as a duplicate.
	vars := queryDuplicate{}.Variants(rr, ip, "1' AND 1=1--")
	var last *Variant
	for i := range vars {
		if vars[i].Name == "query-dup-payload-last" {
			last = &vars[i]
		}
	}
	if last == nil {
		t.Fatal("missing query-dup-payload-last")
	}
	line := requestLine(last.Raw)
	if strings.Contains(line, "1' AND 1=1--") {
		t.Errorf("payload must be URL-encoded on the wire, found raw spaces: %q", line)
	}
	if !strings.Contains(line, "id=1&id=1%27") { // %27 = single quote, encoded
		t.Errorf("expected encoded duplicate sequence id=1&id=1%%27..., got %q", line)
	}
	// The request line must not contain a raw space in the encoded value region
	// (a raw space would break the METHOD/target/HTTP-version split).
	fields := strings.Fields(line)
	if len(fields) != 3 {
		t.Errorf("request line must be METHOD TARGET HTTP/x (3 fields), got %d: %q", len(fields), line)
	}
}
