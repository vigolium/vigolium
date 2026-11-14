package fuzz

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/bulkhttp"
)

// multiplexSentinel is injected at each position to see where a payload lands
// in the parsed request.
const multiplexSentinel = "vigolium-proto-probe"

// MultiplexBlocker reports why a fuzz job must be sent as HTTP/1.1, or ""
// when HTTP/2 and HTTP/3 deliver every case exactly as HTTP/1.1 would. A
// run uses one protocol for its baseline and every case, so the reason is
// decided once, for the whole job:
//
//   - the request (or a position's edit of it) carries a connection-specific
//     header whose loss would change it (bulkhttp.RequiresHTTP1): HTTP/2 and
//     HTTP/3 forbid those and their encoders silently drop them;
//   - a position rewrites the Host header (HTTP/2 and HTTP/3 carry it as
//     :authority, which front ends route on differently - the very thing a
//     Host-header probe is testing);
//   - a position lands in a header name or the HTTP version;
//   - a payload holds CR, LF or NUL, whose meaning (header injection,
//     request splitting) only exists in HTTP/1.1's text framing.
func MultiplexBlocker(raw []byte, positions []Position, cases []Case) string {
	return MultiplexBlockerPlan(raw, positions, CaseSlice(cases))
}

// MultiplexBlockerPlan is MultiplexBlocker over a lazily-indexed plan.
func MultiplexBlockerPlan(raw []byte, positions []Position, cases CasePlan) string {
	base, err := parseRawRequest(raw)
	if err != nil {
		return "the request does not parse as HTTP/1.1"
	}
	if reason := bulkhttp.RequiresHTTP1(base.Header); reason != "" {
		return "the request " + reason
	}
	for _, p := range positions {
		label := p.Label + ":" + p.Name
		req, err := parseRawRequest(p.build(raw, multiplexSentinel))
		if err != nil {
			return fmt.Sprintf("position %s does not build a parseable request", label)
		}
		if req.Host != base.Host {
			return fmt.Sprintf("position %s fuzzes the Host header", label)
		}
		if strings.Contains(req.Proto, multiplexSentinel) {
			return fmt.Sprintf("position %s fuzzes the HTTP version", label)
		}
		for name := range req.Header {
			if strings.Contains(strings.ToLower(name), multiplexSentinel) {
				return fmt.Sprintf("position %s fuzzes a header name", label)
			}
		}
		if reason := bulkhttp.RequiresHTTP1(req.Header); reason != "" {
			return fmt.Sprintf("position %s %s", label, reason)
		}
	}
	for i, n := 0, planLen(cases); i < n; i++ {
		for _, a := range cases.At(i).Assignments {
			if strings.ContainsAny(a.Payload, "\r\n\x00") {
				return "a payload contains CR, LF or NUL"
			}
		}
	}
	return ""
}

func parseRawRequest(raw []byte) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(bytes.NewReader(NormalizeRawRequest(raw))))
}

func planLen(p CasePlan) int {
	if p == nil {
		return 0
	}
	return p.Len()
}
