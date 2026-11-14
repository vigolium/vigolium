package modkit

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// ReflectionNeed says where a module needs an insertion point's value to come
// back for its test to mean anything (ECON-2).
type ReflectionNeed uint8

const (
	// ReflectBody: the value must appear in the response body.
	ReflectBody ReflectionNeed = 1 << iota
	// ReflectHeaders: the value must appear in a response header.
	ReflectHeaders
	// ReflectAny: either.
	ReflectAny = ReflectBody | ReflectHeaders
)

// ReflectionAware is the optional module interface: a module whose oracle is
// "the payload is reflected and transformed" (template injection, SSI/ESI,
// transformation probes, header injection) declares the reflection it needs,
// and the executor skips points whose shared canary probe shows no such
// reflection. One probe per point replaces every such module's own.
type ReflectionAware interface {
	RequiresReflection() ReflectionNeed
}

// OutOfBandLeg marks a ReflectionAware module that also has a blind
// (out-of-band) leg which does not need reflection: while OAST is enabled the
// reflection gate does not apply to it, so only its in-band leg is gated.
type OutOfBandLeg interface {
	HasOutOfBandLeg() bool
}

// Reflection contexts (ReflectionProfile.Contexts bitmask).
const (
	ReflectCtxHTMLText uint16 = 1 << iota
	ReflectCtxHTMLAttr
	ReflectCtxScript
	ReflectCtxComment
	ReflectCtxJSON
	ReflectCtxOther
)

// ReflectionProfile is what one canary probe of an insertion point showed.
type ReflectionProfile struct {
	InBody    bool
	InHeaders bool
	// Contexts is the bitmask of body contexts the canary appeared in.
	Contexts uint16
	// RawEncoded: the canary came back byte-for-byte (an alphanumeric canary
	// has nothing for an encoder to change, so this is the only encoding the
	// shared probe can observe; modules probe special characters themselves).
	RawEncoded bool
	// Blocked: the probe response was a WAF/auth/rate-limit block, so the
	// profile says nothing — callers fail open.
	Blocked bool
}

// Satisfies reports whether the profile meets need.
func (p *ReflectionProfile) Satisfies(need ReflectionNeed) bool {
	if p == nil || need == 0 {
		return true
	}
	if need&ReflectBody != 0 && p.InBody {
		return true
	}
	if need&ReflectHeaders != 0 && p.InHeaders {
		return true
	}
	return false
}

// Reflected reports whether the canary came back anywhere.
func (p *ReflectionProfile) Reflected() bool { return p != nil && (p.InBody || p.InHeaders) }

// reflectionCanary returns a canary of the same shape as base: digits for a
// numeric value (so a typed parameter still accepts it), lowercase
// alphanumerics otherwise.
func reflectionCanary(base string) string {
	const digits = "0123456789"
	const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	pick := func(set string, n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			k, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
			if err != nil {
				b.WriteByte(set[i%len(set)])
				continue
			}
			b.WriteByte(set[k.Int64()])
		}
		return b.String()
	}
	if base != "" && infra.IsNumericValue(base) {
		return "7" + pick(digits, 9)
	}
	return "vgl" + pick(alnum, 9)
}

// classifyReflection finds canary's body contexts.
func classifyReflection(body, contentType, canary string) uint16 {
	var ctx uint16
	if strings.Contains(strings.ToLower(contentType), "json") {
		ctx |= ReflectCtxJSON
	}
	lower := strings.ToLower(body)
	for from := 0; ; {
		i := strings.Index(body[from:], canary)
		if i < 0 {
			break
		}
		pos := from + i
		before := lower[:pos]
		switch {
		case strings.LastIndex(before, "<script") > strings.LastIndex(before, "</script"):
			ctx |= ReflectCtxScript
		case strings.LastIndex(before, "<!--") > strings.LastIndex(before, "-->"):
			ctx |= ReflectCtxComment
		case strings.LastIndexByte(before, '<') > strings.LastIndexByte(before, '>'):
			ctx |= ReflectCtxHTMLAttr
		case strings.Contains(lower, "<html") || strings.Contains(lower, "<body"):
			ctx |= ReflectCtxHTMLText
		default:
			ctx |= ReflectCtxOther
		}
		from = pos + len(canary)
	}
	return ctx
}

// ReflectionProfile probes ip once with a type-preserving canary and reports
// where it came back. Memoised per (record, point type, point name) for the
// scan, with concurrent callers collapsed (EndpointMemo), so every
// reflection-dependent module on the point shares one request (ECON-2). A
// transport error is returned and not cached; a blocked answer is cached as
// Blocked (callers fail open).
func (sc *ScanContext) ReflectionProfile(ctx context.Context, item *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, client *http.Requester) (*ReflectionProfile, error) {
	if item == nil || ip == nil || client == nil {
		return nil, nil
	}
	var probeErr error
	name := "reflection-v1\x00" + ip.Type().String() + "\x00" + ip.Name()
	v := sc.EndpointMemo(name, item, 0, func() (any, bool) {
		canary := reflectionCanary(ip.BaseValue())
		req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(canary)), item.Service())
		resp, _, err := client.ExecuteContext(ctx, req, http.Options{})
		if err != nil {
			probeErr = err
			return (*ReflectionProfile)(nil), false
		}
		defer resp.Close()
		p := &ReflectionProfile{Blocked: infra.IsBlockedResponse(resp)}
		if r := resp.Response(); r != nil {
			body := resp.Body().String()
			if strings.Contains(body, canary) {
				p.InBody, p.RawEncoded = true, true
				p.Contexts = classifyReflection(body, r.Header.Get("Content-Type"), canary)
			}
			for _, vals := range r.Header {
				for _, hv := range vals {
					if strings.Contains(hv, canary) {
						p.InHeaders = true
					}
				}
			}
		}
		return p, true
	})
	if probeErr != nil {
		return nil, probeErr
	}
	p, _ := v.(*ReflectionProfile)
	return p, nil
}
