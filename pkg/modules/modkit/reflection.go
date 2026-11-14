package modkit

import (
	"context"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/utils"
)

// ReflectionNeed says where a module needs an insertion point's value to come
// back for its test to mean anything.
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

// ReflectionProfile is what one canary probe of an insertion point showed.
type ReflectionProfile struct {
	InBody    bool
	InHeaders bool
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
	if base != "" && infra.IsNumericValue(base) {
		return "7" + utils.RandomOf(9, "0123456789")
	}
	return "vgl" + utils.RandomOf(9, "abcdefghijklmnopqrstuvwxyz0123456789")
}

// ReflectionProfile probes ip once with a type-preserving canary and reports
// where it came back. Memoised per (record, point type, point name) for the
// scan, with concurrent callers collapsed (EndpointMemo), so every
// reflection-dependent module on the point shares one request. A
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
			p.InBody = strings.Contains(resp.Body().String(), canary)
		headers:
			for _, vals := range r.Header {
				for _, hv := range vals {
					if strings.Contains(hv, canary) {
						p.InHeaders = true
						break headers
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
