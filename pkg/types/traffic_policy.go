package types

import "strings"

// TrafficPolicy is the scan's per-method traffic policy (SAFE-8), resolved
// once by the runner from scope.methods and read by every sender: the
// requester (chokepoint), the executor (method_policy skip), discovery, the
// browser crawler and the known-issue scan. A nil *TrafficPolicy allows
// everything.
type TrafficPolicy struct {
	// AllowedMethods is the uppercase method set; empty means every method.
	AllowedMethods map[string]bool
	// SubmitForms, LoginAttempts and Uploads gate the crawler's state-changing
	// interactions. All false under a read-only policy.
	SubmitForms   bool
	LoginAttempts bool
	Uploads       bool
}

// readOnlyMethods are the methods a read-only policy may contain.
var readOnlyMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// NewTrafficPolicy builds the policy for a scope.methods list. An empty list
// returns nil (allow everything). A list of only GET/HEAD/OPTIONS is read-only
// and turns off form submission, crawler login attempts and uploads.
func NewTrafficPolicy(methods []string) *TrafficPolicy {
	allowed := make(map[string]bool, len(methods))
	for _, m := range methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			allowed[m] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	p := &TrafficPolicy{AllowedMethods: allowed, SubmitForms: true, LoginAttempts: true, Uploads: true}
	if p.ReadOnly() {
		p.SubmitForms, p.LoginAttempts, p.Uploads = false, false, false
	}
	return p
}

// AllowsMethod reports whether method may be sent. Nil-safe.
func (p *TrafficPolicy) AllowsMethod(method string) bool {
	if p == nil || len(p.AllowedMethods) == 0 {
		return true
	}
	return p.AllowedMethods[strings.ToUpper(strings.TrimSpace(method))]
}

// ReadOnly reports whether the policy allows only GET/HEAD/OPTIONS.
func (p *TrafficPolicy) ReadOnly() bool {
	if p == nil || len(p.AllowedMethods) == 0 {
		return false
	}
	for m := range p.AllowedMethods {
		if !readOnlyMethods[m] {
			return false
		}
	}
	return true
}

// AllowsSubmitForms / AllowsLoginAttempts / AllowsUploads are nil-safe reads.
func (p *TrafficPolicy) AllowsSubmitForms() bool   { return p == nil || p.SubmitForms }
func (p *TrafficPolicy) AllowsLoginAttempts() bool { return p == nil || p.LoginAttempts }
func (p *TrafficPolicy) AllowsUploads() bool       { return p == nil || p.Uploads }

// MethodOverrideHeaders are the request headers that smuggle a different
// method past a policy; a disallowed value in any of them is refused too.
var MethodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}
