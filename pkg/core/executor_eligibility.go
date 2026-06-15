package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/utils"
)

// requestEligibility caches common CanProcess checks for a single request.
// This avoids re-parsing the URL and re-checking media/method filters for every module.
type requestEligibility struct {
	baseEligible bool // true when URL parses OK, not media, not skip-method
}

// computeEligibility pre-computes the base CanProcess checks once per request.
func computeEligibility(item *httpmsg.HttpRequestResponse) requestEligibility {
	if item == nil || item.Request() == nil {
		return requestEligibility{}
	}
	urlx, err := item.URL()
	if err != nil {
		return requestEligibility{}
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return requestEligibility{}
	}
	method := item.Request().Method()
	switch method {
	case "OPTIONS", "CONNECT", "HEAD", "TRACE":
		return requestEligibility{}
	}
	return requestEligibility{baseEligible: true}
}

// includesBaseCanProcess is an optional interface for active modules.
// Modules whose CanProcess includes the base URL/media/method checks return true (default).
// Modules with fully custom CanProcess override this to return false.
type includesBaseCanProcess interface {
	IncludesBaseCanProcess() bool
}

// includesBase returns true if the module's CanProcess includes the standard base checks.
func includesBase(m modules.ActiveModule) bool {
	if checker, ok := m.(includesBaseCanProcess); ok {
		return checker.IncludesBaseCanProcess()
	}
	return true // default: assumes base is included
}

// activeModuleCanProcess checks whether a module can process the request, using
// the cached eligibility to skip redundant CanProcess calls when the base checks
// would reject the request.
func activeModuleCanProcess(m modules.ActiveModule, item *httpmsg.HttpRequestResponse, elig *requestEligibility) bool {
	if elig.baseEligible {
		// Base passes — still call CanProcess for modules with extra checks
		return m.CanProcess(item)
	}
	// Base fails — only call CanProcess for modules that don't include base checks
	if includesBase(m) {
		return false // base would reject, skip without calling CanProcess
	}
	return m.CanProcess(item)
}

// passesTechFilter applies the tech-stack allowlist gate. Modules with no
// required techs, or hosts with no detected stack yet, fail open.
func (e *Executor) passesTechFilter(m modules.Module, item *httpmsg.HttpRequestResponse) bool {
	if e.cfg.TechFilterDisabled {
		return true
	}
	required := e.requiredTechsFor(m)
	if len(required) == 0 {
		return true
	}
	if e.scanCtx == nil || e.scanCtx.TechStack == nil {
		return true
	}
	return e.scanCtx.TechStack.Allows(hostFromItem(item), required)
}

// passesContentClassFilter applies the content-class gate to a passive module:
// a module that structurally requires a body shape (e.g. clickjacking needs an
// HTML document) is skipped on a record whose response is a confirmed different
// structured class. Fails open on unknown/text responses, on content-agnostic
// modules, and when the tech filter is disabled (--no-tech-filter / deep). The
// per-host heuristics class is consulted only when the record's own Content-Type
// is indeterminate.
func (e *Executor) passesContentClassFilter(m modules.Module, item *httpmsg.HttpRequestResponse) bool {
	if e.cfg.TechFilterDisabled {
		return true
	}
	required := e.requiredContentClassesFor(m)
	if len(required) == 0 {
		return true
	}
	class := modkit.ResponseContentClass(item)
	if class == modkit.ContentClassUnknown && e.scanCtx != nil && e.scanCtx.ContentClass != nil {
		// Record's own type is indeterminate — fall back to the host's root class.
		class = e.scanCtx.ContentClass.Get(hostFromItem(item))
	}
	return modkit.ContentClassAllows(required, class)
}

// requiredContentClassesFor returns the module's required content-class list,
// memoized on the executor. Prefers an explicit ContentClassAware implementation
// and otherwise derives the requirement from the module's tags.
func (e *Executor) requiredContentClassesFor(m modules.Module) []string {
	id := m.ID()
	if v, ok := e.caches.moduleContentClassReq.Load(id); ok {
		if v == nil {
			return nil
		}
		return v.([]string)
	}
	var derived []string
	if aware, ok := m.(modules.ContentClassAware); ok {
		derived = normalizeTechTags(aware.RequiredContentClasses())
	} else {
		derived = modules.DerivedContentClasses(m.Tags())
	}
	var stored any
	if len(derived) > 0 {
		stored = derived
	}
	e.caches.moduleContentClassReq.Store(id, stored)
	return derived
}

// requiredTechsFor returns the module's required-tech allowlist. Results are
// memoized on the executor and stored pre-normalized so the registry lookup
// can skip per-call trim/lower work. Fingerprint modules (which populate the
// registry) are always exempt.
func (e *Executor) requiredTechsFor(m modules.Module) []string {
	id := m.ID()
	if v, ok := e.caches.moduleTechReq.Load(id); ok {
		if v == nil {
			return nil
		}
		return v.([]string)
	}
	var derived []string
	if aware, ok := m.(modules.TechAware); ok {
		derived = normalizeTechTags(aware.RequiredTechs())
	} else if !strings.HasSuffix(id, "-fingerprint") {
		derived = modules.DerivedRequiredTechs(m.Tags()) // already normalized
	}
	var stored any
	if len(derived) > 0 {
		stored = derived
	}
	e.caches.moduleTechReq.Store(id, stored)
	return derived
}

// normalizeTechTags returns a fresh slice of trimmed, lowercased, non-empty
// tags. Used to canonicalize the result of an explicit TechAware
// implementation so registry lookups can compare directly.
func normalizeTechTags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// hostFromItem extracts the host for tech-registry lookup. Prefers Service().Host()
// (already includes port for non-default ports) and falls back to the URL host.
func hostFromItem(item *httpmsg.HttpRequestResponse) string {
	if item == nil {
		return ""
	}
	if svc := item.Service(); svc != nil {
		if h := svc.Host(); h != "" {
			return h
		}
	}
	if u, err := item.URL(); err == nil && u != nil {
		return u.Host
	}
	return ""
}
