package modtest

import (
	"errors"
	"fmt"
	"sync"

	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// ActiveModule is the slice of modules.ActiveModule that RunActive needs.
// Declared here (modules.ActiveModule satisfies it) because pkg/modules imports
// every module package, whose tests import modtest - importing pkg/modules from
// here would be a cycle.
type ActiveModule interface {
	ID() string
	ScanScopes() modkit.ScanScope
	AllowedInsertionPointTypes() modkit.InsertionPointTypeSet
	ScanPerInsertionPoint(rr *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, client *httpRequester.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerRequest(rr *httpmsg.HttpRequestResponse, client *httpRequester.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerHost(rr *httpmsg.HttpRequestResponse, client *httpRequester.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error)
}

// RunActive runs mod against rr the way the executor dispatches it: once per
// scan scope the module declares (the executor runs every declared scope):
//   - ScanScopeHost: ScanPerHost once;
//   - ScanScopeRequest: ScanPerRequest once;
//   - ScanScopeInsertionPoint: every insertion point of rr (nested included)
//     the module accepts, ScanPerInsertionPoint for each.
//
// Findings from every call are concatenated; per-call errors are joined and
// returned alongside whatever findings the other calls produced. It is the
// shared dispatcher for the benign sweep and the detection benchmark harness
// (test/benchmark/harness).
func RunActive(mod ActiveModule, rr *httpmsg.HttpRequestResponse, client *httpRequester.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	scopes := mod.ScanScopes()
	known := modkit.ScanScopeHost | modkit.ScanScopeRequest | modkit.ScanScopeInsertionPoint
	if scopes&known == 0 {
		return nil, fmt.Errorf("module %s: unknown ScanScope %v", mod.ID(), scopes)
	}

	var (
		all  []*output.ResultEvent
		errs []error
	)
	collect := func(label string, found []*output.ResultEvent, err error) {
		all = append(all, found...)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
		}
	}

	if scopes.Has(modkit.ScanScopeHost) {
		found, err := mod.ScanPerHost(rr, client, scanCtx)
		collect("per-host", found, err)
	}
	if scopes.Has(modkit.ScanScopeRequest) {
		found, err := mod.ScanPerRequest(rr, client, scanCtx)
		collect("per-request", found, err)
	}
	if scopes.Has(modkit.ScanScopeInsertionPoint) {
		points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
		if err != nil {
			errs = append(errs, fmt.Errorf("create insertion points: %w", err))
		}
		allowed := mod.AllowedInsertionPointTypes()
		for _, ip := range points {
			if !allowed.Contains(ip.Type()) {
				continue
			}
			found, err := mod.ScanPerInsertionPoint(rr, ip, client, scanCtx)
			collect(fmt.Sprintf("insertion point %q", ip.Name()), found, err)
		}
	}
	return all, errors.Join(errs...)
}

// MockOASTProvider is an enabled modkit.OASTProvider that mints unique
// callback URLs under a reserved domain and records what was planted. No
// callback ever arrives, so a module that files a finding with it is reporting
// something other than an interaction.
type MockOASTProvider struct {
	mu       sync.Mutex
	n        int
	URLs     []string
	Payloads map[string]string
}

// GenerateURL implements modkit.OASTProvider.
func (m *MockOASTProvider) GenerateURL(_, _, _, _, _ string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	u := fmt.Sprintf("http://c%04d.oast.invalid", m.n)
	m.URLs = append(m.URLs, u)
	return u
}

// RecordPayload implements modkit.OASTProvider.
func (m *MockOASTProvider) RecordPayload(callbackURL, payload string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Payloads == nil {
		m.Payloads = make(map[string]string)
	}
	m.Payloads[callbackURL] = payload
}

// Enabled implements modkit.OASTProvider.
func (m *MockOASTProvider) Enabled() bool { return true }
