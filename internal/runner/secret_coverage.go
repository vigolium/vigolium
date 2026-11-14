package runner

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/output"
)

// secretCoverage is the set of record UUIDs whose response the dynamic
// assessment's secret_detect pass already analysed in this scan.
//
// secret_detect used to be removed from dynamic assessment whenever the
// known-issue scan was enabled, to avoid duplicate secret findings. The
// known-issue scan is the last phase, so a scan cut short (budget, Ctrl-C,
// failure) lost secret detection entirely. Now both run: assessment covers what
// it reaches, and the known-issue batch covers only the records assessment did
// not, with finding identity collapsing anything that overlaps.
type secretCoverage struct {
	mu   sync.RWMutex
	uuid map[string]struct{}
}

func newSecretCoverage() *secretCoverage {
	return &secretCoverage{uuid: make(map[string]struct{})}
}

func (c *secretCoverage) add(uuid string) {
	if c == nil || uuid == "" {
		return
	}
	c.mu.Lock()
	c.uuid[uuid] = struct{}{}
	c.mu.Unlock()
}

// has reports whether the record was already scanned. Nil-safe: no coverage
// means nothing was covered.
func (c *secretCoverage) has(uuid string) bool {
	if c == nil || uuid == "" {
		return false
	}
	c.mu.RLock()
	_, ok := c.uuid[uuid]
	c.mu.RUnlock()
	return ok
}

func (c *secretCoverage) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.uuid)
}

// coverageRecordingPassive wraps the secret_detect passive module so each
// record it analyses without error is noted in a secretCoverage. It forwards
// the contextual interface when the wrapped module has one.
type coverageRecordingPassive struct {
	modules.PassiveModule
	cov *secretCoverage
}

func (m *coverageRecordingPassive) record(item *httpmsg.HttpRequestResponse, scanCtx *modules.ScanContext) {
	if scanCtx == nil || scanCtx.RequestUUIDResolver == nil || item == nil || item.Request() == nil {
		return
	}
	m.cov.add(scanCtx.RequestUUIDResolver.ResolveRequestUUID(item.Request().ID()))
}

// ScanPerRequest implements modules.PassiveModule.
func (m *coverageRecordingPassive) ScanPerRequest(item *httpmsg.HttpRequestResponse, scanCtx *modules.ScanContext) ([]*output.ResultEvent, error) {
	res, err := m.PassiveModule.ScanPerRequest(item, scanCtx)
	if err == nil {
		m.record(item, scanCtx)
	}
	return res, err
}

// ScanPerRequestContext forwards modules.ContextualPassiveModule when present.
func (m *coverageRecordingPassive) ScanPerRequestContext(ctx context.Context, item *httpmsg.HttpRequestResponse, scanCtx *modules.ScanContext) ([]*output.ResultEvent, error) {
	var (
		res []*output.ResultEvent
		err error
	)
	if cm, ok := m.PassiveModule.(modules.ContextualPassiveModule); ok {
		res, err = cm.ScanPerRequestContext(ctx, item, scanCtx)
	} else {
		res, err = m.PassiveModule.ScanPerRequest(item, scanCtx)
	}
	if err == nil && ctx.Err() == nil {
		m.record(item, scanCtx)
	}
	return res, err
}

// ScanPerHostContext forwards modules.ContextualPassiveModule when present.
func (m *coverageRecordingPassive) ScanPerHostContext(ctx context.Context, item *httpmsg.HttpRequestResponse, scanCtx *modules.ScanContext) ([]*output.ResultEvent, error) {
	if cm, ok := m.PassiveModule.(modules.ContextualPassiveModule); ok {
		return cm.ScanPerHostContext(ctx, item, scanCtx)
	}
	return m.ScanPerHost(item, scanCtx)
}

// wrapSecretCoverage replaces secret_detect in mods with a coverage-recording
// wrapper writing into cov. Other modules are returned unchanged.
func wrapSecretCoverage(mods []modules.PassiveModule, cov *secretCoverage) []modules.PassiveModule {
	out := make([]modules.PassiveModule, len(mods))
	for i, m := range mods {
		if m.ID() == secret_detect.ModuleID {
			out[i] = &coverageRecordingPassive{PassiveModule: m, cov: cov}
			continue
		}
		out[i] = m
	}
	return out
}
