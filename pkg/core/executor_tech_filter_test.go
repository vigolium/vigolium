package core

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// techStub satisfies modules.Module, which is all passesTechFilter needs.
type techStub struct {
	id       string
	tags     []string
	required []string // when set, the stub reports as TechAware
}

func (m *techStub) ID() string                                     { return m.id }
func (m *techStub) Name() string                                   { return m.id }
func (m *techStub) Description() string                            { return "" }
func (m *techStub) ShortDescription() string                       { return "" }
func (m *techStub) ConfirmationCriteria() string                   { return "" }
func (m *techStub) Severity() severity.Severity                    { return 0 }
func (m *techStub) Confidence() severity.Confidence                { return 0 }
func (m *techStub) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *techStub) Tags() []string                                 { return m.tags }
func (m *techStub) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }

// techStubAware adds an explicit TechAware implementation.
type techStubAware struct{ techStub }

func (m *techStubAware) RequiredTechs() []string { return m.required }

func TestPassesTechFilter(t *testing.T) {
	_, rr := makeTestItem("example.com", "/", "")

	makeExecutor := func(disabled bool, marks map[string]string) *Executor {
		e := &Executor{cfg: ExecutorConfig{TechFilterDisabled: disabled}}
		e.scanCtx = &modules.ScanContext{TechStack: modkit.NewTechRegistry()}
		for host, tag := range marks {
			e.scanCtx.TechStack.Mark(host, tag)
		}
		return e
	}

	t.Run("filter disabled always passes", func(t *testing.T) {
		e := makeExecutor(true, nil)
		m := &techStub{id: "spring-test", tags: []string{"spring", "java"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("disabled filter must always pass")
		}
	})

	t.Run("module without tech tags always passes", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "nextjs"})
		m := &techStub{id: "xss-generic", tags: []string{"injection", "xss"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("non-tech-tagged module must always pass")
		}
	})

	t.Run("fail-open when host unknown", func(t *testing.T) {
		e := makeExecutor(false, nil)
		m := &techStub{id: "spring-test", tags: []string{"spring"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("unknown host must fail open")
		}
	})

	t.Run("gated when host known in the same category and no match", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "django"})
		m := &techStub{id: "spring-test", tags: []string{"spring", "java"}}
		if e.passesTechFilter(m, rr) {
			t.Fatal("Spring module must be gated on a Django host")
		}
	})

	// A front-end-only identification says nothing about the
	// backend. {angular, spa} are descriptive; nextjs is a meta-framework.
	t.Run("descriptive tags never gate", func(t *testing.T) {
		e := makeExecutor(false, nil)
		e.scanCtx.TechStack.Mark("example.com", "angular")
		e.scanCtx.TechStack.Mark("example.com", "spa")
		m := &techStub{id: "spring-test", tags: []string{"spring", "java"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("Spring module skipped on an Angular front end: descriptive tags must not gate")
		}
		if e.scanCtx.TechStack.HostKnown("example.com") {
			t.Fatal("a host known only by descriptive tags must not be HostKnown")
		}
	})
	t.Run("other category does not exclude", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "nextjs"})
		m := &techStub{id: "spring-test", tags: []string{"spring", "java"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("a Next.js front end must not exclude backend modules")
		}
	})
	// "javascript" no longer gates.
	t.Run("javascript tag does not gate", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "django"})
		m := &techStub{id: "js-secrets", tags: []string{"javascript", "passive"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("javascript-tagged module must run on any host")
		}
	})
	// A reverse proxy banner never excludes the app behind it.
	t.Run("server tags never exclude", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "nginx"})
		m := &techStub{id: "tomcat-mgr", tags: []string{"tomcat"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("nginx in front must not exclude a Tomcat module")
		}
	})

	t.Run("passes when host has matching tech", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "spring"})
		m := &techStub{id: "spring-test", tags: []string{"spring", "java"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("Spring module must run on Spring host")
		}
	})

	t.Run("fingerprint modules are exempt", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "nextjs"})
		m := &techStub{id: "django-fingerprint", tags: []string{"django"}}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("fingerprint modules must always run")
		}
	})

	t.Run("TechAware overrides tag derivation", func(t *testing.T) {
		e := makeExecutor(false, map[string]string{"example.com": "nextjs"})
		m := &techStubAware{
			techStub: techStub{
				id:       "weird-mod",
				tags:     []string{"spring"},
				required: []string{"nextjs"},
			},
		}
		if !e.passesTechFilter(m, rr) {
			t.Fatal("explicit TechAware must override tag derivation")
		}
	})
}
