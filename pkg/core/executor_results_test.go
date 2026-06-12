package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// metaStub is an activeStub with a configurable static Description (the
// "what it means / how it's exploited / fix" explanation block) and Tags, so we
// can exercise assignModuleInfo's description-composition and tag propagation.
type metaStub struct {
	activeStub
	desc string
	tags []string
}

func (m *metaStub) Description() string { return m.desc }
func (m *metaStub) Tags() []string      { return m.tags }

var _ modules.Module = (*metaStub)(nil)

func TestAssignModuleInfo_DescriptionAndTags(t *testing.T) {
	const block = "**What it means:** demo. **How it's exploited:** demo. **Fix:** demo."
	e := &Executor{}
	m := &metaStub{
		activeStub: activeStub{id: "demo-module"},
		desc:       block,
		tags:       []string{"injection", "moderate"},
	}

	t.Run("inline lead is preserved and block appended", func(t *testing.T) {
		r := &output.ResultEvent{Info: output.Info{Description: "Demo finding on header X"}}
		e.assignModuleInfo(r, m)
		assert.True(t, strings.HasPrefix(r.Info.Description, "Demo finding on header X"),
			"the module's per-finding context line must stay as the lead")
		assert.Contains(t, r.Info.Description, block, "the explanation block must be appended")
		assert.Contains(t, r.Info.Description, "\n\n", "block must be separated from the lead")
	})

	t.Run("empty inline falls back to the block alone", func(t *testing.T) {
		r := &output.ResultEvent{}
		e.assignModuleInfo(r, m)
		assert.Equal(t, block, r.Info.Description)
	})

	t.Run("tags propagate from the module", func(t *testing.T) {
		r := &output.ResultEvent{}
		e.assignModuleInfo(r, m)
		assert.Equal(t, []string{"injection", "moderate"}, r.Info.Tags)
	})

	t.Run("pre-set tags are not overwritten", func(t *testing.T) {
		r := &output.ResultEvent{Info: output.Info{Tags: []string{"nuclei-set"}}}
		e.assignModuleInfo(r, m)
		assert.Equal(t, []string{"nuclei-set"}, r.Info.Tags)
	})

	t.Run("block is not appended twice", func(t *testing.T) {
		r := &output.ResultEvent{Info: output.Info{Description: "lead\n\n" + block}}
		e.assignModuleInfo(r, m)
		assert.Equal(t, 1, strings.Count(r.Info.Description, block),
			"already-composed descriptions must not gain a duplicate block")
	})
}

func TestAssignModuleInfo_EmptyBlockLeavesDescriptionUntouched(t *testing.T) {
	e := &Executor{}
	m := &metaStub{activeStub: activeStub{id: "no-desc"}}
	r := &output.ResultEvent{Info: output.Info{Description: "just the lead", Severity: severity.High}}
	e.assignModuleInfo(r, m)
	assert.Equal(t, "just the lead", r.Info.Description)
}
