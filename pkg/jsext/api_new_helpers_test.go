package jsext

import (
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── diffResponses tests ──────────────────────────────────────────────────────

func TestDiffResponsesSameStatus(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var a = {status: 200, body: "hello world", headers: {"content-type": "text/html"}};
		var b = {status: 200, body: "hello earth", headers: {"content-type": "text/html"}};
		var result = vigolium.utils.diffResponses(a, b);
		JSON.stringify({
			statusMatch: result.status_match,
			sim: result.body_similarity,
			lengthDiff: result.length_diff,
			likelySame: result.likely_same_content
		});
	`)
	require.NoError(t, err)
	s := val.String()
	assert.Contains(t, s, `"statusMatch":true`)
}

func TestDiffResponsesDifferentStatus(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var a = {status: 200, body: "OK", headers: {}};
		var b = {status: 404, body: "Not Found", headers: {}};
		vigolium.utils.diffResponses(a, b).status_match;
	`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

func TestDiffResponsesHeaderDiff(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var a = {status: 200, body: "", headers: {"x-old": "1", "shared": "same"}};
		var b = {status: 200, body: "", headers: {"x-new": "2", "shared": "same"}};
		var result = vigolium.utils.diffResponses(a, b);
		JSON.stringify({
			added: result.header_diff.added.length,
			removed: result.header_diff.removed.length
		});
	`)
	require.NoError(t, err)
	s := val.String()
	assert.Contains(t, s, `"added":1`)
	assert.Contains(t, s, `"removed":1`)
}

func TestDiffResponsesNull(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`vigolium.utils.diffResponses(null, null)`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))
}

func TestDiffResponsesBodySimilarityIdentical(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var a = {status: 200, body: "exactly the same content", headers: {}};
		var b = {status: 200, body: "exactly the same content", headers: {}};
		vigolium.utils.diffResponses(a, b).body_similarity;
	`)
	require.NoError(t, err)
	assert.Equal(t, 1.0, val.ToFloat())
}

func TestDiffResponsesLikelySameContent(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var a = {status: 200, body: "exactly the same content here", headers: {}};
		var b = {status: 200, body: "exactly the same content here", headers: {}};
		vigolium.utils.diffResponses(a, b).likely_same_content;
	`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
}

func TestDiffResponsesLengthDiff(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var a = {status: 200, body: "short", headers: {}};
		var b = {status: 200, body: "a much longer body string", headers: {}};
		vigolium.utils.diffResponses(a, b).length_diff;
	`)
	require.NoError(t, err)
	// b is longer than a, so length_diff should be positive
	assert.True(t, val.ToInteger() > 0)
}

// ── cssSelect tests ──────────────────────────────────────────────────────────

func TestCSSSelectByClass(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var html = '<html><body><div class="test">hello</div><div class="other">world</div></body></html>';
		var results = vigolium.utils.cssSelect(html, ".test");
		JSON.stringify({count: results.length, text: results[0].text});
	`)
	require.NoError(t, err)
	s := val.String()
	assert.Contains(t, s, `"count":1`)
	assert.Contains(t, s, `"text":"hello"`)
}

func TestCSSSelectByID(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var html = '<html><body><span id="foo">bar</span></body></html>';
		var results = vigolium.utils.cssSelect(html, "#foo");
		results[0].text;
	`)
	require.NoError(t, err)
	assert.Equal(t, "bar", val.String())
}

func TestCSSSelectInputAttrs(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var html = '<form><input name="csrf_token" type="hidden" value="abc123"><input name="user" type="text"></form>';
		var results = vigolium.utils.cssSelect(html, 'input[name="csrf_token"]');
		JSON.stringify({count: results.length, value: results[0].attrs.value, name: results[0].attrs.name});
	`)
	require.NoError(t, err)
	s := val.String()
	assert.Contains(t, s, `"count":1`)
	assert.Contains(t, s, `"value":"abc123"`)
	assert.Contains(t, s, `"name":"csrf_token"`)
}

func TestCSSSelectEmpty(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var html = '<html><body><p>nothing</p></body></html>';
		vigolium.utils.cssSelect(html, ".nonexistent").length;
	`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), val.ToInteger())
}

func TestCSSSelectMultiple(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var html = '<ul><li>one</li><li>two</li><li>three</li></ul>';
		vigolium.utils.cssSelect(html, "li").length;
	`)
	require.NoError(t, err)
	assert.Equal(t, int64(3), val.ToInteger())
}

func TestCSSSelectInnerHTML(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`
		var html = '<div id="wrap"><strong>bold</strong> text</div>';
		vigolium.utils.cssSelect(html, "#wrap")[0].html;
	`)
	require.NoError(t, err)
	s := val.String()
	assert.Contains(t, s, "<strong>bold</strong>")
}

func TestCSSSelectEmptyInput(t *testing.T) {
	vm := newTestVM(t)
	val, err := vm.RunString(`vigolium.utils.cssSelect("", "div").length`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), val.ToInteger())
}
