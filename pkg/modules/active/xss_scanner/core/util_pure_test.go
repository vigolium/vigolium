package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/mimetype_detector"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// ── http_content_type.go ─────────────────────────────────────────────────────

func TestContentTypeToDefCode(t *testing.T) {
	cases := []struct {
		in   mimetype_detector.ContentType
		want int16
	}{
		{mimetype_detector.ContentType_NONE, DefTypeNone},
		{mimetype_detector.ContentType_HTML, DefTypeHTML},
		{mimetype_detector.ContentType_PLAIN_TEXT, DefTypePlainText},
		{mimetype_detector.ContentType_CSS, DefTypeCSS},
		{mimetype_detector.ContentType_SCRIPT, DefTypeScript},
		{mimetype_detector.ContentType_JSON, DefTypeJSON},
		{mimetype_detector.ContentType_XML, DefTypeXML},
		{mimetype_detector.ContentType_RTF, DefTypeRTF},
		{mimetype_detector.ContentType_YAML, DefTypeYAML},
		{mimetype_detector.ContentType_SVG, DefTypeSVGImage},
		{mimetype_detector.ContentType_UNRECOGNIZED_CONTENT, DefTypeUnrecognizedContent},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ContentTypeToDefCode(tc.in))
	}
}

func TestIsTextualContentType(t *testing.T) {
	for _, code := range []int16{DefTypeNone, DefTypeHTML, DefTypePlainText, DefTypeCSS, DefTypeScript, DefTypeJSON, DefTypeRTF, DefTypeXML, DefTypeYAML} {
		assert.True(t, IsTextualContentType(code), "code %d should be textual", code)
	}
	for _, code := range []int16{DefTypeJPEGImage, DefTypePNGImage, DefTypeSound, DefTypeVideo, DefTypeFlashObject, DefTypeUnrecognizedContent} {
		assert.False(t, IsTextualContentType(code), "code %d should not be textual", code)
	}
}

func TestIsAmbiguousOrUnrecognized(t *testing.T) {
	assert.True(t, IsAmbiguousOrUnrecognized(DefTypeNone))
	assert.True(t, IsAmbiguousOrUnrecognized(DefTypeUnrecognizedContent))
	assert.True(t, IsAmbiguousOrUnrecognized(DefTypeAmbiguous))
	assert.False(t, IsAmbiguousOrUnrecognized(DefTypeHTML))
}

func TestIsBinaryContentType(t *testing.T) {
	for _, code := range []int16{DefTypeJPEGImage, DefTypeGIFImage, DefTypePNGImage, DefTypeSVGImage, DefTypeSound, DefTypeVideo, DefTypeFlashObject} {
		assert.True(t, IsBinaryContentType(code), "code %d should be binary", code)
	}
	for _, code := range []int16{DefTypeHTML, DefTypePlainText, DefTypeScript, DefTypeNone, DefTypeUnknownApplication} {
		assert.False(t, IsBinaryContentType(code), "code %d should not be binary", code)
	}
}

func TestContentTypeCodeToString(t *testing.T) {
	assert.Equal(t, "HTML", ContentTypeCodeToString(DefTypeHTML))
	assert.Equal(t, "plain text", ContentTypeCodeToString(DefTypePlainText))
	assert.Equal(t, "a JPEG image", ContentTypeCodeToString(DefTypeJPEGImage))
	assert.Equal(t, "none", ContentTypeCodeToString(DefTypeNone))
	assert.Equal(t, "", ContentTypeCodeToString(DefTypeEmptyType1280))
	assert.Equal(t, "unrecognized", ContentTypeCodeToString(int16(9999)))
}

func TestContentTypeCodeToShortString(t *testing.T) {
	assert.Equal(t, "HTML", ContentTypeCodeToShortString(DefTypeHTML))
	assert.Equal(t, "text", ContentTypeCodeToShortString(DefTypePlainText))
	assert.Equal(t, "JPEG", ContentTypeCodeToShortString(DefTypeJPEGImage))
	assert.Equal(t, "", ContentTypeCodeToShortString(DefTypeNone))
	assert.Equal(t, "", ContentTypeCodeToShortString(int16(9999)))
}

func TestNewContentTypeProfileHTML(t *testing.T) {
	headers := map[string][]string{
		"Content-Type":           {"text/html; charset=utf-8"},
		"X-Content-Type-Options": {"nosniff"},
	}
	body := []byte("<!DOCTYPE html><html><body>x</body></html>")
	profile := NewContentTypeProfile(headers, body)
	require.NotNil(t, profile)

	assert.True(t, profile.IsContentTypeProfile())
	assert.Equal(t, "utf-8", profile.DetectedCharset())
	assert.Equal(t, "text/html; charset=utf-8", profile.GetContentTypeHeaderValue())
	assert.Equal(t, "text/html", profile.GetContentTypeHeaderValues())
	// Body is HTML -> inferred HTML; helpers should agree.
	assert.True(t, IsHtmlDef(profile))
	assert.True(t, profile.GetIsText() == isEffectiveTypeHelper(profile, DefTypePlainText))
	assert.False(t, profile.GetIsFlash())
	assert.NotEmpty(t, profile.String())

	info := profile.GetAllHeaderInfo()
	assert.Contains(t, info, "text/html; charset=utf-8")
	assert.Contains(t, info, "charset=utf-8")
	assert.Contains(t, info, "nosniff")
}

func TestNewContentTypeProfilePlainText(t *testing.T) {
	headers := map[string][]string{"Content-Type": {"text/plain"}}
	profile := NewContentTypeProfile(headers, []byte("just plain words here"))
	require.NotNil(t, profile)
	assert.True(t, profile.GetIsText())
	assert.True(t, IsPlainTextDef(profile))
	assert.True(t, IsTextualContentType(profile.GetStatedTypeCode()))
}

func TestIsBinaryDefNil(t *testing.T) {
	assert.False(t, IsBinaryDef(nil))
	assert.False(t, IsScriptDef(nil))
	assert.False(t, IsHtmlDef(nil))
	assert.False(t, IsPlainTextDef(nil))
}

// isEffectiveTypeHelper mirrors the package-private isEffectiveType for the
// equality check above without re-implementing it here.
func isEffectiveTypeHelper(profile *ContentTypeProfile, code int16) bool {
	return isEffectiveType(profile, code)
}

// ── util_string_encoder.go ───────────────────────────────────────────────────

func TestEncodeStringWithMode(t *testing.T) {
	// Odd mode -> custom percent encoding (alphanumerics pass through).
	assert.Equal(t, "abc123", EncodeStringWithMode("abc123", 1))
	assert.Equal(t, "a%3cb", EncodeStringWithMode("a<b", 1))       // '<' -> %3c
	assert.Equal(t, "%20", EncodeStringWithMode(" ", 1))           // space -> %20
	assert.Equal(t, "%07", EncodeStringWithMode("\x07", 1))        // single-hex-digit -> zero-padded
	assert.Equal(t, "\x00plain", EncodeStringWithMode("plain", 2)) // even & bit2 -> NUL prefix
	assert.Equal(t, "plain", EncodeStringWithMode("plain", 0))     // even & no bit2 -> unchanged
	assert.Equal(t, "plain", EncodeStringWithMode("plain", 4))     // even, bit2 unset
}

// ── util_string_context_parser.go ────────────────────────────────────────────

func TestExtractQuotedStringSegments(t *testing.T) {
	src := `var a = "hello"; var b = 'world'; // line comment "skip"
		var c = /* block */ "after"`
	segs, err := ExtractQuotedStringSegments(src, 0, len(src))
	require.NoError(t, err)

	contents := make([]string, 0, len(segs))
	for _, s := range segs {
		contents = append(contents, s.Content)
	}
	assert.Contains(t, contents, "hello")
	assert.Contains(t, contents, "world")
	assert.Contains(t, contents, "after")
	// Strings inside comments are not extracted.
	assert.NotContains(t, contents, "skip")
}

func TestExtractQuotedStringSegmentsEscapes(t *testing.T) {
	src := `"a\"b"`
	segs, err := ExtractQuotedStringSegments(src, 0, len(src))
	require.NoError(t, err)
	require.Len(t, segs, 1)
	assert.Equal(t, `a\"b`, segs[0].Content)
}

func TestExtractQuotedStringSegmentsInvalidBounds(t *testing.T) {
	_, err := ExtractQuotedStringSegments("abc", -1, 3)
	assert.Error(t, err)
	_, err = ExtractQuotedStringSegments("abc", 0, 99)
	assert.Error(t, err)
	_, err = ExtractQuotedStringSegments("abc", 2, 1)
	assert.Error(t, err)
}

func TestExtractQuotedStringSegmentsUnterminated(t *testing.T) {
	segs, err := ExtractQuotedStringSegments(`"unterminated`, 0, len(`"unterminated`))
	require.NoError(t, err)
	assert.Empty(t, segs)
}

func TestGetByteContextAfterDecoding(t *testing.T) {
	// Inside an unterminated double-quote string -> double-quote context.
	data := []byte(`x = "abc`)
	ctx := GetByteContextAfterDecoding(data, 0, len(data)-1)
	assert.Equal(t, segmentTypeDoubleQuote, ctx)

	// Closed string -> no context.
	closed := []byte(`x = "abc"`)
	assert.Equal(t, segmentTypeNone, GetByteContextAfterDecoding(closed, 0, len(closed)-1))

	// Invalid range -> none.
	assert.Equal(t, segmentTypeNone, GetByteContextAfterDecoding([]byte("ab"), 5, 1))

	// Empty data -> none.
	assert.Equal(t, segmentTypeNone, GetByteContextAfterDecoding([]byte{}, 0, 0))
}

// ── util_pattern_matcher.go ──────────────────────────────────────────────────

func TestByteMatchPosition(t *testing.T) {
	p := NewByteMatchPosition(2, 7)
	assert.Equal(t, 2, p.MatchStartIndex)
	assert.Equal(t, 7, p.MatchEndIndex)
}

func TestSimpleBytePatternMatcher(t *testing.T) {
	data := []byte("hello world")
	m := NewSimpleBytePatternMatcher([]byte("world"))
	pos := m.FindMatch(data, 0, len(data))
	require.NotNil(t, pos)
	assert.Equal(t, 6, pos.MatchStartIndex)
	assert.Equal(t, 11, pos.MatchEndIndex)

	// No match returns nil.
	assert.Nil(t, m.FindMatch([]byte("nothing here"), 0, 12))
	// Empty pattern returns nil.
	assert.Nil(t, NewSimpleBytePatternMatcher(nil).FindMatch(data, 0, len(data)))
	// startIndex out of range returns nil.
	assert.Nil(t, m.FindMatch(data, 100, 200))
}

func TestHtmlDecodingBytePatternMatcher(t *testing.T) {
	// "&lt;" decodes to "<"; the pattern "<" should match the encoded entity.
	data := []byte("prefix &lt; suffix")
	m := NewHtmlDecodingBytePatternMatcher([]byte("<"))
	pos := m.FindMatch(data, 0, len(data))
	require.NotNil(t, pos)
}

func TestPatternMatcherConstructorVariants(t *testing.T) {
	// All constructors return a usable matcher.
	for _, m := range []*ConfigurableBytePatternMatcher{
		NewSimpleBytePatternMatcher([]byte("x")),
		NewHtmlDecodingBytePatternMatcher([]byte("x")),
		NewUnescapingHtmlDecodingBytePatternMatcher([]byte("x")),
		NewUnescapingBytePatternMatcher([]byte("x")),
		NewConfigurableBytePatternMatcher([]byte("x"), true, true),
	} {
		require.NotNil(t, m)
		assert.NotNil(t, m.FindMatch([]byte("xyz"), 0, 3))
	}
}

// ── model_pattern_match_state.go ─────────────────────────────────────────────

func TestPatternMatchState(t *testing.T) {
	s := NewPatternMatchState(5, byte('q'), nil)
	require.NotNil(t, s)
	assert.Equal(t, 5, s.CurrentIndex())
	assert.Equal(t, byte('q'), s.CurrentChar())
	assert.Equal(t, 5, GetStateIndex(s))
	assert.Equal(t, byte('q'), GetStateChar(s))

	// Nil-safe accessors.
	assert.Equal(t, 0, GetStateIndex(nil))
	assert.Equal(t, byte(0), GetStateChar(nil))
}

// ── util_payload_transformer.go ──────────────────────────────────────────────

func TestPayloadModificationContext(t *testing.T) {
	rng := utils.NewRandomGeneratorWithFixedSeed(1)

	ctx := NewPayloadModificationContext([]byte("MAIN"), rng)
	require.NotNil(t, ctx)
	assert.False(t, ctx.HasPrefix())
	assert.Equal(t, []byte("MAIN"), ctx.GetPrefixedPrimaryData())

	withPrefix := NewPayloadModificationContextWithPrefix([]byte("PRE"), []byte("MAIN"), rng)
	assert.True(t, withPrefix.HasPrefix())
	assert.Equal(t, []byte("PREMAIN"), withPrefix.GetPrefixedPrimaryData())

	// Nil random provider is tolerated.
	noRng := NewPayloadModificationContext([]byte("X"), nil)
	require.NotNil(t, noRng)
}

func TestPrefixingPayloadModifier(t *testing.T) {
	rng := utils.NewRandomGeneratorWithFixedSeed(2)
	ctx := NewPayloadModificationContextWithPrefix([]byte("PRE"), []byte("MAIN"), rng)

	mod := NewPrefixingPayloadModifier(ctx)
	assert.Equal(t, []byte("PREMAINpay"), mod.Modify([]byte("pay")))

	// Nil context returns input unchanged.
	nilMod := NewPrefixingPayloadModifier(nil)
	assert.Equal(t, []byte("pay"), nilMod.Modify([]byte("pay")))
}

func TestNoOpPayloadModifier(t *testing.T) {
	mod := NewNoOpPayloadModifier()
	assert.Equal(t, []byte("unchanged"), mod.Modify([]byte("unchanged")))
}

func TestContextualPrefixPayloadTransformer(t *testing.T) {
	rng := utils.NewRandomGeneratorWithFixedSeed(3)
	ctx := NewPayloadModificationContextWithPrefix([]byte("P"), []byte("M"), rng)

	tr := NewContextualPrefixPayloadTransformer(ctx)
	assert.Equal(t, []byte("PMpayload"), tr.Modify([]byte("payload")))

	nilTr := NewContextualPrefixPayloadTransformer(nil)
	assert.Equal(t, []byte("payload"), nilTr.Modify([]byte("payload")))
}

// ── util_random_html_tag_generator.go ────────────────────────────────────────

func TestRandomHTMLTagGenerator(t *testing.T) {
	gen := NewRandomHTMLTagGenerator(utils.NewRandomGeneratorWithFixedSeed(42))
	require.NotNil(t, gen)
	gen.IsRandomTextProvider() // marker, no-op

	for i := 0; i < 25; i++ {
		tag := gen.GenerateText(6)
		assert.NotEmpty(t, tag)
		assert.False(t, gen.isStandardTag(tag), "generated tag %q must not be a standard HTML tag", tag)
	}

	// Nil provider chain falls back to a default tag name.
	nilGen := NewRandomHTMLTagGenerator(nil)
	assert.Equal(t, "defaulttag", nilGen.GenerateText(6))
}

// ── util_event_handler_validator.go ──────────────────────────────────────────

func TestCaseInsensitiveStringSetChecker(t *testing.T) {
	checker := NewCaseInsensitiveStringSetChecker(map[string]struct{}{"Img": {}, "Body": {}})
	assert.True(t, checker.Contains("img"))
	assert.True(t, checker.Contains("BODY"))
	assert.False(t, checker.Contains("div"))

	filtered := checker.FilterContainedItems(map[string]struct{}{"img": {}, "div": {}, "body": {}})
	assert.Len(t, filtered, 2)
	_, hasImg := filtered["img"]
	assert.True(t, hasImg)
	_, hasDiv := filtered["div"]
	assert.False(t, hasDiv)
}

func TestExclusionTagAttributeValidator(t *testing.T) {
	v := NewExclusionTagAttributeValidator("script", "style")
	assert.False(t, v.IsValidForTag("script"))
	assert.False(t, v.IsValidForTag("SCRIPT"))
	assert.True(t, v.IsValidForTag("div"))

	// Set has at least one non-excluded tag -> valid.
	assert.True(t, v.IsValidForAnyTagInSet(map[string]struct{}{"script": {}, "div": {}}))
	// Every tag excluded -> invalid.
	assert.False(t, v.IsValidForAnyTagInSet(map[string]struct{}{"script": {}, "style": {}}))
}

func TestInclusionTagAttributeValidator(t *testing.T) {
	v := NewInclusionTagAttributeValidator("input")
	assert.True(t, v.IsValidForTag("input"))
	assert.True(t, v.IsValidForTag("INPUT"))
	assert.False(t, v.IsValidForTag("div"))

	assert.True(t, v.IsValidForAnyTagInSet(map[string]struct{}{"input": {}, "div": {}}))
	assert.False(t, v.IsValidForAnyTagInSet(map[string]struct{}{"span": {}, "div": {}}))
}

func TestTagSpecificAssessorRegistry(t *testing.T) {
	reg := NewTagSpecificAssessorRegistry()
	assert.Nil(t, reg.GetCheckerForTag("onfocus"))

	checker := NewFocusEventHiddenInputAssessor()
	reg.RegisterCheckerForTag("onfocus", checker)
	assert.NotNil(t, reg.GetCheckerForTag("ONFOCUS")) // case-insensitive lookup
}

// fakeTagAccessor is a minimal HTMLTagInfoAccessor for compatibility-assessor tests.
type fakeTagAccessor struct {
	tag   string
	attrs map[string]string
}

func (f *fakeTagAccessor) IsHTMLTagInfoAccessor()                  {}
func (f *fakeTagAccessor) TagName() string                         { return f.tag }
func (f *fakeTagAccessor) Attributes() []*htmlparser.HTMLAttribute { return nil }
func (f *fakeTagAccessor) GetAttributeValue(name string) string    { return f.attrs[name] }

func TestFocusEventHiddenInputAssessor(t *testing.T) {
	a := NewFocusEventHiddenInputAssessor()
	// hidden input is NOT compatible with focus events.
	assert.False(t, a.IsCompatible(&fakeTagAccessor{tag: "input", attrs: map[string]string{"type": "hidden"}}))
	// visible input is compatible.
	assert.True(t, a.IsCompatible(&fakeTagAccessor{tag: "input", attrs: map[string]string{"type": "text"}}))
	// nil accessor -> compatible (defensive default).
	assert.True(t, a.IsCompatible(nil))
}

func TestMouseOverEventHiddenInputAssessor(t *testing.T) {
	a := NewMouseOverEventHiddenInputAssessor()
	assert.False(t, a.IsCompatible(&fakeTagAccessor{tag: "input", attrs: map[string]string{"type": "hidden"}}))
	assert.True(t, a.IsCompatible(&fakeTagAccessor{tag: "div"}))
	assert.True(t, a.IsCompatible(nil))
}

func TestEventHandlerEligibilityLogic(t *testing.T) {
	logic := NewEventHandlerEligibilityLogic()
	require.NotNil(t, logic)

	// onfocus requires an <input> tag.
	assert.True(t, logic.AreTagsEligibleForEvent(map[string]struct{}{"input": {}}, "onfocus"))
	assert.False(t, logic.AreTagsEligibleForEvent(map[string]struct{}{"div": {}}, "onfocus"))
	// Unknown event -> not eligible.
	assert.False(t, logic.AreTagsEligibleForEvent(map[string]struct{}{"input": {}}, "nosuchevent"))

	// onfocus on a visible input is eligible.
	visibleInput := &fakeTagAccessor{tag: "input", attrs: map[string]string{"type": "text"}}
	assert.True(t, logic.IsTagEligibleForEvent("input", visibleInput, "onfocus"))
	// onfocus on a hidden input is not (compatibility assessor rejects).
	hiddenInput := &fakeTagAccessor{tag: "input", attrs: map[string]string{"type": "hidden"}}
	assert.False(t, logic.IsTagEligibleForEvent("input", hiddenInput, "onfocus"))
	// Empty tag name -> false.
	assert.False(t, logic.IsTagEligibleForEvent("", visibleInput, "onfocus"))
	// Unknown event -> false.
	assert.False(t, logic.IsTagEligibleForEvent("input", visibleInput, "nosuchevent"))
	// Event with a validator but no registered compatibility assessor (onerror) -> false.
	assert.False(t, logic.IsTagEligibleForEvent("img", &fakeTagAccessor{tag: "img"}, "onerror"))
}
