package xss_light_scanner

import (
	"testing"
)

func TestTransformType_IsExploitable(t *testing.T) {
	tests := []struct {
		name      string
		transform TransformType
		expected  bool
	}{
		{"Passed", TransformPassed, true},
		{"DoubleBackslash", TransformDoubleBackslash, true},
		{"BackslashEsc", TransformBackslashEsc, false},
		{"TripleBackslash", TransformTripleBackslash, false},
		{"HTMLEncoded", TransformHTMLEncoded, false},
		{"URLEncoded", TransformURLEncoded, false},
		{"Removed", TransformRemoved, false},
		{"Unknown", TransformUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.transform.IsExploitable(); got != tt.expected {
				t.Errorf("TransformType.IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_HasUnescaped(t *testing.T) {
	ea := NewEscapeAnalysis(HTMLGeneric, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformPassed})
	ea.SetTransform("\"", &CharTransform{InputChar: '"', Transform: TransformBackslashEsc})
	ea.SetTransform("<", &CharTransform{InputChar: '<', Transform: TransformHTMLEncoded})

	tests := []struct {
		char     byte
		expected bool
	}{
		{'\'', true}, // Passed
		{'"', false}, // BackslashEsc
		{'<', false}, // HTMLEncoded
		{'>', false}, // Not set
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			if got := ea.HasUnescaped(tt.char); got != tt.expected {
				t.Errorf("HasUnescaped('%c') = %v, want %v", tt.char, got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_HasBackslashEscaped(t *testing.T) {
	ea := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformBackslashEsc})
	ea.SetTransform("\"", &CharTransform{InputChar: '"', Transform: TransformPassed})

	if !ea.HasBackslashEscaped('\'') {
		t.Error("HasBackslashEscaped('\\'') should be true")
	}
	if ea.HasBackslashEscaped('"') {
		t.Error("HasBackslashEscaped('\"') should be false (was passed, not escaped)")
	}
	if ea.HasBackslashEscaped('`') {
		t.Error("HasBackslashEscaped('`') should be false (not set)")
	}
}

func TestEscapeAnalysis_HasDoubleBackslash(t *testing.T) {
	ea := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea.SetTransform("\\'", &CharTransform{InputSeq: "\\'", Transform: TransformDoubleBackslash})
	ea.SetTransform("\\\"", &CharTransform{InputSeq: "\\\"", Transform: TransformTripleBackslash})

	if !ea.HasDoubleBackslash("\\'") {
		t.Error("HasDoubleBackslash(\"\\\\'\") should be true")
	}
	if ea.HasDoubleBackslash("\\\"") {
		t.Error("HasDoubleBackslash(\"\\\\\"\") should be false (was triple)")
	}
	if ea.HasDoubleBackslash("\\`") {
		t.Error("HasDoubleBackslash(\"\\\\`\") should be false (not set)")
	}
}

// ============================================================================
// EscapeAnalysis.IsExploitable() Tests - Event Handlers
// ============================================================================

func TestEscapeAnalysis_IsExploitable_EventHandlers(t *testing.T) {
	tests := []struct {
		ctx        ReflectionContext
		quoteChar  byte
		transforms map[string]*CharTransform
		expected   bool
		name       string
	}{
		// Unescaped quote - exploitable
		{JSInEventHandlerDQ, '"', map[string]*CharTransform{"\"": {Transform: TransformPassed}}, true, "DQ_QuotePassed"},
		{JSInEventHandlerSQ, '\'', map[string]*CharTransform{"'": {Transform: TransformPassed}}, true, "SQ_QuotePassed"},
		{JSInEventHandlerBT, '`', map[string]*CharTransform{"`": {Transform: TransformPassed}}, true, "BT_QuotePassed"},

		// HTML-encoded quote - also exploitable (browser decodes HTML entities before JS execution)
		{JSInEventHandlerDQ, '"', map[string]*CharTransform{"\"": {Transform: TransformHTMLEncoded}}, true, "DQ_QuoteHTMLEncoded"},
		{JSInEventHandlerSQ, '\'', map[string]*CharTransform{"'": {Transform: TransformHTMLEncoded}}, true, "SQ_QuoteHTMLEncoded"},
		{JSInEventHandlerBT, '`', map[string]*CharTransform{"`": {Transform: TransformHTMLEncoded}}, true, "BT_QuoteHTMLEncoded"},

		// Backslash escaped quote - not directly exploitable (needs Phase 2 double-escape test)
		{JSInEventHandlerDQ, '"', map[string]*CharTransform{"\"": {Transform: TransformBackslashEsc}}, false, "DQ_QuoteBackslashEsc"},
		{JSInEventHandlerSQ, '\'', map[string]*CharTransform{"'": {Transform: TransformBackslashEsc}}, false, "SQ_QuoteBackslashEsc"},
		{JSInEventHandlerBT, '`', map[string]*CharTransform{"`": {Transform: TransformBackslashEsc}}, false, "BT_QuoteBackslashEsc"},

		// Unquoted - space or > pass means exploitable
		{JSInEventHandlerUnquoted, ' ', map[string]*CharTransform{" ": {Transform: TransformPassed}}, true, "Unquoted_SpacePassed"},
		{JSInEventHandlerUnquoted, '>', map[string]*CharTransform{">": {Transform: TransformPassed}}, true, "Unquoted_GTPassed"},
		{JSInEventHandlerUnquoted, ' ', map[string]*CharTransform{" ": {Transform: TransformRemoved}, ">": {Transform: TransformRemoved}}, false, "Unquoted_BothRemoved"},

		// Script breakout - any event handler is exploitable if </script> chars pass
		{JSInEventHandlerDQ, '"', map[string]*CharTransform{"<": {Transform: TransformPassed}, "/": {Transform: TransformPassed}, ">": {Transform: TransformPassed}}, true, "DQ_ScriptBreakout"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(tc.ctx, 0)
			for k, v := range tc.transforms {
				ea.SetTransform(k, v)
			}
			if ea.IsExploitable() != tc.expected {
				t.Errorf("Event handler context %s: IsExploitable() = %v, want %v", tc.ctx, ea.IsExploitable(), tc.expected)
			}
		})
	}
}

// ============================================================================
// EscapeAnalysis.IsExploitable() Tests - JS Code Statement (Always Exploitable)
// ============================================================================

func TestEscapeAnalysis_IsExploitable_JSCodeStatement(t *testing.T) {
	ea := NewEscapeAnalysis(JSCodeStatement, 0)
	if !ea.IsExploitable() {
		t.Error("JSCodeStatement should always be exploitable")
	}
}

// ============================================================================
// EscapeAnalysis.IsExploitable() Tests - JS String Contexts
// ============================================================================

func TestEscapeAnalysis_IsExploitable_JSStringSQ(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"QuoteAndTerminatorPassed",
			map[string]*CharTransform{
				"'": {Transform: TransformPassed},
				";": {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuotePassedNewlinePassed",
			map[string]*CharTransform{
				"'":  {Transform: TransformPassed},
				"\n": {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuoteEscaped_NoDoubleBackslash",
			map[string]*CharTransform{
				"'": {Transform: TransformBackslashEsc},
				";": {Transform: TransformPassed},
			},
			false,
		},
		{
			"QuoteEscaped_DoubleBackslash",
			map[string]*CharTransform{
				"'":   {Transform: TransformBackslashEsc},
				"\\'": {Transform: TransformDoubleBackslash},
				";":   {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuoteEscaped_TripleBackslash",
			map[string]*CharTransform{
				"'":   {Transform: TransformBackslashEsc},
				"\\'": {Transform: TransformTripleBackslash},
				";":   {Transform: TransformPassed},
			},
			false,
		},
		{
			"QuotePassed_NoTerminator",
			map[string]*CharTransform{
				"'": {Transform: TransformPassed},
			},
			true, // Quote breakout is sufficient - no terminator needed
		},
		{
			"QuoteHTMLEncoded",
			map[string]*CharTransform{
				"'": {Transform: TransformHTMLEncoded},
				";": {Transform: TransformPassed},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(JSStringSQBreakout, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_JSStringDQ(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"QuoteAndTerminatorPassed",
			map[string]*CharTransform{
				"\"": {Transform: TransformPassed},
				";":  {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuoteEscaped_DoubleBackslash",
			map[string]*CharTransform{
				"\"":   {Transform: TransformBackslashEsc},
				"\\\"": {Transform: TransformDoubleBackslash},
				";":    {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuoteHTMLEncoded",
			map[string]*CharTransform{
				"\"": {Transform: TransformHTMLEncoded},
				";":  {Transform: TransformPassed},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(JSStringDQBreakout, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_JSTemplateLiteral(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"BacktickPassed",
			map[string]*CharTransform{
				"`": {Transform: TransformPassed},
			},
			true,
		},
		{
			"BacktickEscaped_DoubleBackslash",
			map[string]*CharTransform{
				"`":   {Transform: TransformBackslashEsc},
				"\\`": {Transform: TransformDoubleBackslash},
			},
			true,
		},
		{
			"TemplateInjection_AllPassed",
			map[string]*CharTransform{
				"$": {Transform: TransformPassed},
				"{": {Transform: TransformPassed},
				"}": {Transform: TransformPassed},
			},
			true,
		},
		{
			"TemplateInjection_DollarRemoved",
			map[string]*CharTransform{
				"$": {Transform: TransformRemoved},
				"{": {Transform: TransformPassed},
				"}": {Transform: TransformPassed},
			},
			false,
		},
		{
			"BacktickEscaped_NoDoubleBackslash",
			map[string]*CharTransform{
				"`": {Transform: TransformBackslashEsc},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(JSTemplateLiteral, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ============================================================================
// EscapeAnalysis.IsExploitable() Tests - HTML Contexts
// ============================================================================

func TestEscapeAnalysis_IsExploitable_HTMLGeneric(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"BothAngleBracketsPassed",
			map[string]*CharTransform{
				"<": {Transform: TransformPassed},
				">": {Transform: TransformPassed},
			},
			true,
		},
		{
			"LTEncoded",
			map[string]*CharTransform{
				"<": {Transform: TransformHTMLEncoded},
				">": {Transform: TransformPassed},
			},
			false,
		},
		{
			"GTEncoded",
			map[string]*CharTransform{
				"<": {Transform: TransformPassed},
				">": {Transform: TransformHTMLEncoded},
			},
			false,
		},
		{
			"BothRemoved",
			map[string]*CharTransform{
				"<": {Transform: TransformRemoved},
				">": {Transform: TransformRemoved},
			},
			false,
		},
	}

	contexts := []ReflectionContext{
		HTMLGeneric,
		HTMLTagCloseAndInject,
		HTMLAfterXMPClose,
		HTMLAfterNoscriptClose,
		HTMLAfterTitleClose,
		XMLGeneric,
	}

	for _, ctx := range contexts {
		for _, tt := range tests {
			t.Run(ctx.String()+"_"+tt.name, func(t *testing.T) {
				ea := NewEscapeAnalysis(ctx, 0)
				for k, v := range tt.transforms {
					ea.SetTransform(k, v)
				}
				if got := ea.IsExploitable(); got != tt.expected {
					t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
				}
			})
		}
	}
}

func TestEscapeAnalysis_IsExploitable_HTMLAttributeValueDQ(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"QuotePassed",
			map[string]*CharTransform{
				"\"": {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuoteHTMLEncoded",
			map[string]*CharTransform{
				"\"": {Transform: TransformHTMLEncoded},
			},
			false,
		},
		{
			"QuoteRemoved",
			map[string]*CharTransform{
				"\"": {Transform: TransformRemoved},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(HTMLAttributeValueDQBreakout, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_HTMLAttributeValueSQ(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"QuotePassed",
			map[string]*CharTransform{
				"'": {Transform: TransformPassed},
			},
			true,
		},
		{
			"QuoteHTMLEncoded",
			map[string]*CharTransform{
				"'": {Transform: TransformHTMLEncoded},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(HTMLAttributeValueSQBreakout, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_HTMLAttributeValueBT(t *testing.T) {
	ea := NewEscapeAnalysis(HTMLAttributeValueBTBreakout, 0)
	ea.SetTransform("`", &CharTransform{Transform: TransformPassed})

	if !ea.IsExploitable() {
		t.Error("Backtick passed should be exploitable")
	}

	ea2 := NewEscapeAnalysis(HTMLAttributeValueBTBreakout, 0)
	ea2.SetTransform("`", &CharTransform{Transform: TransformHTMLEncoded})

	if ea2.IsExploitable() {
		t.Error("Backtick encoded should not be exploitable")
	}
}

func TestEscapeAnalysis_IsExploitable_HTMLAttributeValueUnquoted(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"SpacePassed",
			map[string]*CharTransform{
				" ": {Transform: TransformPassed},
			},
			true,
		},
		{
			"GTPassed",
			map[string]*CharTransform{
				">": {Transform: TransformPassed},
			},
			true,
		},
		{
			"BothRemoved",
			map[string]*CharTransform{
				" ": {Transform: TransformRemoved},
				">": {Transform: TransformRemoved},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(HTMLAttributeValueUnquotedBreakout, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_HTMLAttributeName(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"EqualAndSpacePassed",
			map[string]*CharTransform{
				"=": {Transform: TransformPassed},
				" ": {Transform: TransformPassed},
			},
			true,
		},
		{
			"EqualAndGTPassed",
			map[string]*CharTransform{
				"=": {Transform: TransformPassed},
				">": {Transform: TransformPassed},
			},
			true,
		},
		{
			"EqualPassed_SpaceAndGTRemoved",
			map[string]*CharTransform{
				"=": {Transform: TransformPassed},
				" ": {Transform: TransformRemoved},
				">": {Transform: TransformRemoved},
			},
			false,
		},
		{
			"EqualRemoved",
			map[string]*CharTransform{
				"=": {Transform: TransformRemoved},
				" ": {Transform: TransformPassed},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(HTMLAttributeName, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ============================================================================
// EscapeAnalysis.IsExploitable() Tests - Comment Contexts
// ============================================================================

func TestEscapeAnalysis_IsExploitable_HTMLComment(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"GTAndDashPassed",
			map[string]*CharTransform{
				">": {Transform: TransformPassed},
				"-": {Transform: TransformPassed},
			},
			true,
		},
		{
			"GTOnly",
			map[string]*CharTransform{
				">": {Transform: TransformPassed},
			},
			false,
		},
		{
			"DashOnly",
			map[string]*CharTransform{
				"-": {Transform: TransformPassed},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(HTMLCommentBreakout, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_JSLineComment(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"NewlinePassed",
			map[string]*CharTransform{
				"\n": {Transform: TransformPassed},
			},
			true,
		},
		{
			"CarriageReturnPassed",
			map[string]*CharTransform{
				"\r": {Transform: TransformPassed},
			},
			true,
		},
		{
			"BothRemoved",
			map[string]*CharTransform{
				"\n": {Transform: TransformRemoved},
				"\r": {Transform: TransformRemoved},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(JSLineComment, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeAnalysis_IsExploitable_JSBlockComment(t *testing.T) {
	tests := []struct {
		name       string
		transforms map[string]*CharTransform
		expected   bool
	}{
		{
			"AsteriskAndSlashPassed",
			map[string]*CharTransform{
				"*": {Transform: TransformPassed},
				"/": {Transform: TransformPassed},
			},
			true,
		},
		{
			"AsteriskOnly",
			map[string]*CharTransform{
				"*": {Transform: TransformPassed},
			},
			false,
		},
		{
			"SlashOnly",
			map[string]*CharTransform{
				"/": {Transform: TransformPassed},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := NewEscapeAnalysis(JSBlockComment, 0)
			for k, v := range tt.transforms {
				ea.SetTransform(k, v)
			}
			if got := ea.IsExploitable(); got != tt.expected {
				t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ============================================================================
// EscapeAnalysis.IsExploitable() Tests - URL Attribute Contexts
// ============================================================================

func TestEscapeAnalysis_IsExploitable_URLAttributes(t *testing.T) {
	t.Run("AtURLStart_AlwaysExploitable", func(t *testing.T) {
		// When reflection is at URL start, always exploitable (can inject javascript:)
		contexts := []ReflectionContext{
			JSInURLAttributeDQ,
			JSInURLAttributeSQ,
			JSInURLAttributeBT,
			JSInUnquotedURLAttribute,
		}

		for _, ctx := range contexts {
			t.Run(ctx.String(), func(t *testing.T) {
				ea := NewEscapeAnalysis(ctx, 0)
				ea.IsAtURLStart = true

				if !ea.IsExploitable() {
					t.Errorf("URL attribute at start should be exploitable")
				}
			})
		}
	})

	t.Run("NotAtURLStart_NeedsQuoteBreakout", func(t *testing.T) {
		tests := []struct {
			name       string
			context    ReflectionContext
			transforms map[string]*CharTransform
			expected   bool
		}{
			// Double quote URL attribute
			{
				"JSInURLAttributeDQ_QuotePassed",
				JSInURLAttributeDQ,
				map[string]*CharTransform{"\"": {Transform: TransformPassed}},
				true,
			},
			{
				"JSInURLAttributeDQ_QuoteEncoded",
				JSInURLAttributeDQ,
				map[string]*CharTransform{"\"": {Transform: TransformHTMLEncoded}},
				false,
			},

			// Single quote URL attribute
			{
				"JSInURLAttributeSQ_QuotePassed",
				JSInURLAttributeSQ,
				map[string]*CharTransform{"'": {Transform: TransformPassed}},
				true,
			},
			{
				"JSInURLAttributeSQ_QuoteEncoded",
				JSInURLAttributeSQ,
				map[string]*CharTransform{"'": {Transform: TransformHTMLEncoded}},
				false,
			},

			// Backtick URL attribute
			{
				"JSInURLAttributeBT_BacktickPassed",
				JSInURLAttributeBT,
				map[string]*CharTransform{"`": {Transform: TransformPassed}},
				true,
			},
			{
				"JSInURLAttributeBT_BacktickEncoded",
				JSInURLAttributeBT,
				map[string]*CharTransform{"`": {Transform: TransformHTMLEncoded}},
				false,
			},

			// Unquoted URL attribute
			{
				"JSInUnquotedURLAttribute_SpacePassed",
				JSInUnquotedURLAttribute,
				map[string]*CharTransform{" ": {Transform: TransformPassed}},
				true,
			},
			{
				"JSInUnquotedURLAttribute_GTPassed",
				JSInUnquotedURLAttribute,
				map[string]*CharTransform{">": {Transform: TransformPassed}},
				true,
			},
			{
				"JSInUnquotedURLAttribute_BothRemoved",
				JSInUnquotedURLAttribute,
				map[string]*CharTransform{" ": {Transform: TransformRemoved}, ">": {Transform: TransformRemoved}},
				false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ea := NewEscapeAnalysis(tt.context, 0)
				ea.IsAtURLStart = false // Not at URL start
				for k, v := range tt.transforms {
					ea.SetTransform(k, v)
				}
				if got := ea.IsExploitable(); got != tt.expected {
					t.Errorf("IsExploitable() = %v, want %v", got, tt.expected)
				}
			})
		}
	})
}

// ============================================================================
// EscapeAnalysis Helper Method Tests
// ============================================================================

func TestEscapeAnalysis_GetTransform(t *testing.T) {
	ea := NewEscapeAnalysis(HTMLGeneric, 100)
	ea.SetTransform("'", &CharTransform{InputSeq: "'", Transform: TransformPassed})
	ea.SetTransform("\\'", &CharTransform{InputSeq: "\\'", Transform: TransformDoubleBackslash})

	// Test existing transforms
	if ct := ea.GetTransform("'"); ct == nil || ct.Transform != TransformPassed {
		t.Error("GetTransform(\"'\") should return TransformPassed")
	}
	if ct := ea.GetTransform("\\'"); ct == nil || ct.Transform != TransformDoubleBackslash {
		t.Error("GetTransform(\"\\\\'\") should return TransformDoubleBackslash")
	}

	// Test non-existing transform
	if ct := ea.GetTransform("\""); ct != nil {
		t.Error("GetTransform('\"') should return nil")
	}
}

func TestEscapeAnalysis_GetCharTransform(t *testing.T) {
	ea := NewEscapeAnalysis(HTMLGeneric, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformPassed})

	if ct := ea.GetCharTransform('\''); ct == nil || ct.Transform != TransformPassed {
		t.Error("GetCharTransform('\\'') should return TransformPassed")
	}
	if ct := ea.GetCharTransform('"'); ct != nil {
		t.Error("GetCharTransform('\"') should return nil")
	}
}

func TestNewEscapeAnalysis(t *testing.T) {
	ea := NewEscapeAnalysis(JSStringSQBreakout, 150)

	if ea.Context != JSStringSQBreakout {
		t.Errorf("Context = %v, want JSStringSQBreakout", ea.Context)
	}
	if ea.Offset != 150 {
		t.Errorf("Offset = %d, want 150", ea.Offset)
	}
	if ea.Transforms == nil {
		t.Error("Transforms should not be nil")
	}
	if len(ea.Transforms) != 0 {
		t.Errorf("Transforms should be empty, got %d", len(ea.Transforms))
	}
}
