package xss_light_scanner

import (
	"testing"
)

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		name     string
		r        RiskLevel
		expected string
	}{
		{"medium", RiskMedium, "medium"},
		{"high", RiskHigh, "high"},
		{"critical", RiskCritical, "critical"},
		{"invalid", RiskLevel(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.String(); got != tt.expected {
				t.Errorf("RiskLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestReflectionContext_GetInfo(t *testing.T) {
	tests := []struct {
		name            string
		ctx             ReflectionContext
		expectedID      int
		expectedDisplay string
		expectedRisk    RiskLevel
	}{
		{"HTMLGeneric", HTMLGeneric, 0, "HTML Body", RiskHigh},
		{"HTMLTagCloseAndInject", HTMLTagCloseAndInject, 2, "HTML Tag Name", RiskHigh},
		{"HTMLAttributeName", HTMLAttributeName, 3, "HTML Attribute Name", RiskHigh},
		{"HTMLAttributeValueDQBreakout", HTMLAttributeValueDQBreakout, 4, "HTML Attribute Value (Double Quote)", RiskHigh},
		{"HTMLAttributeValueSQBreakout", HTMLAttributeValueSQBreakout, 5, "HTML Attribute Value (Single Quote)", RiskHigh},
		{"HTMLAttributeValueBTBreakout", HTMLAttributeValueBTBreakout, 6, "HTML Attribute Value (Backtick)", RiskHigh},
		{"HTMLAttributeValueUnquotedBreakout", HTMLAttributeValueUnquotedBreakout, 7, "HTML Attribute Value (Unquoted)", RiskHigh},
		{"JSInURLAttributeDQ", JSInURLAttributeDQ, 8, "JavaScript in URL Attribute (Double Quote)", RiskHigh},
		{"JSInURLAttributeSQ", JSInURLAttributeSQ, 9, "JavaScript in URL Attribute (Single Quote)", RiskHigh},
		{"JSInURLAttributeBT", JSInURLAttributeBT, 10, "JavaScript in URL Attribute (Backtick)", RiskHigh},
		{"JSInUnquotedURLAttribute", JSInUnquotedURLAttribute, 11, "JavaScript in URL Attribute (Unquoted)", RiskHigh},
		{"JSInEventHandlerDQ", JSInEventHandlerDQ, 12, "JavaScript in Event Handler (Double Quote)", RiskHigh},
		{"JSInEventHandlerSQ", JSInEventHandlerSQ, 13, "JavaScript in Event Handler (Single Quote)", RiskHigh},
		{"JSInEventHandlerBT", JSInEventHandlerBT, 14, "JavaScript in Event Handler (Backtick)", RiskHigh},
		{"JSInEventHandlerUnquoted", JSInEventHandlerUnquoted, 15, "JavaScript in Event Handler (Unquoted)", RiskHigh},
		{"JSStringDQBreakout", JSStringDQBreakout, 16, "JavaScript String (Double Quote)", RiskHigh},
		{"JSStringSQBreakout", JSStringSQBreakout, 17, "JavaScript String (Single Quote)", RiskHigh},
		{"JSCodeStatement", JSCodeStatement, 18, "JavaScript Code", RiskCritical},
		{"XMLGeneric", XMLGeneric, 19, "XML Body", RiskMedium},
		{"HTMLAfterXMPClose", HTMLAfterXMPClose, 20, "HTML After </xmp> Close", RiskHigh},
		{"HTMLAfterNoscriptClose", HTMLAfterNoscriptClose, 21, "HTML After </noscript> Close", RiskHigh},
		{"HTMLAfterTitleClose", HTMLAfterTitleClose, 22, "HTML After </title> Close", RiskHigh},
		{"HTMLCommentBreakout", HTMLCommentBreakout, 23, "HTML Comment", RiskMedium},
		{"JSLineComment", JSLineComment, 24, "JavaScript Line Comment", RiskMedium},
		{"JSBlockComment", JSBlockComment, 25, "JavaScript Block Comment", RiskMedium},
		{"JSTemplateLiteral", JSTemplateLiteral, 26, "JavaScript Template Literal", RiskHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.ctx.GetInfo()
			if info.ID != tt.expectedID {
				t.Errorf("GetInfo().ID = %v, want %v", info.ID, tt.expectedID)
			}
			if info.DisplayName != tt.expectedDisplay {
				t.Errorf("GetInfo().DisplayName = %v, want %v", info.DisplayName, tt.expectedDisplay)
			}
			if info.RiskLevel != tt.expectedRisk {
				t.Errorf("GetInfo().RiskLevel = %v, want %v", info.RiskLevel, tt.expectedRisk)
			}
		})
	}
}

func TestReflectionContext_GetInfo_Unknown(t *testing.T) {
	ctx := ReflectionContext(999)
	info := ctx.GetInfo()

	if info.ID != -1 {
		t.Errorf("Unknown context ID = %v, want -1", info.ID)
	}
	if info.DisplayName != "Unknown" {
		t.Errorf("Unknown context DisplayName = %v, want Unknown", info.DisplayName)
	}
}

func TestReflectionContext_String(t *testing.T) {
	tests := []struct {
		ctx      ReflectionContext
		expected string
	}{
		{HTMLGeneric, "HTML Body"},
		{JSCodeStatement, "JavaScript Code"},
		{HTMLCommentBreakout, "HTML Comment"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.ctx.String(); got != tt.expected {
				t.Errorf("ReflectionContext.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFromID(t *testing.T) {
	tests := []struct {
		id       int
		expected ReflectionContext
	}{
		{0, HTMLGeneric},
		{2, HTMLTagCloseAndInject},
		{3, HTMLAttributeName},
		{4, HTMLAttributeValueDQBreakout},
		{5, HTMLAttributeValueSQBreakout},
		{6, HTMLAttributeValueBTBreakout},
		{7, HTMLAttributeValueUnquotedBreakout},
		{8, JSInURLAttributeDQ},
		{9, JSInURLAttributeSQ},
		{10, JSInURLAttributeBT},
		{11, JSInUnquotedURLAttribute},
		{12, JSInEventHandlerDQ},
		{13, JSInEventHandlerSQ},
		{14, JSInEventHandlerBT},
		{15, JSInEventHandlerUnquoted},
		{16, JSStringDQBreakout},
		{17, JSStringSQBreakout},
		{18, JSCodeStatement},
		{19, XMLGeneric},
		{20, HTMLAfterXMPClose},
		{21, HTMLAfterNoscriptClose},
		{22, HTMLAfterTitleClose},
		{23, HTMLCommentBreakout},
		{24, JSLineComment},
		{25, JSBlockComment},
		{26, JSTemplateLiteral},
	}

	for _, tt := range tests {
		t.Run(tt.expected.String(), func(t *testing.T) {
			if got := FromID(tt.id); got != tt.expected {
				t.Errorf("FromID(%d) = %v, want %v", tt.id, got, tt.expected)
			}
		})
	}
}

func TestFromID_Invalid(t *testing.T) {
	invalidIDs := []int{-1, 1, 999, 100}

	for _, id := range invalidIDs {
		t.Run("invalid_id", func(t *testing.T) {
			if got := FromID(id); got != HTMLGeneric {
				t.Errorf("FromID(%d) = %v, want HTMLGeneric", id, got)
			}
		})
	}
}

// Test all 26 contexts have valid info
func TestAllContextsHaveValidInfo(t *testing.T) {
	contexts := []ReflectionContext{
		HTMLGeneric,
		HTMLTagCloseAndInject,
		HTMLAttributeName,
		HTMLAttributeValueDQBreakout,
		HTMLAttributeValueSQBreakout,
		HTMLAttributeValueBTBreakout,
		HTMLAttributeValueUnquotedBreakout,
		JSInURLAttributeDQ,
		JSInURLAttributeSQ,
		JSInURLAttributeBT,
		JSInUnquotedURLAttribute,
		JSInEventHandlerDQ,
		JSInEventHandlerSQ,
		JSInEventHandlerBT,
		JSInEventHandlerUnquoted,
		JSStringDQBreakout,
		JSStringSQBreakout,
		JSCodeStatement,
		XMLGeneric,
		HTMLAfterXMPClose,
		HTMLAfterNoscriptClose,
		HTMLAfterTitleClose,
		HTMLCommentBreakout,
		JSLineComment,
		JSBlockComment,
		JSTemplateLiteral,
	}

	for _, ctx := range contexts {
		t.Run(ctx.String(), func(t *testing.T) {
			info := ctx.GetInfo()

			if info.ID < 0 {
				t.Errorf("Context %v has invalid ID %d", ctx, info.ID)
			}
			if info.DisplayName == "" || info.DisplayName == "Unknown" {
				t.Errorf("Context %v has invalid DisplayName", ctx)
			}
			if info.Description == "" {
				t.Errorf("Context %v has empty Description", ctx)
			}
		})
	}
}
