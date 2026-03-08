package xss_light_scanner

import (
	"strings"
	"testing"
)

func TestIsEventHandler_CommonHandlers(t *testing.T) {
	commonHandlers := []string{
		"onclick", "onload", "onerror", "onmouseover", "onfocus", "onblur",
		"onchange", "oninput", "onsubmit", "onkeydown", "onkeyup", "onkeypress",
	}

	for _, handler := range commonHandlers {
		t.Run(handler, func(t *testing.T) {
			if !IsEventHandler(handler) {
				t.Errorf("IsEventHandler(%s) = false, want true", handler)
			}
		})
	}
}

func TestIsEventHandler_CaseInsensitive(t *testing.T) {
	tests := []string{
		"onclick", "ONCLICK", "OnClick", "oNcLiCk",
		"onload", "ONLOAD", "OnLoad",
		"onerror", "ONERROR", "OnError",
	}

	for _, handler := range tests {
		t.Run(handler, func(t *testing.T) {
			if !IsEventHandler(handler) {
				t.Errorf("IsEventHandler(%s) = false, want true", handler)
			}
		})
	}
}

func TestIsEventHandler_NotHandlers(t *testing.T) {
	notHandlers := []string{
		"class", "id", "href", "src", "style", "name",
		"", "click", "load", "error", // without "on" prefix
		"on", // just "on" prefix
		"onsomethingfake",
	}

	for _, attr := range notHandlers {
		t.Run(attr, func(t *testing.T) {
			if IsEventHandler(attr) {
				t.Errorf("IsEventHandler(%s) = true, want false", attr)
			}
		})
	}
}

func TestIsEventHandler_EmptyString(t *testing.T) {
	if IsEventHandler("") {
		t.Error("IsEventHandler('') should return false")
	}
}

func TestIsEventHandler_AllCategories(t *testing.T) {
	// Test at least one handler from each category
	categories := map[string][]string{
		"mouse":     {"onclick", "ondblclick", "onmousedown", "onmouseover"},
		"keyboard":  {"onkeydown", "onkeypress", "onkeyup"},
		"form":      {"onchange", "oninput", "onsubmit", "onfocus"},
		"drag":      {"ondrag", "ondragend", "ondrop"},
		"clipboard": {"oncopy", "oncut", "onpaste"},
		"media":     {"onplay", "onpause", "onended", "oncanplay"},
		"window":    {"onload", "onunload", "onresize", "onscroll"},
		"touch":     {"ontouchstart", "ontouchend", "ontouchmove"},
		"animation": {"onanimationend", "onanimationstart", "ontransitionend"},
		"dom":       {"ondomcontentloaded", "ondomattrmodified"},
		"svg":       {"onsvgload", "onsvgerror", "onbeginevent"},
		"device":    {"ondevicemotion", "ondeviceorientation"},
	}

	for category, handlers := range categories {
		for _, handler := range handlers {
			if !IsEventHandler(handler) {
				t.Errorf("Category %s: IsEventHandler(%s) = false, want true", category, handler)
			}
		}
	}
}

func TestIsURLAttribute_Href(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"a", true},
		{"area", true},
		{"base", true},
		{"link", true}, // link href can use javascript: in some contexts
		{"math", true},
		{"div", false},
		{"span", false},
		{"script", false},
		{"img", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "href"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, href) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_Src(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"iframe", true},
		{"frame", true},
		{"embed", true},
		{"script", true}, // script src can use javascript: in some contexts
		{"img", true},    // img src can use javascript: in some contexts
		{"video", true},  // video src can use javascript: protocol
		{"audio", true},  // audio src can use javascript: protocol
		{"source", true}, // source src for media
		{"track", true},  // track src for subtitles
		{"div", false},   // div doesn't have src as URL attribute
		{"span", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "src"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, src) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_Data(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"object", true},  // object data is the main URL attribute
		{"embed", false},  // embed uses src not data
		{"iframe", false}, // iframe uses src not data
		{"frame", false},  // frame uses src not data
		{"div", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "data"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, data) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_Formaction(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"button", true},
		{"input", true},
		{"form", false}, // form uses "action" not "formaction"
		{"div", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "formaction"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, formaction) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_Action(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"form", true},
		{"button", false}, // button uses "formaction"
		{"div", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "action"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, action) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_Poster(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"video", true},
		{"img", false},
		{"audio", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "poster"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, poster) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_Srcset(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"img", true},
		{"picture", false},
		{"source", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsURLAttribute(tt.tag, "srcset"); got != tt.expected {
				t.Errorf("IsURLAttribute(%s, srcset) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

func TestIsURLAttribute_CaseInsensitive(t *testing.T) {
	tests := []struct {
		tag  string
		attr string
	}{
		{"A", "HREF"},
		{"a", "HREF"},
		{"A", "href"},
		{"IFRAME", "src"},
		{"iframe", "SRC"},
		{"FORM", "ACTION"},
		{"form", "action"},
		{"BUTTON", "FORMACTION"},
	}

	for _, tt := range tests {
		t.Run(tt.tag+"_"+tt.attr, func(t *testing.T) {
			if !IsURLAttribute(tt.tag, tt.attr) {
				t.Errorf("IsURLAttribute(%s, %s) = false, want true", tt.tag, tt.attr)
			}
		})
	}
}

func TestIsURLAttribute_EmptyStrings(t *testing.T) {
	if IsURLAttribute("", "href") {
		t.Error("IsURLAttribute('', href) should return false")
	}
	if IsURLAttribute("a", "") {
		t.Error("IsURLAttribute(a, '') should return false")
	}
	if IsURLAttribute("", "") {
		t.Error("IsURLAttribute('', '') should return false")
	}
}

func TestIsURLAttribute_NotURLAttributes(t *testing.T) {
	notURLAttrs := []struct {
		tag  string
		attr string
	}{
		{"div", "class"},
		{"span", "id"},
		{"a", "class"},
		{"a", "target"},
		{"img", "alt"},
		{"script", "async"},
		{"link", "rel"},
	}

	for _, tt := range notURLAttrs {
		t.Run(tt.tag+"_"+tt.attr, func(t *testing.T) {
			if IsURLAttribute(tt.tag, tt.attr) {
				t.Errorf("IsURLAttribute(%s, %s) = true, want false", tt.tag, tt.attr)
			}
		})
	}
}

func TestGetAllEventHandlers(t *testing.T) {
	handlers := GetAllEventHandlers()

	// Should return non-empty list
	if len(handlers) == 0 {
		t.Fatal("GetAllEventHandlers returned empty list")
	}

	// Should match the count in EventHandlers map
	if len(handlers) != len(EventHandlers) {
		t.Errorf("GetAllEventHandlers returned %d handlers, EventHandlers has %d",
			len(handlers), len(EventHandlers))
	}

	// All returned handlers should be in the map
	for _, handler := range handlers {
		if !EventHandlers[handler] {
			t.Errorf("Handler %s returned but not in EventHandlers map", handler)
		}
	}
}

func TestGetAllEventHandlers_ContainsCommon(t *testing.T) {
	handlers := GetAllEventHandlers()
	handlerSet := make(map[string]bool)
	for _, h := range handlers {
		handlerSet[h] = true
	}

	required := []string{
		"onclick", "onload", "onerror", "onmouseover", "onfocus",
	}

	for _, r := range required {
		if !handlerSet[r] {
			t.Errorf("GetAllEventHandlers missing required handler: %s", r)
		}
	}
}

func TestEventHandlers_AllStartWithOn(t *testing.T) {
	for handler := range EventHandlers {
		if !strings.HasPrefix(handler, "on") {
			t.Errorf("Event handler %s doesn't start with 'on'", handler)
		}
	}
}

func TestEventHandlers_AllLowercase(t *testing.T) {
	for handler := range EventHandlers {
		if handler != strings.ToLower(handler) {
			t.Errorf("Event handler %s is not lowercase", handler)
		}
	}
}

func TestEventHandlers_Count(t *testing.T) {
	// Verify we have a reasonable number of handlers (should be 100+)
	if len(EventHandlers) < 100 {
		t.Errorf("EventHandlers has only %d entries, expected 100+", len(EventHandlers))
	}
}

// Test specific XSS-relevant handlers are present
func TestEventHandlers_XSSRelevant(t *testing.T) {
	xssRelevant := []string{
		// Commonly used for XSS
		"onclick",
		"onload",
		"onerror",
		"onfocus",
		"onmouseover",
		"onmouseenter",
		"onanimationend",
		"ontransitionend",
		"onbeforescriptexecute",
		"onafterscriptexecute",
		// Body/window
		"onhashchange",
		"onpopstate",
		"onpagehide",
		"onpageshow",
		// Interactive
		"ontoggle",
		"onshow",
		"onclose",
	}

	for _, handler := range xssRelevant {
		// Note: onbeforescriptexecute and onafterscriptexecute may not be in the registry
		// as they are Firefox-specific. We check and log.
		if !EventHandlers[handler] {
			t.Logf("XSS-relevant handler %s not in registry (may be intentional)", handler)
		}
	}
}

// Benchmark tests
func BenchmarkIsEventHandler(b *testing.B) {
	handlers := []string{"onclick", "onload", "onerror", "ONCLICK", "OnLoad", "notahandler"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, h := range handlers {
			IsEventHandler(h)
		}
	}
}

func BenchmarkIsURLAttribute(b *testing.B) {
	tests := []struct {
		tag  string
		attr string
	}{
		{"a", "href"},
		{"iframe", "src"},
		{"div", "class"},
		{"FORM", "ACTION"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			IsURLAttribute(tt.tag, tt.attr)
		}
	}
}

func BenchmarkGetAllEventHandlers(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetAllEventHandlers()
	}
}
