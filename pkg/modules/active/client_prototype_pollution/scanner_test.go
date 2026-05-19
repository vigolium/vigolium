package client_prototype_pollution

import (
	"strings"
	"testing"
)

func TestSourcePatternMatching(t *testing.T) {
	tests := []struct {
		name    string
		js      string
		wantHit string // expected source pattern name, empty if none expected
	}{
		{
			name:    "jQuery deep extend",
			js:      `$.extend( true, target, input);`,
			wantHit: "jQuery.extend (deep)",
		},
		{
			name:    "lodash merge",
			js:      `_.merge(defaults, userParams);`,
			wantHit: "lodash.merge",
		},
		{
			name:    "lodash defaultsDeep",
			js:      `_.defaultsDeep(config, input);`,
			wantHit: "lodash.defaultsDeep",
		},
		{
			name:    "lodash set",
			js:      `_.set(obj, path, value);`,
			wantHit: "lodash.set",
		},
		{
			name:    "Object.assign from location",
			js:      `Object.assign(config, location.search);`,
			wantHit: "Object.assign from params",
		},
		{
			name:    "Object.assign from params",
			js:      `Object.assign({}, params);`,
			wantHit: "Object.assign from params",
		},
		{
			name:    "location.search split parser",
			js:      `location.search.split("&")[key] = val`,
			wantHit: "location.search split parser",
		},
		{
			name:    "safe code no match",
			js:      `console.log("hello world"); var x = 42;`,
			wantHit: "",
		},
		{
			name:    "jQuery shallow extend (not deep)",
			js:      `$.extend(target, source);`,
			wantHit: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched string
			for _, sp := range ppSourcePatterns {
				if sp.Pattern.MatchString(tt.js) {
					matched = sp.Name
					break
				}
			}
			if tt.wantHit == "" {
				if matched != "" {
					t.Errorf("expected no match, got %q", matched)
				}
			} else {
				if matched != tt.wantHit {
					t.Errorf("expected match %q, got %q", tt.wantHit, matched)
				}
			}
		})
	}
}

func TestGadgetPatternMatching(t *testing.T) {
	tests := []struct {
		name    string
		js      string
		wantHit string
	}{
		{
			name:    "innerHTML gadget",
			js:      `el.innerHTML = config["template"];`,
			wantHit: "innerHTML gadget",
		},
		{
			name:    "innerHTML with options",
			js:      `el.innerHTML = options["html"];`,
			wantHit: "innerHTML gadget",
		},
		{
			name:    "eval gadget",
			js:      `eval(config["code"]);`,
			wantHit: "eval gadget",
		},
		{
			name:    "script src gadget",
			js:      `script.src = defaults["scriptUrl"];`,
			wantHit: "script.src gadget",
		},
		{
			name:    "safe code",
			js:      `document.getElementById("app").textContent = "hello";`,
			wantHit: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched string
			for _, gp := range ppGadgetPatterns {
				if gp.Pattern.MatchString(tt.js) {
					matched = gp.Name
					break
				}
			}
			if tt.wantHit == "" {
				if matched != "" {
					t.Errorf("expected no match, got %q", matched)
				}
			} else {
				if matched != tt.wantHit {
					t.Errorf("expected match %q, got %q", tt.wantHit, matched)
				}
			}
		})
	}
}

func TestExtractMatchLine(t *testing.T) {
	content := "var a = 1;\n$.extend( true, target, input);\nvar b = 2;"
	// Find the position of $.extend
	pos := strings.Index(content, "$.extend")
	if pos == -1 {
		t.Fatal("test setup: $.extend not found")
	}

	line := extractMatchLine(content, pos)
	if line != "$.extend( true, target, input);" {
		t.Errorf("extractMatchLine() = %q, want %q", line, "$.extend( true, target, input);")
	}
}

func TestExtractMatchLine_LongLine(t *testing.T) {
	// Create a very long line
	long := strings.Repeat("x", 300) + "$.extend( true, a, b);"
	pos := strings.Index(long, "$.extend")
	line := extractMatchLine(long, pos)
	if len(line) > 210 { // 200 + "..."
		t.Errorf("line should be truncated, got length %d", len(line))
	}
}

func TestBuildProbeURL(t *testing.T) {
	tests := []struct {
		name    string
		pageURL string
		suffix  string
		want    string
	}{
		{
			name:    "no existing query",
			pageURL: "https://example.com/page",
			suffix:  "__proto__[test]=1",
			want:    "https://example.com/page?__proto__[test]=1",
		},
		{
			name:    "existing query",
			pageURL: "https://example.com/page?id=1",
			suffix:  "__proto__[test]=1",
			want:    "https://example.com/page?id=1&__proto__[test]=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildProbeURL(tt.pageURL, tt.suffix)
			if got != tt.want {
				t.Errorf("buildProbeURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
