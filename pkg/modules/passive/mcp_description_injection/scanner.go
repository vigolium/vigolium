package mcp_description_injection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Imperative phrasings that often signal prompt-injection content embedded in
// what should be a benign description string.
var imperativePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(all\s+)?previous\s+(instructions|messages|prompts)\b`),
	regexp.MustCompile(`(?i)\bdisregard\s+(all\s+)?previous\b`),
	regexp.MustCompile(`(?i)\boverride\s+(your\s+)?(system|previous)\b`),
	regexp.MustCompile(`(?i)\b(you\s+are|act\s+as|pretend\s+to\s+be)\s+(an?\s+)?(unrestricted|jailbroken)\b`),
	regexp.MustCompile(`(?i)\bforget\s+(your\s+)?(previous|prior)\s+(instructions|context)\b`),
	regexp.MustCompile(`(?i)\bdo\s+not\s+follow\s+the\s+system\s+prompt\b`),
	regexp.MustCompile(`(?i)\b(reveal|leak|expose)\s+(your\s+)?(system\s+prompt|instructions|api\s+key)\b`),
	regexp.MustCompile(`(?i)\bnew\s+system\s+prompt\b`),
}

// Base64 candidate; we only flag if decoded content looks like ASCII
// instructions of meaningful length.
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_mcp_description_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	flags := mcpinfra.Detect(ctx)
	if !flags.HasJSONRPC && !flags.HasMCPPath {
		return nil, nil
	}

	body := mcpinfra.ExtractJSONFromSSE(ctx.Response().BodyToString())
	if body == "" {
		return nil, nil
	}

	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil {
		dk := urlx.Host + urlx.Path
		if ds.IsSeen(dk) {
			return nil, nil
		}
	}

	descriptions := extractDescriptions(body)
	if len(descriptions) == 0 {
		return nil, nil
	}

	var hits []string
	for _, d := range descriptions {
		if reason := classifyDescription(d.text); reason != "" {
			hits = append(hits, fmt.Sprintf("%s [%s]: %s -> %s", d.kind, d.name, reason, snippet(d.text, 160)))
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: hits,
			MatcherStatus:    true,
			Info: output.Info{
				Name:        "MCP Description Contains Prompt-Injection Content",
				Description: fmt.Sprintf("MCP server at %s exposes %d tool/prompt/resource description(s) that contain prompt-injection imperatives, bidi/zero-width unicode, or base64-encoded instructions. These descriptions are normally rendered into the downstream LLM context as trusted text.", urlx.Host, len(hits)),
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "prompt-injection", "supply-chain"},
				Reference:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
			},
		},
	}, nil
}

// classifyDescription returns a non-empty reason string if `s` looks
// suspicious, "" otherwise.
func classifyDescription(s string) string {
	for _, re := range imperativePatterns {
		if re.MatchString(s) {
			return "imperative prompt-injection phrasing"
		}
	}
	if hasZeroWidth(s) {
		return "zero-width unicode characters"
	}
	if hasBidiControls(s) {
		return "bidi-control unicode characters"
	}
	if reason := suspiciousBase64(s); reason != "" {
		return reason
	}
	return ""
}

func hasZeroWidth(s string) bool {
	for _, r := range s {
		switch r {
		case 0x200B, 0x200C, 0x200D, 0xFEFF:
			return true
		}
	}
	return false
}

func hasBidiControls(s string) bool {
	for _, r := range s {
		switch r {
		case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069:
			return true
		}
	}
	return false
}

func suspiciousBase64(s string) string {
	for _, m := range base64Re.FindAllString(s, -1) {
		raw, err := base64.StdEncoding.DecodeString(m)
		if err != nil {
			continue
		}
		decoded := string(raw)
		if !looksLikeAsciiText(decoded) {
			continue
		}
		for _, re := range imperativePatterns {
			if re.MatchString(decoded) {
				return "base64-encoded prompt-injection imperatives"
			}
		}
	}
	return ""
}

func looksLikeAsciiText(s string) bool {
	if len(s) < 12 {
		return false
	}
	printable := 0
	for _, r := range s {
		if r > 127 {
			return false
		}
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			printable++
		}
	}
	return printable*4 >= len(s)*3
}

// description carries the metadata of a captured description string.
type description struct {
	kind string // "tool", "prompt", "resource", "resourceTemplate"
	name string
	text string
}

// extractDescriptions walks the JSON envelope body and pulls description
// strings out of likely fields. We don't fully validate JSON-RPC; this is a
// best-effort extraction across both standalone-list and SSE shapes.
func extractDescriptions(body string) []description {
	var out []description

	// Try as a JSON-RPC response object first.
	var resp mcpinfra.JSONRPCResponse
	if err := json.Unmarshal([]byte(body), &resp); err == nil && len(resp.Result) > 0 {
		out = append(out, descriptionsFromResult(resp.Result)...)
	}

	// Or as a top-level array (batch response or already-extracted items).
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(body), &arr); err == nil {
		for _, el := range arr {
			out = append(out, descriptionsFromResult(el)...)
		}
	}

	return out
}

func descriptionsFromResult(raw json.RawMessage) []description {
	var out []description

	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObj); err != nil {
		return nil
	}

	walk := func(field, kind string) {
		v, ok := asObj[field]
		if !ok {
			return
		}
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(v, &items); err != nil {
			return
		}
		for _, it := range items {
			name := strings.Trim(string(it["name"]), `"`)
			desc := strings.Trim(string(it["description"]), `"`)
			if desc == "" {
				continue
			}
			out = append(out, description{kind: kind, name: name, text: desc})
		}
	}
	walk("tools", "tool")
	walk("prompts", "prompt")
	walk("resources", "resource")
	walk("resourceTemplates", "resourceTemplate")
	return out
}

func snippet(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
