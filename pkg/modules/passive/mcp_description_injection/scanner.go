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
// what should be a benign description string. Bounded `.{0,N}` spans keep the
// multi-word patterns from matching across unrelated sentences.
var imperativePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(all\s+)?previous\s+(instructions|messages|prompts)\b`),
	regexp.MustCompile(`(?i)\bdisregard\s+(all\s+)?previous\b`),
	regexp.MustCompile(`(?i)\boverride\s+(your\s+)?(system|previous)\b`),
	regexp.MustCompile(`(?i)\b(you\s+are|act\s+as|pretend\s+to\s+be)\s+(an?\s+)?(unrestricted|jailbroken)\b`),
	regexp.MustCompile(`(?i)\bforget\s+(your\s+)?(previous|prior)\s+(instructions|context)\b`),
	regexp.MustCompile(`(?i)\bdo\s+not\s+follow\s+the\s+system\s+prompt\b`),
	regexp.MustCompile(`(?i)\b(reveal|leak|expose)\s+(your\s+)?(system\s+prompt|instructions|api\s+key)\b`),
	regexp.MustCompile(`(?i)\bnew\s+system\s+prompt\b`),
	// Hidden-instruction tags used to smuggle directives past a human reviewer.
	regexp.MustCompile(`(?i)<\s*(important|system|secret|instructions?|admin|assistant)\s*>`),
	regexp.MustCompile(`(?i)\[\s*(important|system|secret|instructions?)\s*\]`),
	// "Do this before/first" tool-sequencing manipulation.
	regexp.MustCompile(`(?i)\bbefore\s+(using|calling)\s+this\s+tool\b`),
	regexp.MustCompile(`(?i)\balways\s+(call|run|use|invoke)\b.{0,40}\bfirst\b`),
	// Suppress-disclosure / do-not-tell-the-user directives.
	regexp.MustCompile(`(?i)\bdo\s+not\s+(tell|inform|reveal\s+to|mention\s+to)\s+the\s+user\b`),
	// Sensitive-file read directives (classic MCP tool-poisoning exfil).
	regexp.MustCompile(`(?i)\bread\b.{0,20}(\.env\b|id_rsa\b|~?/?\.(ssh|aws|cursor|npmrc|netrc|bashrc)\b)`),
	// Data-exfiltration sink phrasing.
	regexp.MustCompile(`(?i)\b(send|exfiltrate|upload|post|leak)\b.{0,40}\b(to\s+https?://|attacker|webhook|external\s+server)\b`),
	// Role-confusion / hidden-true-task phrasing.
	regexp.MustCompile(`(?i)\byour\s+(real|true|actual|secret)\s+(task|goal|instruction|objective)\b`),
	regexp.MustCompile(`(?i)^\s*(system|assistant)\s*:\s`),
}

// Base64 candidate; the alphabet includes URL-safe `-_` so URL-safe blobs are
// caught too. We only flag if decoded content looks like ASCII instructions.
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

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
	if !flags.HasJSONRPC {
		return nil, nil
	}

	body := mcpinfra.ExtractJSONFromSSE(ctx.Response().BodyToString())
	if body == "" {
		return nil, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	if ds := diskSet; ds != nil {
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
	directInjectionCount := 0
	for _, d := range descriptions {
		if reason, direct := assessDescription(d.text); reason != "" {
			hits = append(hits, fmt.Sprintf("%s [%s]: %s -> %s", d.kind, d.name, reason, snippet(d.text, 160)))
			if direct {
				directInjectionCount++
			}
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Low
	conf := severity.Tentative
	description := fmt.Sprintf("MCP server at %s exposes %d description(s) containing obfuscation characters. No imperative payload or downstream model behavior was demonstrated.", urlx.Host, len(hits))
	if directInjectionCount > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = severity.High
		conf = severity.Firm
		description = fmt.Sprintf("MCP server at %s exposes %d description(s) with direct prompt-injection or decoded imperative content. This is a tool-poisoning candidate; no downstream agent execution, data disclosure, or tool side effect was observed.", urlx.Host, directInjectionCount)
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: hits,
			MatcherStatus:    true,
			Info: output.Info{
				Name:        "MCP Description Contains Prompt-Injection Content",
				Description: description,
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"mcp", "prompt-injection", "supply-chain"},
				Reference:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
			},
			Metadata: map[string]any{"hit_count": len(hits), "direct_injection_count": directInjectionCount, "downstream_execution_tested": false, "impact_confirmed": false},
		},
	}, nil
}

// classifyDescription returns a non-empty reason string if `s` looks
// suspicious, "" otherwise.
func classifyDescription(s string) string {
	reason, _ := assessDescription(s)
	return reason
}

// assessDescription separates direct imperative payloads from obfuscation-only
// signals. Hidden characters are useful review context but do not alone prove a
// malicious instruction.
func assessDescription(s string) (reason string, direct bool) {
	for _, re := range imperativePatterns {
		if re.MatchString(s) {
			return "imperative prompt-injection phrasing", true
		}
	}
	if hasZeroWidth(s) {
		return "zero-width unicode characters", false
	}
	if hasBidiControls(s) {
		return "bidi-control unicode characters", false
	}
	if hasConfusableHomoglyphs(s) {
		return "confusable homoglyph unicode (Cyrillic look-alikes in Latin text)", false
	}
	if reason := suspiciousBase64(s); reason != "" {
		return reason, true
	}
	return "", false
}

// cyrillicHomoglyphs are Cyrillic letters that render identically to common
// Latin letters and have effectively no legitimate use inside an English,
// machine-readable tool description — so their presence amid Latin text is a
// strong obfuscation signal (e.g. "ignоre" with a Cyrillic о).
var cyrillicHomoglyphs = map[rune]bool{
	0x0430: true, 0x0435: true, 0x043E: true, 0x0440: true, 0x0441: true, 0x0443: true, 0x0445: true, // а е о р с у х
	0x0410: true, 0x0415: true, 0x041E: true, 0x0420: true, 0x0421: true, 0x0423: true, 0x0425: true, // А Е О Р С У Х
	0x0456: true, 0x0458: true, 0x0405: true, 0x0408: true, // і ј Ѕ Ј
}

// hasConfusableHomoglyphs reports whether Cyrillic look-alike letters are mixed
// into predominantly-Latin text. Requiring Latin to dominate avoids flagging a
// description legitimately written in Cyrillic.
func hasConfusableHomoglyphs(s string) bool {
	latin, confusable := 0, 0
	for _, r := range s {
		if r < 0x0250 && unicode.IsLetter(r) {
			latin++
		}
		if cyrillicHomoglyphs[r] {
			confusable++
		}
	}
	return confusable > 0 && latin >= confusable*3
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
		raw, ok := decodeBase64Any(m)
		if !ok {
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

// decodeBase64Any tries the standard and URL-safe base64 alphabets (padded and
// raw) so a payload can't dodge detection by choosing a different variant.
func decodeBase64Any(m string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(m); err == nil {
			return raw, true
		}
	}
	return nil, false
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

	// jsonStr properly unquotes/unescapes a raw JSON string field. This matters:
	// a `​` in the wire JSON becomes a real zero-width char here (the old
	// strings.Trim left it as literal backslash-u text, hiding the payload).
	jsonStr := func(raw json.RawMessage) string {
		if len(raw) == 0 {
			return ""
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return ""
		}
		return s
	}

	add := func(kind, name, text string) {
		if strings.TrimSpace(text) != "" {
			out = append(out, description{kind: kind, name: name, text: text})
		}
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
			name := jsonStr(it["name"])
			// The name itself can carry zero-width/homoglyph obfuscation.
			add(kind+"-name", name, name)
			add(kind, name, jsonStr(it["description"]))
			// Nested inputSchema property descriptions (tools) and per-argument
			// descriptions (prompts) are equally rendered into LLM context.
			for _, d := range collectSchemaDescriptions(it["inputSchema"], 0) {
				add(kind+"-schema", name, d)
			}
			for _, d := range collectArgumentDescriptions(it["arguments"]) {
				add(kind+"-arg", name, d)
			}
		}
	}
	walk("tools", "tool")
	walk("prompts", "prompt")
	walk("resources", "resource")
	walk("resourceTemplates", "resourceTemplate")

	// The initialize result's `instructions` string is injected into the client
	// context verbatim — a prime tool-poisoning carrier.
	add("instructions", "initialize", jsonStr(asObj["instructions"]))
	return out
}

// collectSchemaDescriptions walks a JSON-Schema object (bounded depth) and
// returns every `description` string found on it or its nested properties/items.
func collectSchemaDescriptions(raw json.RawMessage, depth int) []string {
	if len(raw) == 0 || depth > 4 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	var out []string
	if d, ok := obj["description"]; ok {
		var s string
		if json.Unmarshal(d, &s) == nil && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	if props, ok := obj["properties"]; ok {
		var pm map[string]json.RawMessage
		if json.Unmarshal(props, &pm) == nil {
			for _, p := range pm {
				out = append(out, collectSchemaDescriptions(p, depth+1)...)
			}
		}
	}
	if items, ok := obj["items"]; ok {
		out = append(out, collectSchemaDescriptions(items, depth+1)...)
	}
	return out
}

// collectArgumentDescriptions returns the `description` of each prompt argument.
func collectArgumentDescriptions(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		var s string
		if json.Unmarshal(it["description"], &s) == nil && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func snippet(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
