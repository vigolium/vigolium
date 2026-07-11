package dom_xss_detect

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	assignmentRe = regexp.MustCompile(`(?s)^\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+)$`)
	sanitizerRe  = regexp.MustCompile(`(?i)\b(?:DOMPurify\.sanitize|sanitizeHTML|escapeHTML|encodeURIComponent|htmlEncode)\s*\(`)
)

// analyseOpenRedirect reports only a traced source-to-navigation flow. Merely
// having location.search and location.href somewhere in the same script is not
// evidence that attacker-controlled data reaches the redirect.
func analyseOpenRedirect(response string) string {
	flow := analyseFlows(response, openRedirectSinks)
	if flow == "" {
		return ""
	}
	return "Traced controllable data into redirect sink:\n" + flow
}

// analyse reports a DOM-XSS candidate only when the lightweight tracer can
// connect a browser-controlled source to an executable DOM sink. The previous
// implementation returned a finding when either a source or a sink appeared,
// which turned ordinary source reads and ordinary DOM rendering into findings.
func analyse(response string) string {
	return analyseFlows(response, sinks)
}

// analyseFlows performs deliberately conservative, statement-local taint
// propagation for inline scripts. It understands direct source-to-sink calls
// and simple identifier assignments/aliases. Complex JavaScript is left to the
// dedicated dom_xss_taint analyzer rather than guessed here.
func analyseFlows(response string, sinkRe *regexp.Regexp) string {
	scripts := scriptExtract.FindAllStringSubmatch(response, -1)
	var flows []string
	for _, script := range scripts {
		if len(script) < 2 {
			continue
		}
		tainted := make(map[string]struct{})
		for lineIndex, line := range strings.Split(script[1], "\n") {
			for _, statement := range splitStatements(line) {
				statement = strings.TrimSpace(statement)
				if statement == "" {
					continue
				}

				flowValue := assignmentValue(statement)
				directSource := sources.MatchString(flowValue)
				usesTainted := statementUsesTainted(flowValue, tainted)
				if sinkRe.MatchString(statement) && (directSource || usesTainted) && !sanitizerRe.MatchString(statement) {
					flows = append(flows, fmt.Sprintf("%-3d %s", lineIndex+1, statement))
				}

				match := assignmentRe.FindStringSubmatch(statement)
				if len(match) != 3 {
					continue
				}
				name, rhs := match[1], match[2]
				if sanitizerRe.MatchString(rhs) {
					delete(tainted, name)
					continue
				}
				if sources.MatchString(rhs) || statementUsesTainted(rhs, tainted) {
					tainted[name] = struct{}{}
				} else {
					delete(tainted, name)
				}
			}
		}
	}
	return strings.Join(flows, "\n")
}

// assignmentValue returns the value side of a simple JavaScript assignment.
// This is important for navigation: in `location.href = "/home"`, location.href
// is a sink being written, not an attacker-controlled source being read.
func assignmentValue(statement string) string {
	for i := 0; i < len(statement); i++ {
		if statement[i] != '=' {
			continue
		}
		var prev, next byte
		if i > 0 {
			prev = statement[i-1]
		}
		if i+1 < len(statement) {
			next = statement[i+1]
		}
		if prev == '=' || prev == '!' || prev == '<' || prev == '>' || next == '=' || next == '>' {
			continue
		}
		return statement[i+1:]
	}
	return statement
}

func splitStatements(line string) []string {
	// This light detector intentionally handles only straight-line statements.
	// Keeping braces with their statement preserves enough context for sink/source
	// regexes while avoiding the old whole-script co-occurrence oracle.
	return strings.FieldsFunc(line, func(r rune) bool { return r == ';' })
}

func statementUsesTainted(statement string, tainted map[string]struct{}) bool {
	for name := range tainted {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		if re.MatchString(statement) {
			return true
		}
	}
	return false
}
