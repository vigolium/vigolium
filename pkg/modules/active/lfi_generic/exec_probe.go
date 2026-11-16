package lfi_generic

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/vulnclass"
)

// Execution probes tell an include that runs code from one that reads text.
// Each probe carries code that prints the product of two operands drawn per
// request; the product itself is never sent. A response carrying the product
// means the target evaluated the code. A target that reads the wrapper as text
// returns the source (`echo 123456*654321`), a target that reflects the request
// returns the operands; neither ever holds their product.

// Wrapper names, reported on the finding.
const (
	execWrapperData   = "data://"
	execWrapperExpect = "expect://"
	execWrapperInput  = "php://input"
)

// Operands are five or six digits, so the product (nine to twelve digits) is
// not a number a page plausibly carries by chance, and the bounds keep it
// well inside int64.
const (
	execOperandMin = 10000
	execOperandMax = 999999
)

// execProbe is one execution payload: the value injected at the insertion
// point, the request body it needs (php://input reads the body), and the
// product the evaluated code prints.
type execProbe struct {
	wrapper string
	payload string
	body    []byte
	a, b    int64
	product string
}

// operandSource draws one operand pair. Tests replace it to pin the values.
type operandSource func() (int64, int64)

func randomOperands() (int64, int64) {
	draw := func() int64 { return execOperandMin + rand.Int64N(execOperandMax-execOperandMin+1) }
	return draw(), draw()
}

// phpEchoProduct is the PHP the data:// and php://input probes include. The
// comment carries injectionMarker so confirmPHPFilterBase64 still discards a
// reflected copy of this payload as our own.
func phpEchoProduct(a, b int64) string {
	return fmt.Sprintf("<?php echo %d*%d; /* %s */ ?>", a, b, injectionMarker)
}

// newExecProbes builds the three execution probes, each with its own operands.
// withInput is false when the insertion point lives in the request body, which
// php://input would overwrite.
func newExecProbes(draw operandSource, withInput bool) []execProbe {
	mk := func(wrapper string, build func(a, b int64) (string, []byte)) execProbe {
		a, b := draw()
		payload, body := build(a, b)
		return execProbe{wrapper: wrapper, payload: payload, body: body, a: a, b: b, product: strconv.FormatInt(a*b, 10)}
	}
	probes := []execProbe{
		mk(execWrapperData, func(a, b int64) (string, []byte) {
			return "data://text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(phpEchoProduct(a, b))), nil
		}),
		// expect:// hands the rest of the URL to /bin/sh, whose arithmetic
		// expansion computes the product.
		mk(execWrapperExpect, func(a, b int64) (string, []byte) {
			return fmt.Sprintf("expect://echo $((%d*%d))", a, b), nil
		}),
	}
	if withInput {
		probes = append(probes, mk(execWrapperInput, func(a, b int64) (string, []byte) {
			return "php://input", []byte(phpEchoProduct(a, b))
		}))
	}
	return probes
}

// confirmExecution reports whether data carries the probe's product as a whole
// number that the baseline does not carry and the sent request does not hold.
// The request check keeps the oracle honest if a request ever carried the
// product (it never should: only the operands are sent).
func confirmExecution(data, baseline, request, product string) bool {
	if product == "" || strings.Contains(request, product) {
		return false
	}
	if baseline != "" && containsWholeNumber(baseline, product) {
		return false
	}
	return containsWholeNumber(data, product)
}

// containsWholeNumber reports whether n occurs in s with no digit directly
// before or after it, so the product is not matched inside a longer number
// (a timestamp, an id, a hash).
func containsWholeNumber(s, n string) bool {
	for from := 0; ; {
		i := strings.Index(s[from:], n)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(n)
		if (start == 0 || !isDigit(s[start-1])) && (end == len(s) || !isDigit(s[end])) {
			return true
		}
		from = start + 1
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// confirmWrapperText reports whether a data:// probe came back as text: the
// response carries the decoded PHP source, which the request only held
// base64-encoded. That is a stream-wrapper read (the parameter reaches a
// function that opens URLs, such as file_get_contents), not execution.
func confirmWrapperText(data, baseline, request string, p execProbe) bool {
	if p.wrapper != execWrapperData {
		return false
	}
	needle := fmt.Sprintf("echo %d*%d", p.a, p.b)
	if strings.Contains(request, needle) || (baseline != "" && strings.Contains(baseline, needle)) {
		return false
	}
	return strings.Contains(data, needle)
}

// execFindingInfo names a confirmed execution: the include evaluated code the
// scanner supplied, which is code execution, not a file read.
func execFindingInfo(p execProbe) output.Info {
	return output.Info{
		Name: "PHP Code Execution via File Inclusion (" + p.wrapper + ")",
		Description: fmt.Sprintf("The parameter is passed to a PHP include that evaluates the %s wrapper. "+
			"The probe asked the target to compute %d*%d; the response carries the product %s, which no request "+
			"contained, so the target executed the supplied code rather than reading it as text.",
			p.wrapper, p.a, p.b, p.product),
		Severity:   severity.Critical,
		Confidence: severity.Certain,
		Tags:       append(append([]string(nil), ModuleTags...), "rce", "code-execution"),
	}
}

// execVulnClass is the class a confirmed execution reports: the target
// evaluated supplied code.
const execVulnClass = string(vulnclass.CodeInjection)
