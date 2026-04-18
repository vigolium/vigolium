package templatebench

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ollama/ollama/api"
	"github.com/ollama/ollama/template"
)

// Bench the attacker-controlled amplification vector:
// TEMPLATE: {{range .Messages}}{{range .ToolCalls}}{{json .Function.Arguments}}{{end}}{{end}}
// with 500 messages x 50 tool calls x 10KB argument per call.
func TestAmplification(t *testing.T) {
	tmplSrc := `{{range .Messages}}{{range .ToolCalls}}{{json .Function.Arguments}}{{end}}{{end}}`
	tmpl, err := template.Parse(tmplSrc)
	if err != nil {
		t.Fatal(err)
	}

	// Build a large argument map ~10KB
	bigArgs := api.NewToolCallFunctionArguments()
	for i := 0; i < 200; i++ {
		bigArgs.Set(fmt.Sprintf("key_%d", i), strings.Repeat("x", 40))
	}

	var messages []api.Message
	for i := 0; i < 500; i++ {
		var toolCalls []api.ToolCall
		for j := 0; j < 50; j++ {
			toolCalls = append(toolCalls, api.ToolCall{
				Function: api.ToolCallFunction{
					Name:      "x",
					Arguments: bigArgs,
				},
			})
		}
		messages = append(messages, api.Message{Role: "user", ToolCalls: toolCalls})
	}

	start := time.Now()
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, template.Values{Messages: messages}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("AMPLIFIED: rendered %d bytes in %s (messages=%d, tool_calls_each=%d, arg_size=~10KB)", buf.Len(), elapsed, 500, 50)

	// Small control
	smallStart := time.Now()
	var sBuf bytes.Buffer
	if err := tmpl.Execute(&sBuf, template.Values{Messages: []api.Message{{Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	sElapsed := time.Since(smallStart)
	t.Logf("BASELINE: rendered %d bytes in %s", sBuf.Len(), sElapsed)
}

// Test whether Parse accepts arbitrarily large templates
func TestLargeTemplate(t *testing.T) {
	// 50MB template body with simple repeated expression
	var sb bytes.Buffer
	for sb.Len() < 50*1024*1024 {
		sb.WriteString("abc{{.Prompt}}\n")
	}
	start := time.Now()
	tmpl, err := template.Parse(sb.String())
	elapsed := time.Since(start)
	t.Logf("Parse: %d bytes in %s", sb.Len(), elapsed)
	if err != nil {
		t.Fatal(err)
	}

	// Measure Vars() cost
	start = time.Now()
	for i := 0; i < 10; i++ {
		if _, err := tmpl.Vars(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("Vars() x10 = %s", time.Since(start))
}
