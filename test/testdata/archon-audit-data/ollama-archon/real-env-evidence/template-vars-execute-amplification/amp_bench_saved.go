package template_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/ollama/ollama/template"
)

func TestVarsCostOnLargeTemplate(t *testing.T) {
	// 10 MB template - realistic upper bound via /api/create JSON body
	var sb bytes.Buffer
	for sb.Len() < 10*1024*1024 {
		sb.WriteString("{{.Prompt}}")
	}
	tmpl, err := template.Parse(sb.String())
	if err != nil {
		t.Fatal(err)
	}

	// Per-Execute Vars() cost
	start := time.Now()
	for i := 0; i < 10; i++ {
		if _, err := tmpl.Vars(); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("10MB template: Vars() x10 = %s (avg %s per call)", elapsed, elapsed/10)
}
