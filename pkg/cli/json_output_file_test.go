package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func withJSONOutput(t *testing.T, path string, jsonMode bool) {
	t.Helper()
	prevPath, prevJSON, prevWatch := jsonOutputPath, globalJSON, globalWatchRaw
	t.Cleanup(func() {
		jsonOutputPath, globalJSON, globalWatchRaw = prevPath, prevJSON, prevWatch
		jsonResultEmitted = false
	})
	jsonOutputPath, globalJSON, globalWatchRaw = path, jsonMode, ""
}

func TestValidateJSONOutputFlagRequiresJSON(t *testing.T) {
	cmd := &cobra.Command{Use: "traffic"}
	root := &cobra.Command{Use: "vigolium"}
	root.AddCommand(cmd)

	withJSONOutput(t, "out.json", false)
	err := validateJSONOutputFlag(cmd)
	if err == nil {
		t.Fatal("-o without --json must be rejected: there is no result document to write")
	}
	// Pointed somewhere useful rather than just refused.
	if !strings.Contains(err.Error(), "vigolium export") {
		t.Errorf("error should name the command that does write rendered output: %q", err)
	}

	withJSONOutput(t, "out.json", true)
	if err := validateJSONOutputFlag(cmd); err != nil {
		t.Errorf("-o with --json rejected: %v", err)
	}
}

func TestValidateJSONOutputFlagRejectsWatch(t *testing.T) {
	cmd := &cobra.Command{Use: "traffic"}
	root := &cobra.Command{Use: "vigolium"}
	root.AddCommand(cmd)

	withJSONOutput(t, "out.json", true)
	globalWatchRaw = "5s"

	if err := validateJSONOutputFlag(cmd); err == nil {
		t.Error("--watch emits a document per tick; there is no single result to save")
	}

	// '-' is explicitly "keep printing to stdout", which --watch can do.
	jsonOutputPath = "-"
	if err := validateJSONOutputFlag(cmd); err != nil {
		t.Errorf("-o - with --watch rejected: %v", err)
	}
}

func TestJSONOutputDestinationTreatsDashAsStdout(t *testing.T) {
	withJSONOutput(t, "-", true)
	if got := jsonOutputDestination(); got != "" {
		t.Errorf("-o - should mean stdout, got %q", got)
	}
	jsonOutputPath = "  spaced.json  "
	if got := jsonOutputDestination(); got != "spaced.json" {
		t.Errorf("destination = %q", got)
	}
	jsonOutputPath = ""
	if got := jsonOutputDestination(); got != "" {
		t.Errorf("unset destination = %q", got)
	}
}

// The saved document must be exactly what the same command prints without -o.
// A file that differs from the stdout form is a second output contract to keep
// in sync, which is what routing through one encoder avoids.
func TestEncodeAgentJSONMatchesStdoutForm(t *testing.T) {
	env := newAgentEnvelope("traffic", "records", []map[string]any{
		{"uuid": "a", "url": "https://example.invalid/?a=1&b=2"},
	}, 1, 0, 100)

	doc, err := encodeAgentJSON(env)
	if err != nil {
		t.Fatalf("encodeAgentJSON: %v", err)
	}
	if !json.Valid(doc) {
		t.Fatalf("not valid JSON: %s", doc)
	}
	// HTML escaping stays off, as on the stdout path — an escaped & in every URL
	// is both unreadable and more tokens.
	if !strings.Contains(string(doc), "?a=1&b=2") {
		t.Errorf("ampersand was escaped: %s", doc)
	}
	// Compact by default (--pretty indents): one line plus the newline.
	if strings.Count(string(doc), "\n") != 1 {
		t.Errorf("not one compact line: %s", doc)
	}
}

func TestResultIsPagedDetectsAWindow(t *testing.T) {
	rows := []map[string]any{{"uuid": "a"}, {"uuid": "b"}}

	// Fewer rows than the total means the file holds one page, and a receipt that
	// claimed completeness would let a partial export be read as a whole one.
	if !resultIsPaged(newAgentEnvelope("traffic", "records", rows, 60, 0, 2)) {
		t.Error("a 2-of-60 page was reported as complete")
	}
	if resultIsPaged(newAgentEnvelope("traffic", "records", rows, 2, 0, 100)) {
		t.Error("a complete result was reported as a page")
	}
	// db stats emits an object, not a row list: there is no page to describe.
	if resultIsPaged(newAgentEnvelope("db stats", "", map[string]any{"records": 1}, 1, 0, 1)) {
		t.Error("an object-valued envelope was reported as a page")
	}
	// A non-envelope (the receipt itself, a bespoke doctor report) is complete.
	if resultIsPaged(map[string]any{"artifact": "json_result"}) {
		t.Error("a non-envelope value was reported as a page")
	}
}

func TestWriteJSONResultToFileWritesDocumentAndReceipt(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "result.json")
	doc := []byte(`{"schema_version":1,"items":[]}` + "\n")

	withJSONOutput(t, dest, true)

	// Capture stdout so the receipt can be parsed rather than eyeballed.
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	writeErr := writeJSONResultToFile(dest, doc, newAgentEnvelope("traffic", "", []string{}, 0, 0, 0))
	_ = w.Close()
	os.Stdout = orig

	if writeErr != nil {
		t.Fatalf("writeJSONResultToFile: %v", writeErr)
	}

	var receipt map[string]any
	if err := json.NewDecoder(r).Decode(&receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v", err)
	}
	if receipt["output"] != dest {
		t.Errorf("receipt output = %v, want %s", receipt["output"], dest)
	}
	if receipt["complete"] != true {
		t.Errorf("receipt complete = %v", receipt["complete"])
	}
	// The receipt replaces the document on stdout; echoing it back would
	// reinstate exactly the transcript cost -o exists to remove.
	if items, _ := receipt["items"].([]any); len(items) != 0 {
		t.Error("the receipt carries the result rows")
	}
	// The receipt is an envelope: the source document's spine, ok, artifacts.
	if receipt["command"] != "traffic" || receipt["ok"] != true || receipt["schema_version"] == nil {
		t.Errorf("receipt is not an envelope: %v", receipt)
	}
	if arts, _ := receipt["artifacts"].([]any); len(arts) != 1 {
		t.Errorf("receipt artifacts = %v", receipt["artifacts"])
	}

	saved, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != string(doc) {
		t.Errorf("saved document differs from the encoded one:\n got %q\nwant %q", saved, doc)
	}
}
