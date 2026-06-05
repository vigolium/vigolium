package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// When --format jsonl routes through the post-scan envelope export
// (DeferredJSONLExport), StandardWriter must not open a live jsonl file and must
// suppress the live nuclei-style ResultEvent stream on stdout — unless console
// output was also requested, which keeps its own live stream.
func TestNewStandardWriterDeferredJSONL(t *testing.T) {
	t.Run("jsonl-only deferred suppresses live file and stdout", func(t *testing.T) {
		opts := &types.Options{
			Output:              filepath.Join(t.TempDir(), "out.jsonl"),
			OutputFormats:       []string{"jsonl"},
			JSONOutput:          true,
			DeferredJSONLExport: true,
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		if w.outputFile != nil {
			t.Error("expected no live output file for deferred jsonl")
		}
		if !w.DisableStdout {
			t.Error("expected live stdout suppressed for deferred jsonl")
		}
	})

	t.Run("jsonl+console keeps console's live output", func(t *testing.T) {
		opts := &types.Options{
			Output:              filepath.Join(t.TempDir(), "out"),
			OutputFormats:       []string{"jsonl", "console"},
			JSONOutput:          true,
			DeferredJSONLExport: true,
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		if w.outputFile == nil {
			t.Error("expected a live output file for the console format")
		}
		if w.DisableStdout {
			t.Error("expected console live stdout to remain enabled")
		}
	})

	t.Run("jsonl+console with .jsonl -o routes console to its own path (no collision)", func(t *testing.T) {
		dir := t.TempDir()
		// -o ends in .jsonl: the deferred jsonl export will write here, so the
		// live console file must NOT also open this exact path.
		opts := &types.Options{
			Output:              filepath.Join(dir, "out.jsonl"),
			OutputFormats:       []string{"jsonl", "console"},
			JSONOutput:          true,
			DeferredJSONLExport: true,
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		// The console live file must land on the console-format path (bare base),
		// leaving out.jsonl free for the post-scan deferred export.
		if _, statErr := os.Stat(filepath.Join(dir, "out")); statErr != nil {
			t.Errorf("expected console live file at the console path %q: %v", filepath.Join(dir, "out"), statErr)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "out.jsonl")); statErr == nil {
			t.Error("live writer must NOT open the .jsonl path reserved for the deferred export")
		}
	})

	t.Run("captured-console keeps the live finding stream on stdout", func(t *testing.T) {
		// The -P/--parallel fan-out captures each child's stdout/stderr to a
		// per-target <output>.console.log. CapturedConsole keeps the live finding
		// stream alive (the captured file is the record), even though jsonl is
		// deferred and console is not among the formats. No extra live file is
		// opened — the findings simply stream to the captured stdout.
		opts := &types.Options{
			Output:              filepath.Join(t.TempDir(), "out.jsonl"),
			OutputFormats:       []string{"jsonl", "html"},
			JSONOutput:          true, // set by reconcileOutputFormats for any jsonl format
			DeferredJSONLExport: true,
			CapturedConsole:     true,
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		if w.DisableStdout {
			t.Error("expected live stdout kept enabled under CapturedConsole")
		}
		if w.outputFile != nil {
			t.Error("did not expect an extra live output file under CapturedConsole (findings go to captured stdout)")
		}
		if w.JSONOutput {
			t.Error("expected human-readable console rendering (not raw JSON) under CapturedConsole")
		}
	})

	t.Run("captured-console still honors --silent", func(t *testing.T) {
		// Silent is authoritative: a captured child run with --silent stays quiet.
		opts := &types.Options{
			Output:              filepath.Join(t.TempDir(), "out.jsonl"),
			OutputFormats:       []string{"jsonl", "html"},
			DeferredJSONLExport: true,
			CapturedConsole:     true,
			Silent:              true,
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		if !w.DisableStdout {
			t.Error("expected stdout suppressed when --silent is set, even with CapturedConsole")
		}
	})

	t.Run("legacy jsonl (CI) keeps the live file", func(t *testing.T) {
		opts := &types.Options{
			Output:              filepath.Join(t.TempDir(), "ci.jsonl"),
			OutputFormats:       []string{"jsonl"},
			JSONOutput:          true,
			DeferredJSONLExport: false, // CI output keeps its own emitter
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		if w.outputFile == nil {
			t.Error("expected the legacy live jsonl file to be created")
		}
	})

	t.Run("console-only is unaffected", func(t *testing.T) {
		opts := &types.Options{
			Output:        filepath.Join(t.TempDir(), "out.txt"),
			OutputFormats: []string{"console"},
		}
		w, err := NewStandardWriter(opts)
		if err != nil {
			t.Fatalf("NewStandardWriter: %v", err)
		}
		defer w.Close()
		if w.outputFile == nil {
			t.Error("expected a live console output file")
		}
		if w.DisableStdout {
			t.Error("did not expect stdout suppressed for console")
		}
	})
}
