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
