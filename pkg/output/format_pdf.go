package output

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-rod/rod/lib/launcher"
)

func GeneratePDFReport(items []any, outputPath string, meta HTMLReportMeta) error {
	chromePath, found := launcher.LookPath()
	if !found {
		return fmt.Errorf("Chrome/Chromium not found; install Google Chrome or Chromium to export PDF")
	}

	tmpDir, err := os.MkdirTemp("", "vigolium-pdf-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := GenerateDocumentReport(items, htmlPath, meta); err != nil {
		return fmt.Errorf("failed to generate HTML for PDF: %w", err)
	}

	absOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("failed to resolve output path: %w", err)
	}

	cmd := exec.Command(chromePath,
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-software-rasterizer",
		"--run-all-compositor-stages-before-draw",
		"--no-pdf-header-footer",
		"--virtual-time-budget=5000",
		"--print-to-pdf="+absOutput,
		"file://"+htmlPath,
	)
	// Suppress Chrome's noisy stderr (allocator warnings, GCM errors, etc.)
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chrome PDF export failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  Note: PDF styling may differ slightly from the browser view.\n")
	fmt.Fprintf(os.Stderr, "  For the best visual experience, use --format html or --format report.\n")

	return nil
}
