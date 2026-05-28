package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

type bundleManifest struct {
	VigoliumVersion string         `json:"vigolium_version"`
	GeneratedAt     string         `json:"generated_at"`
	BundleRoot      string         `json:"bundle_root"`
	ItemCounts      map[string]int `json:"item_counts"`
	TotalItems      int            `json:"total_items"`
	Sessions        []string       `json:"sessions,omitempty"`
	Filters         bundleFilters  `json:"filters"`
	Report          struct {
		Title       string `json:"title,omitempty"`
		Target      string `json:"target,omitempty"`
		Duration    string `json:"duration,omitempty"`
		GeneratedAt string `json:"generated_at,omitempty"`
	} `json:"report"`
}

type bundleFilters struct {
	Only         []string `json:"only,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
	OmitResponse bool     `json:"omit_response,omitempty"`
	Search       string   `json:"search,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Limit        int      `json:"limit,omitempty"`
}

func runExportBundle() error {
	db, err := getDB()
	if err != nil {
		return err
	}
	defer closeDatabaseOnExit()

	ctx := context.Background()
	items, err := queryExportData(ctx, db, topExportOmitResponse, "")
	if err != nil {
		return err
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	meta := resolveBundleReportMeta(ctx, db)

	root := bundleRootName(topExportOutput)

	out, err := os.Create(topExportOutput)
	if err != nil {
		return fmt.Errorf("failed to create bundle file: %w", err)
	}
	defer func() { _ = out.Close() }()

	gz := gzip.NewWriter(out)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	now := time.Now().UTC()

	if err := writeTarDir(tw, root+"/", now); err != nil {
		return err
	}

	jsonlBytes, err := encodeItemsAsJSONL(items)
	if err != nil {
		return err
	}
	if err := writeTarBytes(tw, root+"/export.jsonl", jsonlBytes, now); err != nil {
		return err
	}

	htmlBytes, err := renderHTMLToBytes(items, meta)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to render HTML for bundle: %v\n", terminal.WarningSymbol(), err)
	} else {
		if err := writeTarBytes(tw, root+"/report.html", htmlBytes, now); err != nil {
			return err
		}
	}

	includedSessions, err := writeSessionsToTar(tw, root, settings.Agent.EffectiveSessionsDir(), topExportScanUUIDs, now)
	if err != nil {
		return err
	}

	manifest := bundleManifest{
		VigoliumVersion: getVersion(),
		GeneratedAt:     now.Format(time.RFC3339),
		BundleRoot:      root,
		ItemCounts:      countItemsByType(items),
		TotalItems:      len(items),
		Sessions:        includedSessions,
		Filters: bundleFilters{
			Only:         topExportOnly,
			Exclude:      topExportExclude,
			OmitResponse: topExportOmitResponse,
			Search:       topExportSearch,
			Severity:     topExportSeverity,
			Limit:        topExportLimit,
		},
	}
	manifest.Report.Title = meta.Title
	manifest.Report.Target = meta.ScanTarget
	manifest.Report.Duration = meta.ScanDuration
	manifest.Report.GeneratedAt = meta.GeneratedAt

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := writeTarBytes(tw, root+"/manifest.json", manifestBytes, now); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	printExportStats("bundle", topExportOutput, items)
	if len(includedSessions) > 0 {
		fmt.Fprintf(os.Stderr, "  Sessions:           %d included\n", len(includedSessions))
	}
	return nil
}

// bundleRootName returns the top-level directory inside the tarball, derived
// from the output path basename minus its archive extension.
func bundleRootName(outputPath string) string {
	base := filepath.Base(outputPath)
	switch {
	case strings.HasSuffix(base, ".tar.gz"):
		base = strings.TrimSuffix(base, ".tar.gz")
	case strings.HasSuffix(base, ".tgz"):
		base = strings.TrimSuffix(base, ".tgz")
	}
	if base == "" {
		base = "vigolium-bundle"
	}
	return base
}

// resolveBundleReportMeta picks report metadata, preferring a single matching
// agentic_scan when --scan-uuid resolves to exactly one row. Falls back to
// computeReportMeta and CLI overrides.
func resolveBundleReportMeta(ctx context.Context, db *database.DB) output.HTMLReportMeta {
	title := "Vigolium Scan Report"
	if topExportTitle != "" {
		title = topExportTitle
	}

	autoTarget, autoDuration := computeReportMeta(ctx, db)

	if len(topExportScanUUIDs) == 1 {
		var scan database.AgenticScan
		err := db.NewSelect().Model(&scan).
			Where("uuid = ?", topExportScanUUIDs[0]).
			Limit(1).
			Scan(ctx)
		if err == nil && scan.UUID != "" {
			if scan.TargetURL != "" {
				autoTarget = scan.TargetURL
			}
			if scan.DurationMs > 0 {
				d := time.Duration(scan.DurationMs) * time.Millisecond
				autoDuration = d.Round(time.Second).String()
			}
		}
	}

	target := autoTarget
	if topExportTarget != "" {
		target = topExportTarget
	}
	duration := autoDuration
	if topExportDuration != "" {
		duration = topExportDuration
	}

	return output.HTMLReportMeta{
		Title:           title,
		Version:         getVersion(),
		ScanDuration:    duration,
		ScanTarget:      target,
		GeneratedAt:     topExportGeneratedAt,
		ReportSharedURL: topExportReportURL,
	}
}

func encodeItemsAsJSONL(items []any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return nil, fmt.Errorf("failed to encode jsonl record: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// renderHTMLToBytes calls output.GenerateHTMLReport with a temp file, reads
// the bytes back, and removes the temp. Avoids refactoring the HTML generator.
func renderHTMLToBytes(items []any, meta output.HTMLReportMeta) ([]byte, error) {
	tmp, err := os.CreateTemp("", "vigolium-bundle-html-*.html")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := output.GenerateHTMLReport(items, tmpPath, meta); err != nil {
		return nil, err
	}
	return os.ReadFile(tmpPath)
}

func countItemsByType(items []any) map[string]int {
	counts := make(map[string]int)
	for _, item := range items {
		if env, ok := item.(exportEnvelope); ok {
			counts[env.Type]++
		}
	}
	return counts
}

// writeSessionsToTar copies each requested session dir into the tarball under
// <root>/sessions/<uuid>/. Missing dirs are warned-and-skipped. Returns the
// list of session UUIDs actually included.
func writeSessionsToTar(tw *tar.Writer, root, sessionsBase string, requested []string, mtime time.Time) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	if sessionsBase == "" {
		fmt.Fprintf(os.Stderr, "%s Sessions directory not configured; skipping --scan-uuid entries\n", terminal.WarningSymbol())
		return nil, nil
	}

	if err := writeTarDir(tw, root+"/sessions/", mtime); err != nil {
		return nil, err
	}

	var included []string
	for _, id := range requested {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		src := filepath.Join(sessionsBase, id)
		info, err := os.Stat(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Session %s not found at %s; skipping\n", terminal.WarningSymbol(), id, src)
			continue
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "%s Session path %s is not a directory; skipping\n", terminal.WarningSymbol(), src)
			continue
		}
		prefix := root + "/sessions/" + id
		if err := walkAndTar(tw, src, prefix); err != nil {
			return nil, fmt.Errorf("failed to add session %s: %w", id, err)
		}
		included = append(included, id)
	}
	return included, nil
}

// walkAndTar walks src and writes every regular file and directory entry
// into tw under the given prefix path.
func walkAndTar(tw *tar.Writer, src, prefix string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		var name string
		if rel == "." {
			name = prefix + "/"
		} else {
			name = prefix + "/" + filepath.ToSlash(rel)
		}

		mode := info.Mode()
		switch {
		case mode.IsDir():
			return writeTarDir(tw, strings.TrimSuffix(name, "/")+"/", info.ModTime())
		case mode.IsRegular():
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			hdr := &tar.Header{
				Name:    name,
				Mode:    int64(mode.Perm()),
				Size:    info.Size(),
				ModTime: info.ModTime(),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
			return nil
		default:
			return nil
		}
	})
}

func writeTarDir(tw *tar.Writer, name string, mtime time.Time) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		ModTime:  mtime,
	}
	return tw.WriteHeader(hdr)
}

func writeTarBytes(tw *tar.Writer, name string, data []byte, mtime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: mtime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	return nil
}
