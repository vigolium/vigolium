package output

import (
	"github.com/vigolium/vigolium/pkg/output/formats"
)

// The output format table lives in the leaf package pkg/output/formats, because
// pkg/types (which this package imports) derives FormatOutputPath from it. This
// file binds the report renderers to those names, so every command surface —
// scan --format, export, import, REST output_formats, db export — resolves a
// format and its renderer through one Lookup.

// Kind and Surface re-export the table's types so callers need one import.
type (
	Kind    = formats.Kind
	Surface = formats.Surface
)

const (
	KindStream = formats.KindStream
	KindReport = formats.KindReport
	KindStore  = formats.KindStore
	KindDir    = formats.KindDir

	SurfaceScan     = formats.SurfaceScan
	SurfaceExport   = formats.SurfaceExport
	SurfaceImport   = formats.SurfaceImport
	SurfaceREST     = formats.SurfaceREST
	SurfaceDBExport = formats.SurfaceDBExport
)

// ReportRenderer renders a materialized item set (the unified {type,data}
// export envelopes) to outputPath.
type ReportRenderer func(items []any, outputPath string, meta HTMLReportMeta) error

// StreamReportRenderer renders by pulling items one at a time from a producer,
// so the result set never lives in memory at once.
type StreamReportRenderer func(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error

// OutputFormat is one table row plus the renderer bound to it. Render is nil
// for stream, store and directory kinds, which each command materializes itself.
type OutputFormat struct {
	formats.Format
	Render       ReportRenderer
	RenderStream StreamReportRenderer
	// DefaultTitle is the report title when the caller sets none.
	DefaultTitle string
}

type reportBinding struct {
	render       ReportRenderer
	renderStream StreamReportRenderer
	defaultTitle string
}

const defaultReportTitle = "Vigolium Scan Report"

// reportRenderers binds every KindReport format to its renderer.
// TestFormatRegistryRenderers keeps this map and the table in lockstep.
var reportRenderers = map[string]reportBinding{
	"html":     {render: GenerateHTMLReport, renderStream: GenerateHTMLReportStreaming, defaultTitle: "Vigolium Static Report"},
	"report":   {render: GenerateDocumentReport, defaultTitle: defaultReportTitle},
	"pdf":      {render: GeneratePDFReport, defaultTitle: defaultReportTitle},
	"markdown": {render: GenerateMarkdownReport, defaultTitle: defaultReportTitle},
	"sarif":    {render: GenerateSARIFReport, defaultTitle: defaultReportTitle},
	"csv":      {render: GenerateCSVReport, defaultTitle: defaultReportTitle},
	"junit":    {render: GenerateJUnitReport, defaultTitle: defaultReportTitle},
	"github":   {render: GenerateGitHubAnnotations, defaultTitle: defaultReportTitle},
}

func bind(f formats.Format) OutputFormat {
	of := OutputFormat{Format: f}
	if b, ok := reportRenderers[f.Name]; ok {
		of.Render, of.RenderStream, of.DefaultTitle = b.render, b.renderStream, b.defaultTitle
	}
	return of
}

// Lookup resolves a --format token (alias-aware, case-insensitive) to a format
// the surface accepts, with its renderer bound. The error is a
// *formats.UnknownFormatError whose message lists Names(surface).
func Lookup(name string, s Surface) (OutputFormat, error) {
	f, err := formats.Lookup(name, s)
	if err != nil {
		return OutputFormat{}, err
	}
	return bind(f), nil
}

// FormatByName returns the format a token names regardless of surface, with
// its renderer bound.
func FormatByName(token string) (OutputFormat, bool) {
	f, ok := formats.Get(token)
	if !ok {
		return OutputFormat{}, false
	}
	return bind(f), true
}

// FormatByExtension returns the format a file name's extension names on
// surface s (formats.ByExtension), with its renderer bound.
func FormatByExtension(path string, s Surface) (OutputFormat, bool) {
	f, ok := formats.ByExtension(path, s)
	if !ok {
		return OutputFormat{}, false
	}
	return bind(f), true
}

// Names lists the canonical format names a surface accepts, in table order.
func Names(s Surface) []string { return formats.Names(s) }

// FormatsHelp renders a surface's format list for --format help text.
func FormatsHelp(s Surface) string { return formats.Help(s) }

// CanonicalFormat resolves a token to its canonical name (unknown tokens come
// back lowercased).
func CanonicalFormat(token string) string { return formats.Canonical(token) }

// ReportFormats returns every KindReport format the surface accepts, in table
// order, with renderers bound — the post-run reports a command renders from the
// finished result set.
func ReportFormats(s Surface) []OutputFormat {
	var out []OutputFormat
	for _, f := range formats.All() {
		if f.Kind == KindReport && f.Surfaces&s != 0 {
			out = append(out, bind(f))
		}
	}
	return out
}
