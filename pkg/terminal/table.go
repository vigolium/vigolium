package terminal

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

// Table renders data using tablewriter with Unicode box-drawing characters.
type Table struct {
	headers     []string
	rows        [][]string
	MaxColWidth int         // if > 0, caps each column's content width
	wrapMode    int         // 0 = default (WrapTruncate), tw.WrapNormal for word-wrap
	colWidths   map[int]int // per-column widths (0-indexed); overrides MaxColWidth when set
}

// NewTable creates a new table with the given column headers.
// Headers are auto-normalized: first character capitalized, rest lowercase.
func NewTable(headers ...string) *Table {
	normalized := make([]string, len(headers))
	for i, h := range headers {
		normalized[i] = normalizeHeader(h)
	}
	return &Table{
		headers: normalized,
	}
}

// NewTableWithMaxWidth creates a new table with a maximum column width.
// Columns wider than maxColWidth will be truncated during rendering.
func NewTableWithMaxWidth(maxColWidth int, headers ...string) *Table {
	t := NewTable(headers...)
	t.MaxColWidth = maxColWidth
	return t
}

// NewTableFullWidth creates a table sized to fill the given terminal width.
// Long content word-wraps instead of truncating. The termWidth is the total
// terminal width in columns (use TerminalWidth() to auto-detect).
func NewTableFullWidth(termWidth int, headers ...string) *Table {
	t := NewTable(headers...)
	numCols := len(headers)
	if numCols == 0 {
		numCols = 1
	}
	// Each column border/padding takes ~3 chars, plus outer borders ~2
	overhead := numCols*3 + 2
	usable := max(termWidth-overhead, numCols)
	t.MaxColWidth = usable / numCols
	t.wrapMode = tw.WrapNormal
	return t
}

// NewTableFullWidthWeighted creates a table sized to fill the given terminal width,
// distributing usable space proportionally by the given weights (one per column).
// Columns with higher weights get more space. Long content word-wraps.
func NewTableFullWidthWeighted(termWidth int, weights []int, headers ...string) *Table {
	t := NewTable(headers...)
	numCols := len(headers)
	if numCols == 0 {
		numCols = 1
	}
	// Each column border/padding takes ~3 chars, plus outer borders ~2
	overhead := numCols*3 + 2
	usable := max(termWidth-overhead, numCols)

	// Sum weights (use 1 as default for missing/zero weights)
	totalWeight := 0
	for i := 0; i < numCols; i++ {
		w := 1
		if i < len(weights) && weights[i] > 0 {
			w = weights[i]
		}
		totalWeight += w
	}

	t.colWidths = make(map[int]int, numCols)
	assigned := 0
	for i := 0; i < numCols; i++ {
		w := 1
		if i < len(weights) && weights[i] > 0 {
			w = weights[i]
		}
		colW := usable * w / totalWeight
		if colW < 1 {
			colW = 1
		}
		t.colWidths[i] = colW
		assigned += colW
	}
	// Distribute rounding remainder to the widest-weighted column
	if remainder := usable - assigned; remainder > 0 {
		bestIdx := 0
		for i := 1; i < numCols; i++ {
			if t.colWidths[i] > t.colWidths[bestIdx] {
				bestIdx = i
			}
		}
		t.colWidths[bestIdx] += remainder
	}

	t.wrapMode = tw.WrapNormal
	return t
}

// normalizeHeader capitalizes the first character and lowercases the rest.
func normalizeHeader(s string) string {
	if s == "" {
		return s
	}
	lower := strings.ToLower(s)
	r, size := utf8.DecodeRuneInString(lower)
	if r == utf8.RuneError {
		return lower
	}
	return string(unicode.ToUpper(r)) + lower[size:]
}

// AddRow appends a data row to the table. Values are converted to strings via fmt.Sprint.
func (t *Table) AddRow(values ...any) {
	row := make([]string, len(values))
	for i, v := range values {
		row[i] = fmt.Sprint(v)
	}
	t.rows = append(t.rows, row)
}

// renderTo writes the table to the given writer using tablewriter.
func (t *Table) renderTo(w *bytes.Buffer) {
	if len(t.headers) == 0 {
		return
	}

	opts := []tablewriter.Option{
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithTrimSpace(tw.On),
	}

	if len(t.colWidths) > 0 {
		wrap := tw.WrapTruncate
		if t.wrapMode != 0 {
			wrap = t.wrapMode
		}
		widths := tw.NewMapper[int, int]()
		for col, w := range t.colWidths {
			widths.Set(col, w)
		}
		opts = append(opts,
			tablewriter.WithRowAutoWrap(wrap),
			tablewriter.WithColumnWidths(widths),
		)
	} else if t.MaxColWidth > 0 {
		wrap := tw.WrapTruncate
		if t.wrapMode != 0 {
			wrap = t.wrapMode
		}
		opts = append(opts,
			tablewriter.WithRowAutoWrap(wrap),
			tablewriter.WithRowMaxWidth(t.MaxColWidth),
			tablewriter.WithHeaderMaxWidth(t.MaxColWidth),
		)
	}

	tbl := tablewriter.NewTable(w, opts...)
	tbl.Header(t.headers)
	for _, row := range t.rows {
		_ = tbl.Append(row)
	}
	_ = tbl.Render()
}

// Render returns the table as a string.
func (t *Table) Render() string {
	if len(t.headers) == 0 {
		return ""
	}
	var buf bytes.Buffer
	t.renderTo(&buf)
	return buf.String()
}

// Print renders the table directly to stdout.
func (t *Table) Print() {
	if len(t.headers) == 0 {
		return
	}
	var buf bytes.Buffer
	t.renderTo(&buf)
	_, _ = os.Stdout.Write(buf.Bytes())
}
