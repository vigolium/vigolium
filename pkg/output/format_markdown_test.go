package output

import (
	"strings"
	"testing"
)

func TestStripLeadingH1(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "leading h1 stripped",
			body: "# C7 — single-dek-no-rotation\n\n## Summary\nbody\n",
			want: "## Summary\nbody\n",
		},
		{
			name: "leading blank lines consumed",
			body: "\n\n# Title\nrest\n",
			want: "rest\n",
		},
		{
			name: "h1 stripped even when text differs from title",
			body: "# C1 — Double COLLECT_FUND Trigger\nbody\n",
			want: "body\n",
		},
		{
			name: "no h1 returns body unchanged",
			body: "## Summary\nbody\n",
			want: "## Summary\nbody\n",
		},
		{
			name: "lone h1 with no body returns empty",
			body: "# Only heading",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripLeadingH1(tc.body)
			if got != tc.want {
				t.Errorf("stripLeadingH1 = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDemoteHeadings(t *testing.T) {
	in := "## Summary\ntext\n\n### Sub\n\n```bash\n# not a heading\n## also not\n```\n\n## Details\n"
	want := "#### Summary\ntext\n\n##### Sub\n\n```bash\n# not a heading\n## also not\n```\n\n#### Details\n"
	if got := demoteHeadings(in, 2); got != want {
		t.Errorf("demoteHeadings mismatch\nwant: %q\ngot:  %q", want, got)
	}
}

func TestDemoteHeadingsCapsAtH6(t *testing.T) {
	in := "##### Deep\n###### Already six\n"
	got := demoteHeadings(in, 2)
	if !strings.Contains(got, "###### Deep") || !strings.Contains(got, "###### Already six") {
		t.Errorf("expected headings capped at h6, got %q", got)
	}
}

func TestDemoteHeadingsTildeFence(t *testing.T) {
	in := "## Header\n~~~\n## inside fence\n~~~\n## After\n"
	want := "#### Header\n~~~\n## inside fence\n~~~\n#### After\n"
	if got := demoteHeadings(in, 2); got != want {
		t.Errorf("tilde fence not respected\nwant: %q\ngot:  %q", want, got)
	}
}

func TestNormalizeFindingBody(t *testing.T) {
	body := "# C7 — single-dek-no-rotation\n\n## Summary\n\nDetails here.\n\n## Impact\n"
	got := normalizeFindingBody(body)
	if strings.Contains(got, "# C7") {
		t.Errorf("expected leading h1 stripped, got %q", got)
	}
	if !strings.Contains(got, "#### Summary") || !strings.Contains(got, "#### Impact") {
		t.Errorf("expected headings demoted to h4, got %q", got)
	}
}

func TestFindingHeadingSlug(t *testing.T) {
	cases := []struct {
		id    int
		title string
		want  string
	}{
		{14, "api-key-guard-fail-open-unset-env", "14-api-key-guard-fail-open-unset-env"},
		{7, "single-dek-no-rotation", "7-single-dek-no-rotation"},
		{1, "p5b-001-collect-fund-double-trigger", "1-p5b-001-collect-fund-double-trigger"},
		{42, "XSS — https://example.com/?q=1", "42-xss-httpsexamplecomq1"},
		{3, "  Spaced   Title  ", "3-spaced-title"},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			if got := findingHeadingSlug(tc.id, tc.title); got != tc.want {
				t.Errorf("findingHeadingSlug(%d, %q) = %q, want %q", tc.id, tc.title, got, tc.want)
			}
		})
	}
}

func TestWriteMarkdownTOCGroup(t *testing.T) {
	w := &strings.Builder{}
	findings := []ReportFinding{
		{ID: 14, Title: "api-key-guard-fail-open-unset-env"},
		{ID: 7, Title: "single-dek-no-rotation"},
	}
	writeMarkdownTOCGroup(w, "Critical", "critical-findings", findings)
	got := w.String()
	want := "- [Critical Findings (2)](#critical-findings)\n" +
		"  - [#14 api-key-guard-fail-open-unset-env](#14-api-key-guard-fail-open-unset-env)\n" +
		"  - [#7 single-dek-no-rotation](#7-single-dek-no-rotation)\n"
	if got != want {
		t.Errorf("TOC group mismatch\nwant: %q\ngot:  %q", want, got)
	}
}

func TestWriteMarkdownTOCGroupEmpty(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownTOCGroup(w, "Low", "low-findings", nil)
	if w.String() != "" {
		t.Errorf("expected no output for empty group, got %q", w.String())
	}
}
