package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeKBFile is a tiny helper for seeding a knowledge-base tree in tests.
func writeKBFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestGatherKnowledgeBaseDocs_Directory(t *testing.T) {
	dir := t.TempDir()
	writeKBFile(t, dir, "auth.md", "# Authentication model\n\nThree roles: guest, user, admin.")
	writeKBFile(t, dir, "login.md", "---\ndescription: How to log in as each role\n---\n\nPOST /login")
	writeKBFile(t, dir, "notes.txt", "Plain text notes about the app.")
	writeKBFile(t, dir, "sub/business.md", "Business logic for orders.")
	// Non-text + skipped-dir + binary content must be ignored.
	writeKBFile(t, dir, "diagram.png", "not really a png")
	writeKBFile(t, dir, "node_modules/pkg/readme.md", "dependency doc, must be skipped")
	writeKBFile(t, dir, "bin.md", "text\x00with-nul-byte")

	root, docs, isDir, err := gatherKnowledgeBaseDocs(dir, false)
	require.NoError(t, err)
	require.True(t, isDir)
	require.Equal(t, dir, root)

	got := make([]string, len(docs))
	for i, d := range docs {
		got[i] = d.RelPath
		require.True(t, filepath.IsAbs(d.AbsPath), "AbsPath must be absolute: %s", d.AbsPath)
	}
	// Sorted, text-only, node_modules/binary/png excluded.
	require.Equal(t, []string{"auth.md", "login.md", "notes.txt", "sub/business.md"}, got)

	// Frontmatter description wins for login.md; heading for auth.md.
	byRel := map[string]kbDoc{}
	for _, d := range docs {
		byRel[d.RelPath] = d
	}
	require.Equal(t, "How to log in as each role", byRel["login.md"].Description)
	require.Equal(t, "Authentication model", byRel["auth.md"].Description)
}

func TestGatherKnowledgeBaseDocs_SingleFile(t *testing.T) {
	dir := t.TempDir()
	p := writeKBFile(t, dir, "kb.md", "# Single doc\n\nContent.")

	root, docs, isDir, err := gatherKnowledgeBaseDocs(p, false)
	require.NoError(t, err)
	require.False(t, isDir)
	require.Equal(t, p, root)
	require.Len(t, docs, 1)
	require.Equal(t, "kb.md", docs[0].RelPath)
	require.Equal(t, "Single doc", docs[0].Description)
}

func TestGatherKnowledgeBaseDocs_MissingPath(t *testing.T) {
	_, _, _, err := gatherKnowledgeBaseDocs(filepath.Join(t.TempDir(), "nope"), false)
	require.Error(t, err)
}

func TestDeriveKBDescription(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"frontmatter description", "---\ndescription: The auth flow\ntitle: x\n---\nbody", "The auth flow"},
		{"frontmatter summary", "---\nsummary: \"Roles overview\"\n---\nbody", "Roles overview"},
		{"heading", "## Login procedure\nstuff", "Login procedure"},
		{"first prose line", "Just some notes here.\nmore", "Just some notes here."},
		{"frontmatter without desc falls through to heading", "---\ntitle: x\n---\n# Real heading\n", "Real heading"},
		{"empty", "   \n\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, deriveKBDescription(c.in))
		})
	}
}

func TestBoundKBCorpus_CapsAndCountsOmitted(t *testing.T) {
	big := strings.Repeat("x", kbMaxFileChars)
	// Enough docs that the total blows past kbMaxTotalChars.
	n := (kbMaxTotalChars / kbMaxFileChars) + 3
	docs := make([]kbDoc, n)
	for i := range docs {
		docs[i] = kbDoc{RelPath: "d.md", Content: big}
	}
	corpus, omitted := boundKBCorpus(docs)
	require.NotEmpty(t, corpus)
	require.Greater(t, omitted, 0, "some docs must be omitted once the cap is hit")
	require.LessOrEqual(t, len(corpus), kbMaxTotalChars+2*kbMaxFileChars, "corpus stays roughly bounded")

	// A small set fits entirely — nothing omitted.
	_, omitted2 := boundKBCorpus([]kbDoc{{RelPath: "a.md", Content: "short"}})
	require.Equal(t, 0, omitted2)
}

func TestRenderKnowledgeBaseSection(t *testing.T) {
	docs := []kbDoc{
		{RelPath: "auth.md", AbsPath: "/kb/auth.md", Description: "Auth model"},
		{RelPath: "login.md", AbsPath: "/kb/login.md", Description: "Login flow"},
	}

	t.Run("with summary keeps file list terse", func(t *testing.T) {
		out := renderKnowledgeBaseSection("/kb", true, "**Auth model**\nguest/user/admin", docs)
		require.Contains(t, out, "## Operator-supplied reference documentation")
		require.Contains(t, out, "Consult it before authenticating")
		require.Contains(t, out, "**Knowledge base directory:** `/kb`")
		require.Contains(t, out, "**Auth model**")
		require.Contains(t, out, "- `/kb/auth.md`")
		// Summary present → descriptions omitted from the list.
		require.NotContains(t, out, "- `/kb/auth.md` — Auth model")
	})

	t.Run("without summary the index carries descriptions", func(t *testing.T) {
		out := renderKnowledgeBaseSection("/kb/single.md", false, "", docs)
		require.Contains(t, out, "**Knowledge base file:** `/kb/single.md`")
		require.Contains(t, out, "- `/kb/auth.md` — Auth model")
		require.Contains(t, out, "- `/kb/login.md` — Login flow")
	})
}

// TestBuildKnowledgeBaseSection_RawAndCache exercises the orchestrator without
// an LLM: raw mode renders a deterministic index, writes the artifact, and a
// subsequent non-raw call reuses that cached artifact (prov is nil, so no
// distillation could run).
func TestBuildKnowledgeBaseSection_RawAndCache(t *testing.T) {
	kbDir := t.TempDir()
	writeKBFile(t, kbDir, "auth.md", "# Auth model\nroles")
	writeKBFile(t, kbDir, "login.md", "---\ndescription: Login flow\n---\nPOST /login")
	sessionDir := t.TempDir()

	var buf bytes.Buffer
	section, err := buildKnowledgeBaseSection(context.Background(), nil, "", kbDir, true, sessionDir, &buf, false)
	require.NoError(t, err)
	require.Contains(t, section, "## Operator-supplied reference documentation")
	require.Contains(t, section, "- `"+filepath.Join(kbDir, "auth.md")+"` — Auth model")
	require.Contains(t, buf.String(), "raw — no LLM distillation")

	// Artifact was written for provenance / resume.
	artifact := filepath.Join(sessionDir, knowledgeBaseArtifact)
	data, rerr := os.ReadFile(artifact)
	require.NoError(t, rerr)
	require.Contains(t, string(data), "Operator-supplied reference documentation")

	// Non-raw call with a nil provider reuses the cached artifact rather than
	// attempting (impossible) distillation.
	var buf2 bytes.Buffer
	section2, err := buildKnowledgeBaseSection(context.Background(), nil, "", kbDir, false, sessionDir, &buf2, false)
	require.NoError(t, err)
	require.Equal(t, strings.TrimRight(string(data), "\n"), section2)
	require.Contains(t, buf2.String(), "reusing cached brief")
}

// TestBuildKnowledgeBaseSection_DistillFallback verifies that a non-raw run with
// no usable provider degrades to the deterministic document index instead of
// failing.
func TestBuildKnowledgeBaseSection_DistillFallback(t *testing.T) {
	kbDir := t.TempDir()
	writeKBFile(t, kbDir, "auth.md", "# Auth model\nroles")

	var buf bytes.Buffer
	// Fresh session dir → no cache; nil provider → distill returns false.
	section, err := buildKnowledgeBaseSection(context.Background(), nil, "", kbDir, false, t.TempDir(), &buf, false)
	require.NoError(t, err)
	require.Contains(t, section, "- `"+filepath.Join(kbDir, "auth.md")+"` — Auth model")
	require.Contains(t, buf.String(), "falling back to a document index")
}

func TestBuildKnowledgeBaseSection_EmptyDir(t *testing.T) {
	var buf bytes.Buffer
	section, err := buildKnowledgeBaseSection(context.Background(), nil, "", t.TempDir(), true, t.TempDir(), &buf, false)
	require.NoError(t, err)
	require.Empty(t, section)
	require.Contains(t, buf.String(), "no readable text documents")
}
