package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// --knowledge-base folds operator-supplied reference documentation (how the app
// authenticates, its roles/privilege tiers, business logic) into the autopilot
// operator's opening brief. The design is read-on-demand, mirroring --source:
// the full documents stay on disk, and only a compact LLM-distilled summary plus
// an authoritative document index are inlined — so a directory of many markdown
// files never floods the context window. The agent reads the specific file with
// read_file/grep when it needs detail.

const (
	// knowledgeBaseArtifact is the distilled brief written to the session dir
	// for provenance and --resume reuse (so a resumed run doesn't re-pay the
	// distiller LLM call).
	knowledgeBaseArtifact = "knowledge-base-brief.md"

	// Caps keep the distiller's INPUT bounded regardless of KB size. The brief
	// it emits is small either way; these only stop a huge docs tree from
	// blowing the distiller's own context. Documents omitted from the corpus
	// still appear in the on-demand file index, so nothing is lost — the agent
	// can read them directly.
	kbMaxFiles         = 200   // hard ceiling on indexed documents
	kbMaxFileChars     = 8000  // per-file content fed to the distiller
	kbMaxTotalChars    = 48000 // total content fed to the distiller in one call
	kbDescriptionChars = 140   // deterministic per-file description length
	kbDistillTimeout   = 120 * time.Second
)

// kbTextExtensions are the file types gathered from a knowledge-base directory.
// Everything else (PDFs, images, binaries) is skipped from the text index — the
// agent can still read those on demand, they just don't belong in the corpus.
var kbTextExtensions = map[string]bool{
	".md":       true,
	".markdown": true,
	".mdx":      true,
	".txt":      true,
	".rst":      true,
	".adoc":     true,
}

// kbSkipDirs are directory names never worth walking for app-logic docs.
var kbSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".vigolium":    true,
}

// kbDoc is one gathered knowledge-base document.
type kbDoc struct {
	RelPath     string // path relative to the KB root (basename for a single file)
	AbsPath     string // absolute path the agent passes to read_file
	Content     string // file content, capped at kbMaxFileChars
	Description string // deterministic one-line description (frontmatter/heading/first line)
}

// gatherKnowledgeBaseDocs walks a knowledge-base path (a single file or a
// directory tree) and returns the text documents it contains, each with a
// deterministic one-line description. rootAbs is the absolute KB root; isDir
// reports whether it was a directory. Non-text and binary files are skipped.
// Documents are returned in a stable (relpath-sorted) order so re-runs and the
// on-disk artifact are reproducible.
//
// When routeTraffic is true, files recognized as HTTP-traffic exports (curl,
// raw HTTP, URL lists — the only traffic shapes that can wear a prose text
// extension) are also skipped here, because the traffic loader
// (ingestKnowledgeBaseTraffic) parses them into real http_records instead. With
// routeTraffic false every text file stays prose (the --knowledge-base-no-traffic
// behavior), so a capture is never silently dropped from both paths.
func gatherKnowledgeBaseDocs(kbPath string, routeTraffic bool) (rootAbs string, docs []kbDoc, isDir bool, err error) {
	rootAbs, err = filepath.Abs(kbPath)
	if err != nil {
		return "", nil, false, err
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		return "", nil, false, err
	}

	if !info.IsDir() {
		// A single-file KB that is itself a traffic export is handled entirely by
		// the traffic loader; return no prose docs (not an error) so the caller
		// degrades to the traffic section alone.
		if routeTraffic {
			if _, ok := kbTrafficFormat(rootAbs); ok {
				return rootAbs, nil, false, nil
			}
		}
		doc, ok := readKBFile(rootAbs, filepath.Base(rootAbs))
		if !ok {
			return rootAbs, nil, false, fmt.Errorf("%s is not a readable text document", rootAbs)
		}
		return rootAbs, []kbDoc{doc}, false, nil
	}

	walkErr := filepath.WalkDir(rootAbs, func(path string, d os.DirEntry, we error) error {
		if we != nil {
			return nil // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if path != rootAbs && kbSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(docs) >= kbMaxFiles {
			return nil
		}
		if !kbTextExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		// A text file whose content is actually a curl/raw-HTTP/URL-list capture
		// belongs to the traffic path, not the prose corpus.
		if routeTraffic {
			if _, ok := kbTrafficFormat(path); ok {
				return nil
			}
		}
		rel, relErr := filepath.Rel(rootAbs, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		if doc, ok := readKBFile(path, rel); ok {
			docs = append(docs, doc)
		}
		return nil
	})
	if walkErr != nil {
		return rootAbs, nil, true, walkErr
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].RelPath < docs[j].RelPath })
	return rootAbs, docs, true, nil
}

// readKBFile reads one document (bounded to kbMaxFileChars so a stray huge file
// never gets pulled fully into memory) and derives a deterministic description.
// Returns ok=false for unreadable or binary files.
func readKBFile(absPath, relPath string) (kbDoc, bool) {
	f, err := os.Open(absPath)
	if err != nil {
		return kbDoc{}, false
	}
	defer func() { _ = f.Close() }()
	// The cap is enough for both the binary sniff and the distiller excerpt.
	data, err := io.ReadAll(io.LimitReader(f, kbMaxFileChars))
	if err != nil {
		return kbDoc{}, false
	}
	if looksBinaryBytes(data) {
		return kbDoc{}, false
	}
	content := string(data)
	return kbDoc{
		RelPath:     filepath.ToSlash(relPath),
		AbsPath:     absPath,
		Content:     content,
		Description: deriveKBDescription(content),
	}, true
}

// deriveKBDescription pulls a one-line description from a document, preferring a
// YAML frontmatter `description:`/`summary:` field, then the first markdown
// heading, then the first non-empty line. Returns "" when nothing usable.
func deriveKBDescription(content string) string {
	lines := strings.Split(content, "\n")
	i := 0

	// YAML frontmatter: a leading `---` … `---` block. Prefer an explicit
	// description/summary field, then resume scanning after the block.
	if i < len(lines) && strings.TrimSpace(lines[i]) == "---" {
		for j := i + 1; j < len(lines); j++ {
			s := strings.TrimSpace(lines[j])
			if s == "---" {
				i = j + 1
				break
			}
			for _, key := range []string{"description:", "summary:"} {
				if v, ok := strings.CutPrefix(s, key); ok {
					return truncateLine(cleanKBLine(v), kbDescriptionChars)
				}
			}
		}
	}

	// First meaningful line — a heading or the first prose line, whichever
	// comes first.
	for ; i < len(lines); i++ {
		s := strings.TrimSpace(lines[i])
		if s == "" {
			continue
		}
		return truncateLine(cleanKBLine(s), kbDescriptionChars)
	}
	return ""
}

// cleanKBLine strips markdown/quote decoration so a heading or field value reads
// as plain text in the index.
func cleanKBLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "#>*_`- \t")
	s = strings.Trim(s, "\"'")
	return strings.TrimSpace(s)
}

// boundKBCorpus concatenates document contents for the distiller, capped at
// kbMaxTotalChars. Returns the corpus and the number of documents omitted
// because the cap was reached (they still appear in the on-demand file index).
func boundKBCorpus(docs []kbDoc) (corpus string, omitted int) {
	var b strings.Builder
	used := 0
	for i, d := range docs {
		block := fmt.Sprintf("=== %s ===\n%s\n\n", d.RelPath, d.Content)
		// Always admit the first document so we never send an empty corpus.
		if used > 0 && used+len(block) > kbMaxTotalChars {
			return b.String(), len(docs) - i
		}
		b.WriteString(block)
		used += len(block)
	}
	return b.String(), 0
}

// distillKnowledgeBase runs one tool-less model call that reads the gathered
// docs and returns a compact markdown briefing (auth model, login flow, roles,
// business logic) for the operator's opening turn. Best-effort: returns
// ("", false) on any provider error or empty output, so the caller falls back
// to the deterministic document index. Bounded by kbDistillTimeout and a capped
// input corpus.
func distillKnowledgeBase(ctx context.Context, prov provider.Provider, model string, docs []kbDoc) (string, bool) {
	if prov == nil || len(docs) == 0 {
		return "", false
	}
	corpus, omitted := boundKBCorpus(docs)
	if strings.TrimSpace(corpus) == "" {
		return "", false
	}

	sys := "You are a security-scan planner. You are given reference documentation for a web " +
		"application — its authentication model, login flows, user roles / privilege tiers, and " +
		"business logic. Distill it into a COMPACT briefing that an autonomous penetration-testing " +
		"agent reads before it starts. Output GitHub-flavored markdown using these bold sub-headers, " +
		"omitting any the docs don't support (never invent content):\n" +
		"- **Auth model** — the roles / privilege tiers and what each can access\n" +
		"- **How to authenticate** — login endpoint(s), credential shape, token / session mechanics\n" +
		"- **Key business logic** — objects, ownership rules, and state machines an attacker would target\n" +
		"- **Constraints** — anything security-relevant (rate limits, CSRF, MFA, tenancy)\n" +
		"Be terse and factual: a few hundred words at most. Do NOT restate the docs verbatim, do NOT " +
		"add a preamble or sign-off, and do NOT include anything not present in the provided docs."

	var user strings.Builder
	user.WriteString("Reference documentation follows. Distill it per your instructions.\n\n")
	user.WriteString(corpus)

	eng := engine.New(engine.Config{Provider: prov, Model: model, System: sys, MaxTurns: 1})
	callCtx, cancel := context.WithTimeout(ctx, kbDistillTimeout)
	defer cancel()

	var out strings.Builder
	for ev := range eng.Run(callCtx, user.String()) {
		switch ev.Type {
		case engine.EventTextDelta:
			out.WriteString(ev.Delta)
		case engine.EventError:
			return "", false
		}
	}
	summary := strings.TrimSpace(out.String())
	if summary == "" {
		return "", false
	}
	if omitted > 0 {
		summary += fmt.Sprintf("\n\n_(Distilled from %d of %d documents by size; the remaining %d are listed below and readable on demand.)_",
			len(docs)-omitted, len(docs), omitted)
	}
	return summary, true
}

// knowledgeBaseDirective is the opinionated instruction that heads the inlined
// section — it tells the operator agent WHEN to consult the docs so the
// read-on-demand model doesn't leave them unread.
const knowledgeBaseDirective = "The operator supplied reference documentation describing how this " +
	"application works — its authentication model, login flows, user roles / privilege tiers, and " +
	"business logic. **Consult it before authenticating, before reasoning about user roles or " +
	"privilege boundaries, and before modeling business logic.** The full documents live on disk; " +
	"read the relevant file with `read_file` (or `grep` across the directory) when you need detail — " +
	"don't guess where the docs already have the answer."

// renderKnowledgeBaseFileList renders the authoritative document list with
// absolute paths for read_file. withDesc adds the deterministic one-line
// description (used when no LLM summary is present to carry it).
func renderKnowledgeBaseFileList(docs []kbDoc, withDesc bool) string {
	var b strings.Builder
	for _, d := range docs {
		suffix := ""
		if withDesc && d.Description != "" {
			suffix = " — " + d.Description
		}
		fmt.Fprintf(&b, "- `%s`%s\n", d.AbsPath, suffix)
	}
	return strings.TrimRight(b.String(), "\n")
}

// renderKnowledgeBaseSection assembles the markdown block folded into the
// operator's opening instruction: the directive, the KB location, the optional
// LLM summary, and the always-present authoritative document index.
func renderKnowledgeBaseSection(rootAbs string, isDir bool, summary string, docs []kbDoc) string {
	var b strings.Builder
	// Header deliberately avoids "Application Knowledge Base": in the whitebox
	// pipeline path the audit driver emits its OWN `## Application Knowledge Base`
	// section, so a distinct title keeps the two from shadowing each other.
	b.WriteString("## Operator-supplied reference documentation\n\n")
	b.WriteString(knowledgeBaseDirective)
	b.WriteString("\n\n")
	label := "file"
	if isDir {
		label = "directory"
	}
	fmt.Fprintf(&b, "**Knowledge base %s:** `%s`\n\n", label, rootAbs)

	if summary != "" {
		b.WriteString(summary)
		b.WriteString("\n\n")
	}
	if len(docs) > 0 {
		b.WriteString("**Documents (read on demand):**\n\n")
		// When there's no LLM summary the index carries the descriptions;
		// otherwise the summary already covers the content, so keep the list
		// terse (paths only) to save tokens.
		b.WriteString(renderKnowledgeBaseFileList(docs, summary == ""))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// buildKnowledgeBaseSection loads the operator-supplied knowledge base at
// kbPath, distills it (unless raw), and returns a markdown section to fold into
// the operator's opening instruction. The full docs stay on disk and are read
// on demand; only this compact section is inlined. The assembled section is
// also written to <sessionDir>/knowledge-base-brief.md for provenance and
// --resume reuse. Returns "" (nil error) when the KB holds no readable text
// docs. Distillation failure is non-fatal — it degrades to the deterministic
// document index. Progress is logged to w. routeTraffic mirrors the caller's
// traffic-routing decision: when true, files parsed as traffic are excluded
// from the prose corpus (they're ingested as records elsewhere).
func buildKnowledgeBaseSection(ctx context.Context, prov provider.Provider, model, kbPath string, raw bool, sessionDir string, w io.Writer, routeTraffic bool) (string, error) {
	// --resume / reused --session-dir: reuse a previously distilled brief so we
	// don't re-pay the LLM call. Skipped in raw mode (deterministic index is
	// cheap to rebuild and reflects the current tree).
	artifactPath := ""
	if sessionDir != "" {
		artifactPath = filepath.Join(sessionDir, knowledgeBaseArtifact)
		if !raw {
			if data, rerr := os.ReadFile(artifactPath); rerr == nil && strings.TrimSpace(string(data)) != "" {
				_, _ = fmt.Fprintf(w, "%s Knowledge base: reusing cached brief (%s)\n",
					terminal.InfoSymbol(), terminal.ShortenHome(artifactPath))
				return strings.TrimRight(string(data), "\n"), nil
			}
		}
	}

	rootAbs, docs, isDir, err := gatherKnowledgeBaseDocs(kbPath, routeTraffic)
	if err != nil {
		return "", err
	}
	if len(docs) == 0 {
		_, _ = fmt.Fprintf(w, "%s Knowledge base: no readable text documents under %s — skipping\n",
			terminal.WarningSymbol(), terminal.ShortenHome(rootAbs))
		return "", nil
	}

	summary := ""
	if raw {
		_, _ = fmt.Fprintf(w, "%s Knowledge base: indexed %d document(s) from %s (raw — no LLM distillation)\n",
			terminal.InfoSymbol(), len(docs), terminal.ShortenHome(rootAbs))
	} else {
		_, _ = fmt.Fprintf(w, "%s Knowledge base: distilling %d document(s) from %s ...\n",
			terminal.InfoSymbol(), len(docs), terminal.ShortenHome(rootAbs))
		if s, ok := distillKnowledgeBase(ctx, prov, model, docs); ok {
			summary = s
			_, _ = fmt.Fprintf(w, "%s Knowledge base: distilled brief ready\n", terminal.SuccessSymbol())
		} else {
			_, _ = fmt.Fprintf(w, "%s Knowledge base: distillation unavailable — falling back to a document index\n",
				terminal.WarningSymbol())
		}
	}

	section := renderKnowledgeBaseSection(rootAbs, isDir, summary, docs)

	if artifactPath != "" {
		if werr := os.WriteFile(artifactPath, []byte(section+"\n"), 0o600); werr != nil {
			zap.L().Debug("failed to write knowledge-base brief artifact", zap.Error(werr))
		}
	}
	return section, nil
}
