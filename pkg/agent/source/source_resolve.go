package source

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/gitutil"
	"go.uber.org/zap"
)

// Archive extensions recognized by isArchive.
var archiveExts = []string{".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"}

// githubPRPattern matches GitHub pull request URLs for diff resolution.
var githubPRPattern = regexp.MustCompile(`https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)`)

// maxPatchBytes caps the PatchContent stored in DiffContext to prevent unbounded memory usage.
// The autopilot prompt truncates further to 8KB for LLM context; this limit bounds storage/serialization.
const maxPatchBytes = 32 * 1024 // 32 KB

// SourceResolveOption configures source resolution behavior.
type SourceResolveOption func(*sourceResolveOpts)

type sourceResolveOpts struct {
	cloneDepth int // git clone --depth; 0 means "use gitutil default" (1)
}

// WithCloneDepth sets the --depth value used when cloning a git URL.
// A value <= 0 falls back to gitutil's default (1).
func WithCloneDepth(d int) SourceResolveOption {
	return func(o *sourceResolveOpts) { o.cloneDepth = d }
}

func applySourceResolveOptions(opts []SourceResolveOption) sourceResolveOpts {
	var o sourceResolveOpts
	for _, fn := range opts {
		if fn != nil {
			fn(&o)
		}
	}
	return o
}

// ResolveSourceAndDiff is a convenience that resolves both source and diff in one call.
// It handles git URLs, archives, PR/MR URLs, git refs, and HEAD~N.
// Returns the resolved local source path, files list (auto-populated from diff if empty), and diff context.
func ResolveSourceAndDiff(source, diff string, lastCommits int, files []string, sessionDir string, opts ...SourceResolveOption) (resolvedSource string, resolvedFiles []string, diffCtx *agenttypes.DiffContext, err error) {
	resolvedSource = source
	resolvedFiles = files

	// Resolve source: git URL, archive, or local path
	if resolvedSource != "" {
		resolved, resolveErr := ResolveSource(resolvedSource, sessionDir, opts...)
		if resolveErr != nil {
			return "", nil, nil, fmt.Errorf("failed to resolve --source: %w", resolveErr)
		}
		if resolved != nil {
			resolvedSource = resolved.LocalPath
		}
	}

	// Resolve diff context
	if diff != "" || lastCommits > 0 {
		src, dc, diffErr := ResolveDiff(diff, lastCommits, resolvedSource, sessionDir, opts...)
		if diffErr != nil {
			return "", nil, nil, fmt.Errorf("failed to resolve --diff: %w", diffErr)
		}
		diffCtx = dc
		// If diff resolution auto-cloned a repo (PR URL without --source), update source
		if resolvedSource == "" && src != "" {
			resolvedSource = src
		}
		// Auto-populate files from changed files when not explicitly set
		if diffCtx != nil && len(resolvedFiles) == 0 {
			resolvedFiles = diffCtx.ChangedFiles
		}
	}

	return resolvedSource, resolvedFiles, diffCtx, nil
}

// ResolveSource detects the source type and returns a local path.
func ResolveSource(sourcePath, sessionDir string, opts ...SourceResolveOption) (*agenttypes.ResolvedSource, error) {
	if sourcePath == "" {
		return nil, nil
	}

	cfg := applySourceResolveOptions(opts)
	sourcePath = agenttypes.ExpandHome(sourcePath)

	// Git URL: clone to session dir
	if gitutil.LooksLikeGitURL(sourcePath) {
		localPath, err := cloneSourceToSession(sourcePath, sessionDir, cfg.cloneDepth)
		if err != nil {
			return nil, fmt.Errorf("git clone failed: %w", err)
		}
		return &agenttypes.ResolvedSource{LocalPath: localPath}, nil
	}

	// Archive: extract to session dir
	if isArchive(sourcePath) {
		absPath, err := filepath.Abs(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve archive path: %w", err)
		}
		localPath, err := extractArchiveToSession(absPath, sessionDir)
		if err != nil {
			return nil, fmt.Errorf("archive extraction failed: %w", err)
		}
		return &agenttypes.ResolvedSource{LocalPath: localPath}, nil
	}

	// Local path: verify existence and pass through
	absPath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("source path does not exist: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source path is not a directory: %s", absPath)
	}
	return &agenttypes.ResolvedSource{LocalPath: absPath}, nil
}

// ResolveDiff resolves a --diff argument into changed files and patch content.
// Handles: GitHub PR URLs, GitLab MR URLs, git ref ranges, HEAD~N.
// When diffArg is a PR/MR URL and sourcePath is empty, the repo is auto-cloned.
// Returns the resolved source path (may differ from input if auto-cloned) and the diff context.
func ResolveDiff(diffArg string, lastCommits int, sourcePath, sessionDir string, opts ...SourceResolveOption) (resolvedSourcePath string, dc *agenttypes.DiffContext, err error) {
	cfg := applySourceResolveOptions(opts)
	// --last-commits N is shorthand for --diff HEAD~N
	if lastCommits > 0 && diffArg == "" {
		diffArg = fmt.Sprintf("HEAD~%d", lastCommits)
	}

	if diffArg == "" {
		return sourcePath, nil, nil
	}

	resolvedSourcePath = sourcePath

	// Extract token from URL if embedded (e.g. https://oauth2:TOKEN@github.com/...)
	// Fall back to GITHUB_TOKEN / GITLAB_TOKEN env vars.
	_, urlToken := extractTokenFromURL(diffArg)

	// GitHub PR URL
	if m := githubPRPattern.FindStringSubmatch(diffArg); m != nil {
		owner, repo := m[1], m[2]
		prNumber, _ := strconv.Atoi(m[3])

		// Resolve token: URL-embedded > GITHUB_TOKEN env var
		ghToken := urlToken
		if ghToken == "" {
			ghToken = os.Getenv("GITHUB_TOKEN")
		}

		// Auto-clone if no source provided (pass token for private repos)
		if resolvedSourcePath == "" {
			cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
			if ghToken != "" {
				cloneURL = fmt.Sprintf("https://oauth2:%s@github.com/%s/%s.git", ghToken, owner, repo)
			}
			clonePath, cloneErr := cloneSourceToSession(cloneURL, sessionDir, cfg.cloneDepth)
			if cloneErr != nil {
				return "", nil, fmt.Errorf("auto-clone for PR diff failed: %w", cloneErr)
			}
			resolvedSourcePath = clonePath
		}

		dc, err = resolveGitHubPRDiff(owner, repo, prNumber, ghToken)
		return resolvedSourcePath, dc, err
	}

	// Git ref range or HEAD~N — requires source path
	if resolvedSourcePath == "" {
		return "", nil, fmt.Errorf("--diff %q requires --source (git ref range needs a local repo)", diffArg)
	}
	dc, err = resolveGitRefDiff(diffArg, resolvedSourcePath)
	return resolvedSourcePath, dc, err
}

// cloneSourceToSession clones a git URL into <sessionDir>/source/.
// Embedded OAuth tokens (e.g. https://oauth2:token@...) are extracted and
// passed via CloneOptions.AuthToken; the URL is sanitized before logging.
// cloneDepth <= 0 falls back to gitutil's default (1).
func cloneSourceToSession(gitURL, sessionDir string, cloneDepth int) (string, error) {
	destDir := filepath.Join(sessionDir, "source")

	// Extract embedded token if present
	cleanURL, token := extractTokenFromURL(gitURL)

	zap.L().Info("Cloning source repository",
		zap.String("url", sanitizeGitURL(gitURL)),
		zap.String("dest", destDir),
		zap.Int("depth", cloneDepth))

	opts := gitutil.CloneOptions{
		StoragePath: destDir,
		CloneDepth:  cloneDepth,
		AuthToken:   token,
	}

	// CloneRepo appends a dir name derived from the URL inside StoragePath,
	// so the actual clone dir will be <destDir>/<derived-name>.
	clonedPath, err := gitutil.CloneRepo(cleanURL, opts)
	if err != nil {
		return "", err
	}

	return clonedPath, nil
}

// extractTokenFromURL parses a git URL and extracts any embedded OAuth token.
// Returns the clean URL (without token) and the token (empty if none).
func extractTokenFromURL(rawURL string) (cleanURL, token string) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return rawURL, ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}

	if u.User == nil {
		return rawURL, ""
	}

	// Extract password (the token in oauth2:TOKEN format) or username-as-token
	if pwd, ok := u.User.Password(); ok && pwd != "" {
		token = pwd
	} else {
		token = u.User.Username()
	}

	u.User = nil
	return u.String(), token
}

// sanitizeGitURL strips credentials from a git URL for safe logging.
func sanitizeGitURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		// Reconstruct manually to avoid URL-encoding of the placeholder
		u.User = nil
		s := u.String()
		// Insert ***@ after the scheme://
		schemeEnd := strings.Index(s, "://") + 3
		return s[:schemeEnd] + "***@" + s[schemeEnd:]
	}
	return u.String()
}

func isArchive(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range archiveExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// extractArchiveToSession extracts an archive file into the session's source directory.
// Returns the effective root directory (handles single-root archives).
func extractArchiveToSession(archivePath, sessionDir string) (string, error) {
	destDir := filepath.Join(sessionDir, "source")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create extraction directory: %w", err)
	}

	lower := strings.ToLower(archivePath)
	var err error

	switch {
	case strings.HasSuffix(lower, ".zip"):
		err = extractZip(archivePath, destDir)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		err = extractTarGz(archivePath, destDir)
	case strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tbz2"):
		err = extractTarBz2(archivePath, destDir)
	case strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".txz"):
		err = extractTarXz(archivePath, destDir)
	default:
		return "", fmt.Errorf("unsupported archive format: %s", filepath.Base(archivePath))
	}

	if err != nil {
		return "", err
	}

	// Single-root detection: if destDir has exactly one child directory and no files,
	// return that child as the effective root.
	return detectEffectiveRoot(destDir)
}

func detectEffectiveRoot(destDir string) (string, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return destDir, nil
	}

	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}

	// Single directory, no files → use it as root
	if len(dirs) == 1 && len(entries) == 1 {
		return filepath.Join(destDir, dirs[0].Name()), nil
	}
	return destDir, nil
}

// archiveFilePermMask bounds the permission bits an archive can give an
// extracted file: owner rwx, group/other r-x at most. An archive must not be
// able to plant group- or world-writable files.
const archiveFilePermMask = 0o755

// safeArchivePath turns an archive member name into a path relative to the
// extraction root. It reports false for a name that is empty or climbs out
// of the root. A leading slash is stripped rather than rejected.
func safeArchivePath(name string) (string, bool) {
	clean := filepath.Clean(strings.TrimLeft(filepath.FromSlash(name), string(os.PathSeparator)))
	if clean == "." || !filepath.IsLocal(clean) {
		return "", false
	}
	return clean, true
}

// symlinkStaysInside reports whether a symlink at linkPath (relative to the
// extraction root) pointing at target resolves, lexically, inside the root.
// Absolute targets never do; they are rejected before joining, because
// filepath.Join would rewrite one into a path under the link's directory.
func symlinkStaysInside(linkPath, target string) bool {
	target = filepath.FromSlash(target)
	if target == "" || filepath.IsAbs(target) {
		return false
	}
	return filepath.IsLocal(filepath.Join(filepath.Dir(linkPath), target))
}

// archiveWriter writes archive members under an os.Root, which refuses to
// follow a symlink out of the destination, so an archive cannot plant a link
// and then write through it.
type archiveWriter struct {
	root *os.Root
	made map[string]struct{} // directories already created
}

func openArchiveWriter(destDir string) (*archiveWriter, error) {
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return nil, err
	}
	return &archiveWriter{root: root, made: map[string]struct{}{".": {}}}, nil
}

func (w *archiveWriter) Close() error { return w.root.Close() }

// mkdir creates dir once per extraction: Root.MkdirAll walks every path
// component, so calling it for each file's parent is a syscall per level.
func (w *archiveWriter) mkdir(dir string) error {
	if _, ok := w.made[dir]; ok {
		return nil
	}
	if err := w.root.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for d := dir; d != "."; d = filepath.Dir(d) {
		w.made[d] = struct{}{}
	}
	return nil
}

// writeFile writes src to name with its mode capped by archiveFilePermMask.
func (w *archiveWriter) writeFile(name string, mode os.FileMode, src io.Reader) error {
	if err := w.mkdir(filepath.Dir(name)); err != nil {
		return err
	}
	out, err := w.root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm()&archiveFilePermMask)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, src) //nolint:gosec // bounded by archive entry
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// symlink creates an in-tree symlink, best-effort; escaping targets are skipped.
func (w *archiveWriter) symlink(name, target string) {
	if symlinkStaysInside(name, target) {
		_ = w.root.Symlink(target, name)
	}
}

// extractZip extracts a zip archive to destDir.
func extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	w, err := openArchiveWriter(destDir)
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()

	for _, f := range r.File {
		name, ok := safeArchivePath(f.Name)
		if !ok {
			continue
		}
		if f.FileInfo().IsDir() {
			if err := w.mkdir(name); err != nil {
				return err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = w.writeFile(name, f.Mode(), rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// extractTarGz extracts a .tar.gz archive to destDir.
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	return extractTar(gz, destDir)
}

// extractTarBz2 extracts a .tar.bz2 archive to destDir.
func extractTarBz2(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return extractTar(bzip2.NewReader(f), destDir)
}

// extractTarXz extracts a .tar.xz archive to destDir by shelling out to tar.
// Go stdlib lacks xz decompression support.
func extractTarXz(archivePath, destDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tar", "xJf", archivePath, "-C", destDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar xJf failed: %w (output: %s)", err, string(output))
	}
	return nil
}

// extractTar extracts a tar stream to destDir. Writes go through an
// archiveWriter, and symlinks with absolute or escaping targets are skipped
// rather than created.
func extractTar(r io.Reader, destDir string) error {
	w, err := openArchiveWriter(destDir)
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		name, ok := safeArchivePath(hdr.Name)
		if !ok {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := w.mkdir(name); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := w.writeFile(name, os.FileMode(hdr.Mode), tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			w.symlink(name, hdr.Linkname)
		}
	}
	return nil
}

// --- Diff resolution ---

// resolveGitHubPRDiff fetches diff for a GitHub PR using the GitHub REST API.
// When token is non-empty, it is passed as Authorization: Bearer header for private repos.
// Falls back to unauthenticated requests for public repos.
func resolveGitHubPRDiff(owner, repo string, prNumber int, token string) (*agenttypes.DiffContext, error) {
	repoSlug := owner + "/" + repo

	// Fetch the unified diff via GitHub API (Accept: application/vnd.github.v3.diff)
	diffURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, prNumber)
	patchOut, err := githubAPIGet(diffURL, token, "application/vnd.github.v3.diff")
	if err != nil {
		return nil, fmt.Errorf("GitHub API diff request failed for %s/pull/%d: %w", repoSlug, prNumber, err)
	}

	// Extract changed file names from the unified diff
	files := parseDiffFileNames(patchOut)

	return &agenttypes.DiffContext{
		ChangedFiles: files,
		PatchContent: truncatePatch(patchOut),
		DiffRef:      fmt.Sprintf("github.com/%s/pull/%d", repoSlug, prNumber),
	}, nil
}

// githubAPIGet performs an HTTP GET against the GitHub API with optional auth and Accept header.
func githubAPIGet(url, token, accept string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap response body to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxPatchBytes)+1024))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	return string(body), nil
}

// resolveGitRefDiff resolves a git ref range diff using git CLI.
func resolveGitRefDiff(refRange, sourcePath string) (*agenttypes.DiffContext, error) {
	// Get changed file names
	filesOut, err := execCommand("git", "-C", sourcePath, "diff", "--name-only", refRange)
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only %s failed: %w", refRange, err)
	}

	// Get full patch
	patchOut, patchErr := execCommand("git", "-C", sourcePath, "diff", refRange)
	if patchErr != nil {
		zap.L().Warn("Failed to get git diff patch", zap.Error(patchErr))
	}

	return &agenttypes.DiffContext{
		ChangedFiles: parseChangedFiles(filesOut),
		PatchContent: truncatePatch(patchOut),
		DiffRef:      refRange,
	}, nil
}

// truncatePatch caps patch content to maxPatchBytes.
func truncatePatch(s string) string {
	if len(s) > maxPatchBytes {
		return s[:maxPatchBytes] + "\n\n... (truncated)\n"
	}
	return s
}

// execCommand runs a command and returns stdout as a string.
func execCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("%s %s: %w (stderr: %s)", name, strings.Join(args, " "), err, string(exitErr.Stderr))
		}
		return "", err
	}
	return string(out), nil
}

func parseChangedFiles(output string) []string {
	var files []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files
}

// parseDiffFileNames extracts file paths from a unified diff output.
// Looks for lines starting with "+++ b/" or "--- a/".
func parseDiffFileNames(diffOutput string) []string {
	seen := make(map[string]bool)
	var files []string
	for _, line := range strings.Split(diffOutput, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			f := strings.TrimPrefix(line, "+++ b/")
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	return files
}
