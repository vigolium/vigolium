package gitutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// CloneOptions configures a git clone operation.
type CloneOptions struct {
	StoragePath string // base directory for cloned repos
	CloneDepth  int    // git clone --depth value (default: 1)
	Branch      string // branch to clone (empty = default branch)
	AuthToken   string // if set, injected into HTTPS clone URLs for private repo access
}

// LooksLikeGitURL returns true if the value looks like a git URL rather than a local path.
func LooksLikeGitURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "git@")
}

// CloneRepo clones a git URL into the configured storage directory.
// Returns the absolute path to the cloned directory.
func CloneRepo(gitURL string, opts CloneOptions) (string, error) {
	if opts.CloneDepth <= 0 {
		opts.CloneDepth = 1
	}

	storagePath := opts.StoragePath
	if storagePath == "" {
		home, _ := os.UserHomeDir()
		storagePath = filepath.Join(home, ".vigolium", "source-repos")
	}

	// Derive directory name from git URL
	dirName, err := GitURLToDirName(gitURL)
	if err != nil {
		return "", fmt.Errorf("invalid git URL: %w", err)
	}

	destPath := filepath.Join(storagePath, dirName)

	// Ensure storage directory exists
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create storage directory %s: %w", storagePath, err)
	}

	// Idempotent: skip clone if directory already exists
	if info, statErr := os.Stat(destPath); statErr == nil && info.IsDir() {
		zap.L().Info("Repository already exists, skipping clone", zap.String("path", destPath))
		return destPath, nil
	}

	// Build the clone URL (inject auth token for private repos)
	cloneURL := gitURL
	if opts.AuthToken != "" {
		cloneURL, err = injectToken(gitURL, opts.AuthToken)
		if err != nil {
			return "", fmt.Errorf("failed to inject auth token: %w", err)
		}
	}

	// Run git clone with timeout
	zap.L().Info("Cloning repository", zap.String("url", gitURL))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"clone", fmt.Sprintf("--depth=%d", opts.CloneDepth)}
	if opts.Branch != "" {
		args = append(args, "--branch", opts.Branch)
	}
	args = append(args, cloneURL, destPath)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone failed: %w", err)
	}

	zap.L().Info("Cloned repository", zap.String("path", destPath))
	return destPath, nil
}

// GitURLToDirName derives a filesystem-safe directory name from a git URL.
// e.g. "https://github.com/juice-shop/juice-shop" -> "github.com_juice-shop_juice-shop"
func GitURLToDirName(rawURL string) (string, error) {
	// Handle git@ SSH URLs by converting to parseable form
	normalized := rawURL
	if strings.HasPrefix(rawURL, "git@") {
		// git@github.com:org/repo.git -> https://github.com/org/repo.git
		normalized = strings.Replace(rawURL, ":", "/", 1)
		normalized = strings.Replace(normalized, "git@", "https://", 1)
	}

	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no hostname in URL: %s", rawURL)
	}

	// Clean up path: remove leading slash and .git suffix
	path := strings.TrimPrefix(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	if path == "" {
		return "", fmt.Errorf("no repository path in URL: %s", rawURL)
	}

	// Strip any userinfo that might have been left from token injection
	// Replace / with _ for filesystem safety
	safePath := strings.ReplaceAll(path, "/", "_")

	return host + "_" + safePath, nil
}

// injectToken inserts an OAuth token into an HTTPS git URL for private repo access.
// e.g. "https://github.com/org/repo.git" -> "https://x-access-token:{token}@github.com/org/repo.git"
func injectToken(gitURL, token string) (string, error) {
	u, err := url.Parse(gitURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return gitURL, nil // only inject into HTTP(S) URLs
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String(), nil
}
