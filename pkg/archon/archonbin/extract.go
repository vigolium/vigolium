package archonbin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// CacheDirEnv overrides the per-user cache directory used for extraction.
// Set it to a writable absolute path when the default user-cache dir is
// not appropriate (e.g. ephemeral CI containers, sandboxed test runs).
const CacheDirEnv = "VIGOLIUM_ARCHON_CACHE_DIR"

// ErrBinaryMissing is returned by Path when the archon binary was not
// embedded at build time. The most common cause is `go build` running
// before `make build-archon`. Callers should surface a hint pointing
// users to the make target rather than printing the error verbatim.
var ErrBinaryMissing = errors.New("archon binary not embedded")

var (
	pathOnce      sync.Once
	cachedPath    string
	cachedErr     error
	availableOnce sync.Once
	cachedAvail   bool
)

// minBinarySize is the smallest the archon binary can plausibly be. The
// .gitkeep stub used on fresh clones is 0 bytes; a real archon-ts build
// is ~60–90 MiB. The threshold also rejects Git-LFS pointer files (a
// few hundred bytes) when the repo ships LFS-managed binaries.
const minBinarySize = 1 << 20 // 1 MiB

// Path returns the absolute path to the extracted archon binary. The
// extraction happens at most once per process: first call writes the
// blob to <cacheDir>/archon-<sha12>/archon and chmods it executable,
// subsequent calls return the cached path. The hash-suffixed cache
// directory means a vigolium upgrade that ships a new archon blob
// extracts to a new path automatically.
func Path() (string, error) {
	pathOnce.Do(func() {
		cachedPath, cachedErr = extract()
	})
	return cachedPath, cachedErr
}

// Available reports whether an archon binary was embedded at build time
// and looks plausible (above the minBinarySize threshold). Used by
// driver-availability probes on the server hot path; cached so we don't
// pay the embed.FS stat cost on every request.
func Available() bool {
	availableOnce.Do(func() {
		f, err := binFS.Open(embeddedName)
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil {
			return
		}
		cachedAvail = st.Size() >= minBinarySize
	})
	return cachedAvail
}

func extract() (string, error) {
	data, err := readBinary()
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%w: run `make build-archon` and rebuild vigolium", ErrBinaryMissing)
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])[:12]

	cacheDir, err := resolveCacheDir(hash)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("create archon cache dir: %w", err)
	}

	name := "archon"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dst := filepath.Join(cacheDir, name)

	// Hash-suffixed dir means: if the binary already exists at this path
	// with a non-zero size, it is the right version. Skip re-extract.
	if info, statErr := os.Stat(dst); statErr == nil && info.Mode().IsRegular() && info.Size() == int64(len(data)) {
		return dst, nil
	}

	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", fmt.Errorf("write archon binary: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("chmod archon binary: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("install archon binary: %w", err)
	}
	return dst, nil
}

func readBinary() ([]byte, error) {
	data, err := binFS.ReadFile(embeddedName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read embedded archon: %w", err)
	}
	return data, nil
}

func resolveCacheDir(hash string) (string, error) {
	if dir := os.Getenv(CacheDirEnv); dir != "" {
		return filepath.Join(dir, "archon-"+hash), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(base, "vigolium", "archon-"+hash), nil
}
