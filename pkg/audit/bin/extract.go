package bin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/vigolium/vigolium/internal/helperblob"
	"github.com/vigolium/vigolium/internal/paths"
)

// CacheDirEnv overrides the per-user cache directory used for extraction.
// Set it to a writable absolute path when the default user-cache dir is
// not appropriate (e.g. ephemeral CI containers, sandboxed test runs).
const CacheDirEnv = "VIGOLIUM_AUDIT_CACHE_DIR"

// BinaryEnv points vigolium at a vigolium-audit executable on disk, bypassing
// the embedded or downloaded helper entirely. It is the air-gapped escape
// hatch for `audit_external` builds and works in every build.
const BinaryEnv = "VIGOLIUM_AUDIT_BINARY"

// Helper source kinds reported by Status.
const (
	SourceOverride = "override" // VIGOLIUM_AUDIT_BINARY
	SourceEmbedded = "embedded" // default builds
	SourceDownload = "download" // -tags audit_external
)

// ErrBinaryMissing is returned by Path when no vigolium-audit binary is
// available to this build: nothing was embedded (the most common cause is
// `go build` running before `make build-audit`), or an `audit_external` build
// carries no pin for this platform. Callers should surface a hint pointing
// users to the make target rather than printing the error verbatim.
var ErrBinaryMissing = errors.New("vigolium-audit binary not embedded")

// ErrHelperUnavailable is returned when an `audit_external` build cannot fetch
// its pinned helper: no download base URL is configured, the URL is not https,
// or the download failed. The error text carries the remediation.
var ErrHelperUnavailable = errors.New("vigolium-audit helper unavailable")

// ErrChecksumMismatch is returned when the decompressed or downloaded helper
// does not hash to its pin. It is a hard error: nothing is installed.
var ErrChecksumMismatch = helperblob.ErrChecksumMismatch

// source supplies the pinned, zstd-compressed helper: embedded in default
// builds (embed.go), downloaded in `audit_external` builds (external.go).
type source interface {
	kind() string
	// pin returns the pin for this platform, or an error wrapping
	// ErrBinaryMissing when the build carries none.
	pin() (helperblob.Pin, error)
	// open returns the compressed helper stream.
	open(ctx context.Context, pin helperblob.Pin) (io.ReadCloser, error)
	// ready reports whether open can be expected to succeed without trying it.
	ready(pin helperblob.Pin) bool
	// origin describes where open reads from, for diagnostics.
	origin(pin helperblob.Pin) string
}

var (
	pathMu     sync.Mutex
	cachedPath string
)

// minBinarySize is the smallest the vigolium-audit binary can plausibly be.
// A real build is ~60–90 MiB; the threshold rejects stubs and Git-LFS
// pointer files.
const minBinarySize = 1 << 20 // 1 MiB

// Path returns the absolute path to the vigolium-audit binary, installing it
// on first use: the pinned blob is decompressed (or downloaded and
// decompressed) to <cacheDir>/vigolium-audit-<sha12>/vigolium-audit, verified
// against the pinned sha256 and made executable. Subsequent calls return the
// cached path. The hash-suffixed cache directory means a vigolium upgrade that
// ships a new helper installs to a new path automatically. A failure is not
// cached, so a later call can retry (e.g. after the network comes back).
func Path() (string, error) {
	return PathContext(context.Background())
}

// PathContext is Path with a context bounding a download in `audit_external`
// builds.
func PathContext(ctx context.Context) (string, error) {
	if p := os.Getenv(BinaryEnv); p != "" {
		return checkOverride(p)
	}
	pathMu.Lock()
	defer pathMu.Unlock()
	if cachedPath != "" {
		return cachedPath, nil
	}
	p, err := install(ctx, helperSource)
	if err != nil {
		return "", err
	}
	cachedPath = p
	return p, nil
}

// Available reports whether a vigolium-audit binary can be provided without
// error: an override that exists, or a plausible pin whose source is ready
// (always for embedded builds; for `audit_external` builds, already cached or
// a valid download URL configured). Cheap enough for the server hot path.
func Available() bool {
	if p := os.Getenv(BinaryEnv); p != "" {
		_, err := checkOverride(p)
		return err == nil
	}
	pin, err := helperSource.pin()
	if err != nil || pin.Size < minBinarySize {
		return false
	}
	if verifyPinForHost(pin) != nil {
		return false
	}
	if dst, err := cachedBinaryPath(pin); err == nil && helperblob.Cached(dst, pin) {
		return true
	}
	return helperSource.ready(pin)
}

// External reports whether this is an `audit_external` build, which downloads
// the helper instead of embedding it.
func External() bool { return helperSource.kind() == SourceDownload }

// HelperStatus describes where the vigolium-audit helper comes from and
// whether it is already installed, without installing or downloading it.
type HelperStatus struct {
	Source string // SourceOverride, SourceEmbedded or SourceDownload
	SHA256 string // pinned sha256 of the uncompressed helper ("" for override)
	Size   int64
	Path   string // where the helper is (or will be) installed
	Cached bool   // Path already holds the verified helper
	Origin string // "embedded", the download URL, or the override path
	Err    error  // why the helper cannot be provided, if known up front
}

// Status reports the helper's provenance and cache state. It never extracts
// or downloads; use Path (or PathContext) for that.
func Status() HelperStatus {
	if p := os.Getenv(BinaryEnv); p != "" {
		abs, err := checkOverride(p)
		if abs == "" {
			abs = p
		}
		return HelperStatus{Source: SourceOverride, Path: abs, Cached: err == nil, Origin: p, Err: err}
	}
	st := HelperStatus{Source: helperSource.kind()}
	pin, err := helperSource.pin()
	if err != nil {
		st.Err = err
		return st
	}
	st.SHA256, st.Size = pin.SHA256, pin.Size
	st.Origin = helperSource.origin(pin)
	if err := verifyPinForHost(pin); err != nil {
		st.Err = err
		return st
	}
	dst, err := cachedBinaryPath(pin)
	if err != nil {
		st.Err = err
		return st
	}
	st.Path = dst
	st.Cached = helperblob.Cached(dst, pin)
	if !st.Cached && !helperSource.ready(pin) {
		_, st.Err = downloadURL(pin)
	}
	return st
}

func install(ctx context.Context, src source) (string, error) {
	pin, err := src.pin()
	if err != nil {
		return "", err
	}
	if pin.Size < minBinarySize {
		return "", fmt.Errorf("%w: pinned helper is only %d bytes (stub?); run `make build-audit` and rebuild vigolium", ErrBinaryMissing, pin.Size)
	}
	if err := verifyPinForHost(pin); err != nil {
		return "", err
	}
	dst, err := cachedBinaryPath(pin)
	if err != nil {
		return "", err
	}
	// Hash-suffixed dir: a file of the pinned size there was verified by
	// Install when it was written. Skip re-extract.
	if helperblob.Cached(dst, pin) {
		return dst, nil
	}
	rc, err := src.open(ctx, pin)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	return helperblob.Install(rc, pin, filepath.Dir(dst), filepath.Base(dst))
}

// checkOverride validates a VIGOLIUM_AUDIT_BINARY path.
func checkOverride(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%s=%q: %w", BinaryEnv, p, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return abs, fmt.Errorf("%s=%q: %w", BinaryEnv, p, err)
	}
	if !info.Mode().IsRegular() {
		return abs, fmt.Errorf("%s=%q is not a regular file", BinaryEnv, p)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return abs, fmt.Errorf("%s=%q is not executable", BinaryEnv, p)
	}
	return abs, nil
}

func binaryFileName() string {
	if runtime.GOOS == "windows" {
		return "vigolium-audit.exe"
	}
	return "vigolium-audit"
}

func cachedBinaryPath(pin helperblob.Pin) (string, error) {
	dir, err := resolveCacheDir(pin.Short())
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, binaryFileName()), nil
}

func resolveCacheDir(hash string) (string, error) {
	if dir := os.Getenv(CacheDirEnv); dir != "" {
		return filepath.Join(dir, "vigolium-audit-"+hash), nil
	}
	if paths.StateDirSet() {
		return filepath.Join(paths.UserCacheDir("vigolium"), "vigolium-audit-"+hash), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(base, "vigolium", "vigolium-audit-"+hash), nil
}
