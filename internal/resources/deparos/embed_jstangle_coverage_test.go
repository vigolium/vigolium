package deparos

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// releaseTargets is the set of os/arch pairs the project actually ships
// (see .goreleaser.yaml `builds` and build/npm/build.mjs PLATFORMS). Every
// one MUST have a real, non-stub jstangle embed file — otherwise that platform
// silently falls through to embed_jstangle_unsupported.go and ships with jstangle
// disabled (NewExtractor returns ErrUnsupportedPlatform). That exact gap once
// shipped linux/arm64 and darwin/amd64 without jstangle. Keep this list in sync
// with the release matrix.
var releaseTargets = [][2]string{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// TestJSTangleEmbedCoverage asserts each released platform has a matching
// build-tagged jstangle embed file, so no shipped platform degrades to the
// empty stub. It reads source files (not build-constrained symbols) so it
// runs from any host.
func TestJSTangleEmbedCoverage(t *testing.T) {
	for _, tgt := range releaseTargets {
		goos, goarch := tgt[0], tgt[1]
		file := fmt.Sprintf("embed_jstangle_%s_%s.go", goos, goarch)
		data, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s/%s: missing jstangle embed file %s — this platform would ship the empty stub (jstangle disabled)", goos, goarch, file)
			continue
		}
		src := string(data)
		wantBuild := fmt.Sprintf("//go:build %s && %s && !jstangle_stub", goos, goarch)
		if !strings.Contains(src, wantBuild) {
			t.Errorf("%s: missing build constraint %q", file, wantBuild)
		}
		wantEmbed := fmt.Sprintf("//go:embed jstangle/jstangle-%s-%s", goos, goarch)
		if !strings.Contains(src, wantEmbed) {
			t.Errorf("%s: missing embed directive %q", file, wantEmbed)
		}
	}
}
