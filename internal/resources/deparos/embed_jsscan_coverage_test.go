package deparos

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// releaseTargets is the set of os/arch pairs the project actually ships
// (see .goreleaser.yaml `builds` and build/npm/build.mjs PLATFORMS). Every
// one MUST have a real, non-stub jsscan embed file — otherwise that platform
// silently falls through to embed_jsscan_unsupported.go and ships with jsscan
// disabled (NewExtractor returns ErrUnsupportedPlatform). That exact gap once
// shipped linux/arm64 and darwin/amd64 without jsscan. Keep this list in sync
// with the release matrix.
var releaseTargets = [][2]string{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// TestJSScanEmbedCoverage asserts each released platform has a matching
// build-tagged jsscan embed file, so no shipped platform degrades to the
// empty stub. It reads source files (not build-constrained symbols) so it
// runs from any host.
func TestJSScanEmbedCoverage(t *testing.T) {
	for _, tgt := range releaseTargets {
		goos, goarch := tgt[0], tgt[1]
		file := fmt.Sprintf("embed_jsscan_%s_%s.go", goos, goarch)
		data, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s/%s: missing jsscan embed file %s — this platform would ship the empty stub (jsscan disabled)", goos, goarch, file)
			continue
		}
		src := string(data)
		wantBuild := fmt.Sprintf("//go:build %s && %s && !jsscan_stub", goos, goarch)
		if !strings.Contains(src, wantBuild) {
			t.Errorf("%s: missing build constraint %q", file, wantBuild)
		}
		wantEmbed := fmt.Sprintf("//go:embed jsscan/jsscan-%s-%s", goos, goarch)
		if !strings.Contains(src, wantEmbed) {
			t.Errorf("%s: missing embed directive %q", file, wantEmbed)
		}
	}
}
