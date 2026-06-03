package bin

import (
	"errors"
	"runtime"
	"testing"
)

// synthHeader builds a minimal executable header for the given (goos, goarch)
// so the detector has something to decode without a real 66 MiB binary.
func synthHeader(goos, goarch string) []byte {
	switch goos {
	case "linux":
		h := make([]byte, 64)
		copy(h, []byte{0x7f, 'E', 'L', 'F'})
		h[4] = 2 // ELFCLASS64
		h[5] = 1 // little endian
		switch goarch {
		case "amd64":
			h[18], h[19] = 0x3E, 0x00 // EM_X86_64
		case "arm64":
			h[18], h[19] = 0xB7, 0x00 // EM_AARCH64
		}
		return h
	case "darwin":
		h := make([]byte, 32)
		copy(h, []byte{0xcf, 0xfa, 0xed, 0xfe}) // MH_MAGIC_64 (LE on disk)
		switch goarch {
		case "amd64":
			h[4], h[5], h[6], h[7] = 0x07, 0x00, 0x00, 0x01 // CPU_TYPE_X86_64
		case "arm64":
			h[4], h[5], h[6], h[7] = 0x0c, 0x00, 0x00, 0x01 // CPU_TYPE_ARM64
		}
		return h
	case "windows":
		return []byte{'M', 'Z', 0x90, 0x00}
	}
	return nil
}

func TestDetectBlobPlatform(t *testing.T) {
	cases := []struct {
		name     string
		data     []byte
		wantOS   string
		wantArch string
		wantOK   bool
	}{
		{"elf-amd64", synthHeader("linux", "amd64"), "linux", "amd64", true},
		{"elf-arm64", synthHeader("linux", "arm64"), "linux", "arm64", true},
		{"macho-amd64", synthHeader("darwin", "amd64"), "darwin", "amd64", true},
		{"macho-arm64", synthHeader("darwin", "arm64"), "darwin", "arm64", true},
		{"pe-windows", synthHeader("windows", ""), "windows", "", true},
		{"too-short", []byte{0x7f, 'E'}, "", "", false},
		{"garbage", []byte("not an executable header at all"), "", "", false},
		{"empty", nil, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotOS, gotArch, gotOK := detectBlobPlatform(tc.data)
			if gotOS != tc.wantOS || gotArch != tc.wantArch || gotOK != tc.wantOK {
				t.Fatalf("detectBlobPlatform = (%q, %q, %v), want (%q, %q, %v)",
					gotOS, gotArch, gotOK, tc.wantOS, tc.wantArch, tc.wantOK)
			}
		})
	}
}

func TestVerifyBlobForHost(t *testing.T) {
	// A blob built for the running platform must pass.
	if err := verifyBlobForHost(synthHeader(runtime.GOOS, runtime.GOARCH)); err != nil {
		t.Fatalf("host-matching blob rejected: %v", err)
	}

	// A blob built for a different OS must be flagged as a mismatch. This is
	// the exact failure mode that shipped: a darwin/arm64 blob inside a
	// linux/amd64 build.
	foreignOS := "darwin"
	if runtime.GOOS == "darwin" {
		foreignOS = "linux"
	}
	err := verifyBlobForHost(synthHeader(foreignOS, "arm64"))
	if err == nil {
		t.Fatalf("foreign-OS blob (%s) was not rejected", foreignOS)
	}
	if !errors.Is(err, ErrBinaryPlatformMismatch) {
		t.Fatalf("error is not ErrBinaryPlatformMismatch: %v", err)
	}

	// A blob for the right OS but wrong arch must also be flagged.
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	if err := verifyBlobForHost(synthHeader(runtime.GOOS, otherArch)); err == nil {
		t.Fatalf("wrong-arch blob (%s/%s) was not rejected", runtime.GOOS, otherArch)
	}

	// An unrecognized format must not trip the guard (no false positives).
	if err := verifyBlobForHost([]byte("totally unknown blob format")); err != nil {
		t.Fatalf("unknown format wrongly rejected: %v", err)
	}
}

// TestEmbeddedAuditBlobMatchesHost guards the host build path: whatever
// vigolium-audit blob `make build` embedded must run on the platform this
// test binary was built for. On a fresh clone the embed is the empty stub,
// so the check is skipped. This catches a mis-staged host blob (e.g. a
// darwin blob left in _bin while building on linux) at `make test` time.
func TestEmbeddedAuditBlobMatchesHost(t *testing.T) {
	data, err := binFS.ReadFile(embeddedName)
	if err != nil || len(data) < minBinarySize {
		t.Skip("no real vigolium-audit binary embedded (stub or fresh clone)")
	}
	goos, goarch, ok := detectBlobPlatform(data)
	if !ok {
		t.Fatalf("embedded vigolium-audit blob has an unrecognized executable format")
	}
	if goos != runtime.GOOS || (goarch != "" && goarch != runtime.GOARCH) {
		t.Fatalf("embedded vigolium-audit blob targets %s but this build is %s/%s — wrong host blob staged in _bin/",
			platformLabel(goos, goarch), runtime.GOOS, runtime.GOARCH)
	}
}
