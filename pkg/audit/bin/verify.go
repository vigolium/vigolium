package bin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
)

// ErrBinaryPlatformMismatch is returned when the embedded vigolium-audit blob
// targets a different OS/arch than the running process. This indicates a
// release packaging bug: the wrong-platform audit binary was staged into the
// embed path when vigolium was cross-compiled. See build/scripts/
// stage-audit-blob.sh and the per-target goreleaser pre-hook.
var ErrBinaryPlatformMismatch = errors.New("vigolium-audit binary platform mismatch")

// detectBlobPlatform inspects the leading bytes of an executable blob and
// reports the GOOS/GOARCH it targets, matched to Go's naming (amd64/arm64).
// ok is false when the format is unrecognized — callers must not treat an
// unknown format as a mismatch, only a confidently-decoded foreign platform.
//
// Detection is intentionally minimal: it reads the executable container
// magic (ELF / Mach-O / PE) plus the machine field, which is all the guard
// needs to catch a Mach-O blob shipped inside a Linux build (the bug this
// guard exists to prevent). goarch may be "" when the format is known but the
// machine field is unrecognized.
func detectBlobPlatform(data []byte) (goos, goarch string, ok bool) {
	// ELF — used by our linux targets. e_ident[EI_DATA] at offset 5 gives
	// endianness; e_machine is a 2-byte field at offset 0x12.
	if len(data) >= 20 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		var machine uint16
		if data[5] == 2 { // ELFDATA2MSB (big endian)
			machine = binary.BigEndian.Uint16(data[18:20])
		} else {
			machine = binary.LittleEndian.Uint16(data[18:20])
		}
		switch machine {
		case 0x3E: // EM_X86_64
			goarch = "amd64"
		case 0xB7: // EM_AARCH64
			goarch = "arm64"
		}
		return "linux", goarch, true
	}

	// Mach-O 64-bit thin, little-endian (our darwin x86_64 / arm64 blobs).
	// On-disk magic MH_MAGIC_64 (0xFEEDFACF) is byte-reversed on LE hosts.
	if len(data) >= 8 && data[0] == 0xcf && data[1] == 0xfa && data[2] == 0xed && data[3] == 0xfe {
		cpu := binary.LittleEndian.Uint32(data[4:8])
		switch cpu {
		case 0x01000007: // CPU_TYPE_X86_64
			goarch = "amd64"
		case 0x0100000c: // CPU_TYPE_ARM64
			goarch = "arm64"
		}
		return "darwin", goarch, true
	}

	// PE / Windows. Arch detection is skipped: vigolium-audit is not shipped
	// for windows today, but recognizing the OS keeps the guard honest if it
	// ever is mis-staged.
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return "windows", "", true
	}

	return "", "", false
}

// verifyBlobForHost confirms the embedded vigolium-audit blob targets the
// platform this binary is running on. It returns ErrBinaryPlatformMismatch
// (wrapped with detail) when the blob is for a different OS/arch, converting a
// would-be "exec format error" into an actionable report. An unrecognized
// format returns nil — the guard never blocks on uncertainty; a genuinely
// broken blob will surface its own exec error downstream.
func verifyBlobForHost(data []byte) error {
	goos, goarch, ok := detectBlobPlatform(data)
	if !ok {
		return nil
	}
	if goos != runtime.GOOS || (goarch != "" && goarch != runtime.GOARCH) {
		return fmt.Errorf(
			"%w: embedded binary targets %s but this build runs on %s/%s — the wrong-platform audit binary was embedded at release time, please report this",
			ErrBinaryPlatformMismatch, platformLabel(goos, goarch), runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

func platformLabel(goos, goarch string) string {
	if goarch == "" {
		return goos + "/(unknown arch)"
	}
	return goos + "/" + goarch
}
