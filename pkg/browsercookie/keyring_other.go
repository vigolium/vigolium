//go:build !darwin && !linux

package browsercookie

import (
	"context"
	"runtime"
)

// keyringCheck reports on the platform credential store for the stores that
// need one.
//
// On Windows the key is wrapped with DPAPI and needs no approval, so the
// interesting failure is not access but scheme: Chrome 127 and later wrap it
// again under App-Bound Encryption, which no other process can unwrap. That is
// detected from the profile's own metadata and reported as its own check, so
// there is nothing left to test here.
func keyringCheck(ctx context.Context, s StoreInfo, probe bool) Check {
	return Check{
		Name:   "keyring:" + s.SafeStorage,
		Status: StatusSkip,
		Detail: "the platform credential store needs no approval on " + hostOS(),
		Hint:   "a Chrome 127+ profile is App-Bound encrypted and unreadable regardless; see the encryption check",
	}
}

// keyringWouldPrompt is false here: the platform key store needs no approval.
func keyringWouldPrompt(ctx context.Context, s StoreInfo) (bool, string) { return false, "" }

// hostOS names the operating system, for a diagnostic message.
func hostOS() string { return runtime.GOOS }
