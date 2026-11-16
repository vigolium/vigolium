//go:build linux

package browsercookie

import (
	"context"
	"os"
	"strings"
)

// keyringCheck reports on access to the Chromium key held by the freedesktop
// Secret Service (GNOME Keyring) or KWallet.
//
// There is no cheap, non-prompting equivalent of macOS's attribute read here:
// querying the Secret Service means opening a session on the session bus, and
// an unlocked-keyring prompt may follow. What can be checked for free is the
// precondition that defeats this most often — no session bus at all, which is
// the normal state over SSH and in a container, and the reason a read that
// works on the desktop returns nothing in CI.
func keyringCheck(ctx context.Context, s StoreInfo, probe bool) Check {
	name := "keyring:" + s.SafeStorage
	if !envSet("DBUS_SESSION_BUS_ADDRESS") && !envSet("XDG_RUNTIME_DIR") {
		return Check{
			Name:   name,
			Status: StatusFail,
			Detail: "no D-Bus session bus in this environment (DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are both unset)",
			Hint:   "the keyring cannot be reached from here — run inside the desktop session, or launch the browser with --password-store=basic so its cookies are not keyring-encrypted",
		}
	}
	return Check{
		Name:   name,
		Status: StatusOK,
		Detail: "a session bus is available; the keyring will be queried when a cookie is decrypted",
		Hint:   "a locked keyring prompts on first read, and KWallet may ask for its own approval",
	}
}

// keyringWouldPrompt is false here: whether the Secret Service prompts (a
// locked keyring) is not knowable without opening a session on the bus, and the
// common v10 store needs no keyring at all. --no-prompt is a macOS guarantee.
func keyringWouldPrompt(ctx context.Context, s StoreInfo) (bool, string) { return false, "" }

// envSet reports whether an environment variable is set and non-empty.
func envSet(name string) bool { return strings.TrimSpace(os.Getenv(name)) != "" }
