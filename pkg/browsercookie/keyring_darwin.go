//go:build darwin

package browsercookie

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
)

// keyringCheck reports whether the store's decryption key can be read from the
// login keychain.
//
// Two steps, because they answer different questions and only one of them
// costs anything:
//
//  1. Read the item's attributes. This never prompts and never touches the
//     secret, and it distinguishes "the browser has stored a key" from "this
//     profile has none" — a fresh or automation profile legitimately has none
//     and still decrypts, via the mock password Chromium uses when launched
//     with --use-mock-keychain.
//  2. Read the secret itself, which is what raises the approval prompt. Only
//     when the caller asked to probe.
//
// The secret is never captured: step 2 sends stdout to io.Discard, so the key
// does not enter this process's memory at all. The exit status is the answer.
func keyringCheck(ctx context.Context, s StoreInfo, probe bool) Check {
	name := "keyring:" + s.SafeStorage

	exists, detail := keychainItemExists(ctx, s)
	if !exists {
		return Check{
			Name:   name,
			Status: StatusWarn,
			Detail: "no such keychain item" + detail,
			Hint:   "the browser has never stored a key under this name; an automation profile launched with --use-mock-keychain still decrypts, a normal profile will not",
		}
	}

	if !probe {
		return Check{
			Name:   name,
			Status: StatusOK,
			Detail: "keychain item present (access not tested)",
			Hint:   "run `vigolium kit cookies doctor` to test access and grant it",
		}
	}

	granted, detail := keychainSecretReadable(ctx, s)
	if granted {
		return Check{
			Name:   name,
			Status: StatusOK,
			Detail: "keychain access granted",
		}
	}
	return Check{
		Name:   name,
		Status: StatusFail,
		Detail: "keychain access denied" + detail,
		Hint:   keychainAllowHint + "; over SSH or in a headless session no prompt can be shown, so run this in a desktop session",
	}
}

// keychainItemExists reads the item's attributes, which requires no approval
// and discloses no secret.
func keychainItemExists(ctx context.Context, s StoreInfo) (bool, string) {
	return runSecurity(ctx, s)
}

// keychainSecretReadable attempts the privileged read, discarding the secret.
//
// The -w flag makes security(1) print the password; it is sent to io.Discard
// rather than captured, so this reports only whether the read was permitted.
func keychainSecretReadable(ctx context.Context, s StoreInfo) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, keyringPromptTimeout)
	defer cancel()

	ok, detail := runSecurity(ctx, s, "-w")
	if !ok && ctx.Err() != nil {
		return false, ": timed out waiting for the keychain prompt to be answered"
	}
	return ok, detail
}

// runSecurity runs `security find-generic-password` for the store's Safe
// Storage item, with extra appended, and reports whether it succeeded. Stdout
// goes to io.Discard so a secret printed by -w never enters this process; the
// detail is the first line of stderr on failure.
func runSecurity(ctx context.Context, s StoreInfo, extra ...string) (bool, string) {
	args := append([]string{"find-generic-password", "-s", s.SafeStorage, "-a", s.KeyringAccount}, extra...)
	cmd := exec.CommandContext(ctx, securityBinary, args...)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return false, detailFrom(stderr.String())
	}
	return true, ""
}

// keychainAllowHint is the one piece of advice every keychain message gives.
//
// "Allow" grants this one read. "Always Allow" adds the reading program to the
// item's access list for good — and the reading program is /usr/bin/security
// (or, in a cgo build, whichever binary asked), so from then on ANY process on
// the machine that runs `security find-generic-password -w` reads the
// browser's Safe Storage key without a prompt, and with it every cookie of
// every site. The convenience is a standing credential grant to all local
// code, which is the wrong trade for a tool that reads cookies a handful of
// times per engagement.
const keychainAllowHint = `choose "Allow" (this read only) at the macOS prompt, not "Always Allow": that adds /usr/bin/security to the key's access list, after which any process on this machine can read the browser's key, and every cookie, without asking`

// keyringWouldPrompt reports whether reading this store's cookies asks the
// login keychain for its key — which raises the approval dialog unless a
// standing grant exists, and nothing short of asking can tell which. The item
// lookup it does is the attribute read that never prompts. A store whose item
// does not exist (an automation profile launched with --use-mock-keychain)
// decrypts without the keychain and does not prompt.
func keyringWouldPrompt(ctx context.Context, s StoreInfo) (bool, string) {
	if s.Family != FamilyChromium || s.SafeStorage == "" {
		return false, ""
	}
	if exists, _ := keychainItemExists(ctx, s); !exists {
		return false, ""
	}
	return true, "--no-prompt: the key is in the macOS login keychain (" + s.SafeStorage + "), and reading it raises an approval prompt; run without --no-prompt in a desktop session, or `vigolium kit cookies doctor` to test access"
}

// securityBinary is the absolute path to Apple's keychain tool. Absolute so
// the lookup cannot be redirected by PATH.
const securityBinary = "/usr/bin/security"

// detailFrom trims a tool's stderr into a one-line detail suffix.
func detailFrom(stderr string) string {
	s := strings.TrimSpace(stderr)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return ": " + s
}
