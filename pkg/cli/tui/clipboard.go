package tui

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// copyToClipboard writes text to the host clipboard by shelling out to the
// platform-native helper (pbcopy on macOS, xclip/wl-copy on Linux, clip on
// Windows). No SSH/OSC52 handling — this is intended for local use.
func copyToClipboard(text string) error {
	cmd, err := clipboardCommand()
	if err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func clipboardCommand() (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("pbcopy"), nil
	case "linux":
		if _, err := exec.LookPath("wl-copy"); err == nil {
			return exec.Command("wl-copy"), nil
		}
		if _, err := exec.LookPath("xclip"); err == nil {
			return exec.Command("xclip", "-selection", "clipboard"), nil
		}
		if _, err := exec.LookPath("xsel"); err == nil {
			return exec.Command("xsel", "--clipboard", "--input"), nil
		}
		return nil, fmt.Errorf("no clipboard tool found (install wl-copy, xclip, or xsel)")
	case "windows":
		return exec.Command("clip"), nil
	default:
		return nil, fmt.Errorf("clipboard not supported on %s", runtime.GOOS)
	}
}
