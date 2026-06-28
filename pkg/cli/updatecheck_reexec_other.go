//go:build !unix

package cli

import (
	"os"
	"os/exec"
)

// execReplace runs target as a child process (Windows lacks a real exec(2)),
// forwarding stdio, then exits with the child's status. It returns an error only
// when the child cannot be started; on success it never returns.
func execReplace(target string, argv []string, env []string) error {
	cmd := exec.Command(target, argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		os.Exit(0)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	return err
}
