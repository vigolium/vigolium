//go:build unix

package cli

import "syscall"

// execReplace replaces the current process image with target, passing argv
// (argv[0] is the program name, per exec convention) and env. On success it
// never returns; it returns an error only when the exec call itself fails.
func execReplace(target string, argv []string, env []string) error {
	return syscall.Exec(target, argv, env)
}
