package cli

import (
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// -S used to mean two different things depending on which command you typed it
// after: --stateless on scan/export/finding/replay/agent-audit, and
// --scan-on-receive on server/ingest. A third group (log, and traffic's
// --save-to-vigolium-db path) rejected it outright with "unknown shorthand
// flag" — a non-zero exit and no output, which is the worst of the three: a
// driver passing -S for safety got a control that looked live and could only
// ever report zero rows.
//
// Two changes retire the trap:
//
//  1. On server/ingest the shorthand is retired. --scan-on-receive is the only
//     spelling; -S is a usage error (exit 2) naming it, for one release, so a
//     command line that meant "scan what you receive" fails loudly rather than
//     silently turning into "scan nothing". After that release the hidden flag
//     goes and addStatelessShorthand gives these two commands -S/--stateless
//     like every other.
//  2. --stateless is accepted everywhere as a persistent root flag. On a command
//     where it is meaningless it is a documented no-op — a flag that is harmless
//     everywhere is one a driver never has to keep a per-command acceptance
//     table for.
//
// The root flag is deliberately LONG-ONLY. Giving it the -S shorthand at root
// level would collide with the local -S the read commands and the deprecated
// scan-on-receive tombstone still register, and pflag resolves that by panicking
// at startup rather than by picking one.

// retiredScanOnReceiveShorthand backs the hidden -S tombstone on server/ingest.
// Its value is never used: typing the flag at all is the error.
var retiredScanOnReceiveShorthand bool

// retiredScanOnReceiveFlag is the hidden long name behind the -S tombstone.
const retiredScanOnReceiveFlag = "scan-on-receive-shorthand"

// registerScanOnReceiveFlags declares --scan-on-receive plus the hidden -S
// tombstone on a server/ingest flagset.
func registerScanOnReceiveFlags(flags *pflag.FlagSet, usage string) {
	flags.BoolVar(&globalScanOnReceive, "scan-on-receive", false, usage)
	// A hidden second flag rather than a shorthand on the first: pflag binds a
	// shorthand to one flag, and the point is to reject the old spelling while
	// the long one keeps working.
	flags.BoolVarP(&retiredScanOnReceiveShorthand, retiredScanOnReceiveFlag, "S", false,
		"Retired: -S no longer means --scan-on-receive")
	_ = flags.MarkHidden(retiredScanOnReceiveFlag)
}

// rejectRetiredScanOnReceive fails a server/ingest command line that used -S.
// Any value counts (-S=false too): the letter is changing meaning, and a usage
// error is the only answer that is right for both readings. Called from the
// root PersistentPreRunE so every command that registered the tombstone is
// covered without repeating the check.
func rejectRetiredScanOnReceive(cmd *cobra.Command) error {
	f := cmd.Flags().Lookup(retiredScanOnReceiveFlag)
	if f == nil || !f.Changed {
		return nil
	}
	return usageErrorf("-S no longer means --scan-on-receive on %s; pass --scan-on-receive to scan received traffic, or --stateless for a throwaway DB", cmd.Name())
}

// registerStatelessRootFlag declares the persistent, long-only --stateless so it
// parses on every command. Commands that give it real meaning register their own
// local -S/--stateless, which shadows this one; everywhere else it lands here and
// does nothing beyond being accepted.
func registerStatelessRootFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&globalStateless, "stateless", false,
		"Read from --db (a .jsonl export or standalone .sqlite) with project scoping off, "+
			"or scan into a throwaway database. Accepted (and ignored) on commands where neither applies.")
	// Hidden at root so `vigolium --help` doesn't advertise a flag that is inert
	// for most subcommands; the commands where it means something document it in
	// their own help.
	_ = cmd.PersistentFlags().MarkHidden("stateless")
}

// statelessShorthandFlag is the hidden long name behind the injected -S.
//
// Not "stateless": that name belongs to the root's persistent long-only flag,
// and whether cobra has already merged it into a command's flagset depends on
// what touched the command first (help rendering, a test that executed it, ...).
// Keying the injection on the "stateless" name made the outcome depend on that
// merge order. A distinct name never collides with the merged flag, so the
// injection is the same however the tree was used before; --stateless itself
// keeps resolving to the root persistent flag, bound to the same variable.
const statelessShorthandFlag = "stateless-shorthand"

// addStatelessShorthand gives cmd and every subcommand a local -S (bound to
// globalStateless, like --stateless) when the letter is free, so it means one
// thing everywhere.
//
// Not the root persistent flag, which is long-only: a shorthand there would
// collide with the commands that still bind -S themselves, and pflag resolves
// that by panicking at startup rather than by shadowing. Registering per command
// is what lets those keep theirs while every other command accepts the letter.
//
// One structural guard, no exemption list: the letter is free unless the
// command, or a persistent flag it inherits, already binds it. That covers the
// commands with their own -S/--stateless and the `server`/`ingest` retired
// --scan-on-receive tombstone, and self-heals when the tombstone is finally
// removed. Inherited flags are read from the ancestors' PersistentFlags rather
// than from the command's merged flagset, so the guard never depends on whether
// cobra has merged them yet. A name-keyed exemption list would rot in both
// directions: rename a command and it silently stops matching; add a third -S
// owner and the two mechanisms disagree about which is authoritative.
//
// On a read command -S is meaningful (read --db with project scoping off);
// elsewhere it is a documented no-op. Both beat "unknown shorthand flag", which
// exits non-zero with no output — a control that looks live and can only ever
// report nothing. Idempotent: a second walk finds the letter taken everywhere.
func addStatelessShorthand(c *cobra.Command) {
	for _, sub := range c.Commands() {
		addStatelessShorthand(sub)
	}
	if shorthandTaken(c, "S") {
		return
	}
	c.Flags().BoolVarP(&globalStateless, statelessShorthandFlag, "S", false,
		"Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; ignored where it does not apply")
	_ = c.Flags().MarkHidden(statelessShorthandFlag)
	statelessInjected[c] = true
}

// shorthandTaken reports whether letter is bound on c: by its own local or
// persistent flags, or by a persistent flag of any ancestor. It never triggers
// cobra's persistent-flag merge, so its answer is the same before and after.
func shorthandTaken(c *cobra.Command, letter string) bool {
	if c.Flags().ShorthandLookup(letter) != nil || c.PersistentFlags().ShorthandLookup(letter) != nil {
		return true
	}
	for p := c.Parent(); p != nil; p = p.Parent() {
		if p.PersistentFlags().ShorthandLookup(letter) != nil {
			return true
		}
	}
	return false
}

// statelessInjected records the commands addStatelessShorthand gave an injected
// -S to. They are exactly the commands where the letter is accepted because it
// is accepted everywhere, not because the command does anything with it — and
// so exactly the set where it may be a no-op.
//
// Recorded at registration rather than listed by name: the injection has two
// structural guards and no exemption table, so a hand-written list of "commands
// without real -S" would be a second, drifting copy of a decision already made
// here.
var statelessInjected = map[*cobra.Command]bool{}

// statelessReaderCommands are the injected-'-S' commands where the flag still
// means something, as command paths without the root name.
//
// These reach a read path that consults statelessReadRequested even though they
// never registered -S themselves, so the injected flag is live on them.
var statelessReaderCommands = []string{
	"log", "log ls", "fuzz", "db list",
	"scan ls", "status", "finding show",
}

// warnNoOpStateless tells the operator when -S/--stateless was accepted and
// ignored.
//
// The flag parses on every command so that a driver passing it for safety never
// gets "unknown shorthand flag" — a non-zero exit with no output. But silence
// has its own failure mode: `-S` reads as "do not touch my project database",
// and on a command that writes, it does not mean that. One line naming the
// command is the difference between a wrong belief and a corrected one.
//
// Not in a machine-output mode, and not for the commands that genuinely honor
// it. Rejecting instead of warning is deferred: it would break command lines
// that work today.
func warnNoOpStateless(cmd *cobra.Command) {
	if !globalStateless || machineOutputMode() {
		return
	}
	if !statelessInjected[cmd] {
		return // the command registered its own -S, so it means something here
	}
	path := commandPathWithoutRoot(cmd)
	if slices.Contains(statelessReaderCommands, path) {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s has no effect on %q and is ignored\n",
		terminal.WarnPrefix(), terminal.BoldCyan("-S/--stateless"), path)
}
