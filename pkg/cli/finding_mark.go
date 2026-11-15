package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	findingMarkAs   string
	findingMarkNote string
	findingMarkBy   string
)

// findingMarkVerdicts are the statuses `finding mark` sets. draft is the
// untriaged state findings arrive in, not a verdict anyone records.
var findingMarkVerdicts = []string{
	database.StatusFalsePositive, database.StatusConfirmed, database.StatusAcceptedRisk,
	database.StatusFixed, database.StatusTriaged,
}

// findingMarkDefaultActor is recorded when --by is not given.
const findingMarkDefaultActor = "cli"

var findingMarkCmd = &cobra.Command{
	Use:   "mark <id|hash>... --as <verdict>",
	Short: "Record a verdict on findings (false_positive, confirmed, accepted_risk, fixed, triaged)",
	Long: `Record a lifecycle verdict on one or more findings.

A finding is named by its numeric id (the ID column) or its finding_hash — the
full hash or a prefix of at least 12 characters. The hash is stable across
databases (merges, exports, other machines), the id is not. A prefix that
matches more than one finding is refused with the candidates listed.

  false_positive  not a bug (scanner noise, not exploitable)
  confirmed       reproduced: a human or a re-verification saw it happen
  accepted_risk   real, and the owner has decided to keep it
  fixed           resolved
  triaged         looks real, not yet reproduced

false_positive and accepted_risk are "dismissed": the --fail-on gate, 'scan
diff' and 'finding --new-since' leave them out by default. Every change is
stamped with --note and --by on the finding and appended to its status history.

A finding already at the verdict is reported unchanged and left alone. Any id
or hash that matches nothing in the current project exits 1 after the result
is written, so a typo is never mistaken for success.

Writes to the project database, or to a standalone .sqlite with -S --db
<file> (project scoping off). Refused under --glob-db and for a .jsonl --db
(both read a temporary copy that is discarded) and under --read-only.`,
	Example: `  vigolium finding mark 42 --as false_positive --note "static asset, no user input"
  vigolium finding mark 3f9a0c2b71de 42 43 --as confirmed --by alice -j`,
	Args: cobra.MinimumNArgs(1),
	RunE: runFindingMark,
}

func init() {
	findingCmd.AddCommand(findingMarkCmd)
	f := findingMarkCmd.Flags()
	f.StringVar(&findingMarkAs, "as", "", "Verdict to record: "+strings.Join(findingMarkVerdicts, "|")+" (required)")
	f.StringVar(&findingMarkNote, "note", "", "Why: stored with the verdict and in the finding's status history")
	f.StringVar(&findingMarkBy, "by", "", "Who decided (default \""+findingMarkDefaultActor+"\")")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Write to the standalone .sqlite named by --db with project scoping off")
	f.StringVar(&globalGlobDB, "glob-db", "", "Not supported: a --glob-db merge is a temporary copy, so a verdict written there would be lost")
	_ = f.MarkHidden("glob-db")
}

// findingSelectors splits the positional arguments into ids and hash prefixes.
// All digits and shorter than a hash prefix is an id; anything else must be a
// hex hash prefix of at least database.MinFindingHashPrefix characters.
func findingSelectors(args []string) (ids []int64, hashes []string, err error) {
	for _, raw := range args {
		a := strings.TrimPrefix(strings.TrimSpace(raw), "#")
		if a == "" {
			continue
		}
		if len(a) < database.MinFindingHashPrefix && isAllDigits(a) {
			id, perr := strconv.ParseInt(a, 10, 64)
			if perr != nil || id <= 0 {
				return nil, nil, usageErrorf("invalid finding id %q", raw)
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
			continue
		}
		if verr := database.ValidateFindingHashPrefix(a); verr != nil {
			return nil, nil, usageErrorf("%v", verr)
		}
		hashes = append(hashes, strings.ToLower(a))
	}
	if len(ids) == 0 && len(hashes) == 0 {
		return nil, nil, usageErrorf("finding mark needs at least one finding id or hash")
	}
	return ids, hashes, nil
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// validateFindingMarkSource refuses the stores a verdict cannot persist in.
func validateFindingMarkSource() error {
	if strings.TrimSpace(globalGlobDB) != "" {
		return usageErrorf("finding mark cannot write through --glob-db: the merge is a temporary copy that is discarded on exit, so the verdict would be lost. Mark against one source with -S --db <file.sqlite>")
	}
	if path := strings.TrimSpace(globalDB); path != "" && isJSONLSource(path) {
		return usageErrorf("finding mark cannot write to a .jsonl export (%s): it is loaded into a temporary database that is discarded on exit. Mark in the project database, or in a .sqlite with -S --db", path)
	}
	return nil
}

func runFindingMark(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	verdict := strings.ToLower(strings.TrimSpace(findingMarkAs))
	if verdict == "" {
		return usageErrorf("finding mark needs --as <verdict> (%s)", strings.Join(findingMarkVerdicts, ", "))
	}
	if !slices.Contains(findingMarkVerdicts, verdict) {
		return usageErrorf("invalid --as %q (want one of: %s)", findingMarkAs, strings.Join(findingMarkVerdicts, ", "))
	}
	ids, hashes, err := findingSelectors(args)
	if err != nil {
		return err
	}
	if err := validateFindingMarkSource(); err != nil {
		return err
	}
	actor := strings.TrimSpace(findingMarkBy)
	if actor == "" {
		actor = findingMarkDefaultActor
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	var db *database.DB
	if statelessReadRequested() {
		db, err = openStatelessDB(globDBSkipSet{})
	} else {
		db, err = getDB()
	}
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	res, err := database.NewRepository(db).UpdateFindingStatusScoped(context.Background(), projectUUID, database.FindingStatusUpdate{
		IDs: ids, Hashes: hashes, Status: verdict, Note: strings.TrimSpace(findingMarkNote), Actor: actor,
	})
	if err != nil {
		var amb *database.AmbiguousFindingHashError
		if errors.As(err, &amb) {
			return usageErrorf("%v", amb)
		}
		return err
	}

	if globalJSON {
		unchanged := res.Unchanged
		if unchanged == nil {
			unchanged = []database.FindingStatusChange{}
		}
		notFound := res.NotFound
		if notFound == nil {
			notFound = []string{}
		}
		if err := emitMutation(cmd, "", mutationResult{
			Changed: len(res.Changed) > 0,
			Action:  "update",
			Items:   res.Changed,
			Extra: map[string]any{
				"status":    verdict,
				"unchanged": unchanged,
				"not_found": notFound,
			},
		}, withProjectScope(projectUUID), withDBPath(resolvedReadDBPath())); err != nil {
			return err
		}
	} else {
		printFindingMarkResult(res)
	}

	if len(res.NotFound) > 0 {
		where := ""
		if projectUUID != "" {
			where = " in the current project"
		}
		return codedErrorf(apicontract.CodeFindingNotFound, "%d finding(s) not found%s: %s",
			len(res.NotFound), where, strings.Join(res.NotFound, ", "))
	}
	return nil
}

func printFindingMarkResult(res *database.FindingStatusResult) {
	short := func(h string) string {
		if len(h) > database.MinFindingHashPrefix {
			return h[:database.MinFindingHashPrefix]
		}
		return h
	}
	for _, c := range res.Changed {
		fmt.Printf("%s #%d %s  %s → %s\n", terminal.SuccessSymbol(), c.ID, terminal.Gray(short(c.FindingHash)),
			c.From, terminal.BoldYellow(c.To))
	}
	for _, c := range res.Unchanged {
		fmt.Printf("%s #%d %s  already %s\n", terminal.InfoSymbol(), c.ID, terminal.Gray(short(c.FindingHash)), c.To)
	}
	for _, n := range res.NotFound {
		fmt.Printf("%s %s: no such finding\n", terminal.WarningSymbol(), n)
	}
}
