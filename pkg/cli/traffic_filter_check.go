package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// standardHTTPMethods are the methods a --method filter is expected to name.
// The set is open (WebDAV, custom verbs), so anything else only earns a hint.
var standardHTTPMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}

// checkTrafficSourceFilter rejects a --source label that no record carries and
// vigolium never writes: it can only be a typo, and it used to answer
// "total: 0". A known label with no rows yet is an honest empty answer, and a
// bridge label can be satisfied by live bridge traffic, so both pass.
func checkTrafficSourceFilter(ctx context.Context, db *database.DB, source, projectUUID string) error {
	source = strings.TrimSpace(source)
	if source == "" || database.IsBridgeRecordSource(source) || containsFold(database.KnownRecordSources, source) {
		return nil
	}
	stored, err := database.NewRepository(db).ListRecordSources(ctx, projectUUID)
	if err != nil || containsFold(stored, source) {
		return nil
	}
	candidates := slices.Clone(database.KnownRecordSources)
	candidates = append(candidates, stored...)
	return clicommon.CLIError{
		Err: fmt.Errorf("no record has source %q; sources in this store: %s",
			source, strings.Join(nonEmpty(stored), ", ")),
		DidYouMean: closestName(strings.ToLower(source), candidates),
	}
}

// hintNonStandardMethods notes, on stderr, a --method value that is not a
// standard HTTP method. Not an error: the set of methods is open.
func hintNonStandardMethods(methods []string) {
	for _, m := range methods {
		if !containsFold(standardHTTPMethods, m) {
			fmt.Fprintf(os.Stderr, "%s --method %s is not a standard HTTP method; it matches only records sent with exactly that verb\n",
				terminal.InfoSymbol(), m)
		}
	}
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func nonEmpty(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{"(none)"}
	}
	return out
}
