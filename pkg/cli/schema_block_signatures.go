package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium schema block-signatures` publishes the one WAF/CDN block and
// challenge signature table every classifier in the binary reads
// (waf.Signatures), so a caller that classifies responses it fetched itself
// generates its table from these rows instead of keeping a copy.

var schemaBlockSignaturesCmd = &cobra.Command{
	Use:   "block-signatures",
	Short: "List the WAF/CDN block, challenge and presence signatures the block classifier reads",
	Long: "List every row of the block classifier's signature table: a stable id, the vendor, the kind " +
		"(challenge: a vendor interstitial; block: a named vendor's block page or stamp; refused: a generic " +
		"phrase on a block status, naming no vendor; presence: a header the edge stamps on every response, " +
		"which never classifies alone), the match (status set, header name with exists/equals/contains/prefix/" +
		"regex/iregex over its values, body needle with contains/icontains/regex/iregex, a body size cap and a " +
		"Content-Type substring) and requires (row ids of which at least one must also match). Rows are grouped " +
		"by vendor; the first vendor with a firing non-presence row classifies a response.",
	Example: "  vigolium schema block-signatures\n  vigolium schema block-signatures -j",
	Args:    cobra.NoArgs,
	RunE:    runSchemaBlockSignatures,
}

func init() {
	schemaCmd.AddCommand(schemaBlockSignaturesCmd)
	registerCommandSchema(contract.Command{Name: "schema block-signatures", Item: waf.Signature{},
		Description: "One row per block-classifier signature: id (stable), vendor, kind (challenge, block, refused, presence), match {status, header, header_op, header_values, body_op, body, body_max_bytes, content_type} and requires (any-of row ids)."})
}

func runSchemaBlockSignatures(cmd *cobra.Command, _ []string) error {
	rows := waf.Signatures
	if globalJSON {
		return emitRead(cmd, "", rows, int64(len(rows)), 0, len(rows))
	}
	for _, s := range rows {
		var what []string
		if s.Match.Header != "" {
			what = append(what, fmt.Sprintf("header %s %s %s", s.Match.Header, s.Match.HeaderOp, strings.Join(s.Match.HeaderValues, "|")))
		}
		if s.Match.BodyOp != "" {
			what = append(what, fmt.Sprintf("body %s %q", s.Match.BodyOp, s.Match.Body))
		}
		if len(s.Requires) > 0 {
			what = append(what, "requires "+strings.Join(s.Requires, "|"))
		}
		fmt.Printf("%-48s %-9s %s\n", terminal.Cyan(s.ID), s.Kind, strings.Join(what, "; "))
	}
	return nil
}
