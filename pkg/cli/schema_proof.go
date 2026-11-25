package cli

import (
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/output"
)

// `vigolium schema proof` publishes the proof recipe a finding may carry
// (finding -j proof, output.ProofRecipe): the attack request, its control, a
// closed-set oracle and preconditions. pkg/output registers the document so a
// module test validates against exactly what this prints.

var schemaProofCmd = &cobra.Command{
	Use:   "proof",
	Short: "Print the proof recipe schema (finding -j proof: request, control, oracle, preconditions)",
	Long: "Print the JSON Schema of the proof recipe a finding carries when its module opted in: the attack " +
		"request, a control that differs only in the value at the insertion point (or the baseline record), " +
		"one oracle from a closed set (body_contains, body_absent, status_differs, header_contains, timing_delta, " +
		"oast_interaction, body_similarity) and preconditions. " + output.MarkerPlaceholder + " marks where the " +
		"caller substitutes the marker it mints.",
	Example: "  vigolium schema proof\n  vigolium schema proof -j",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		s, err := contract.DocumentSchema(output.ProofDocumentName)
		if err != nil {
			return err
		}
		return emitSchema(cmd, schemaEntry{Name: output.ProofDocumentName, Kind: schemaKindDocument}, s)
	},
}

func init() {
	schemaCmd.AddCommand(schemaProofCmd)
}
