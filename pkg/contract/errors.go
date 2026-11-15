package contract

import (
	"fmt"

	"github.com/invopop/jsonschema"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// ErrorEnvelope is the public mirror of the CLI's -j error document (pkg/cli
// agentErrorEnvelope): what a failed -j command prints to stdout instead of a
// result. A pkg/cli test keeps the two key sets identical.
type ErrorEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	// OK is always false on an error document.
	OK    bool      `json:"ok"`
	Error ErrorBody `json:"error"`
	// DBPath names the store the command had opened, when it got that far.
	DBPath string `json:"db_path,omitempty"`
	// SoftFail states that --soft-fail forced the process exit status to 0.
	SoftFail      bool   `json:"soft_fail,omitempty"`
	GeneratedAt   string `json:"generated_at"`
	GeneratedAtMS int64  `json:"generated_at_ms"`
}

// ErrorBody is the error object: a stable code to branch on, a message for a
// human, and the exit code the command concluded.
type ErrorBody struct {
	Code     apicontract.ErrorCode `json:"code"`
	Message  string                `json:"message"`
	ExitCode int                   `json:"exit_code"`
	// Hint names the next step, in one sentence.
	Hint string `json:"hint,omitempty"`
	// DidYouMean is the nearest valid spelling of what was typed: a flag with
	// its dashes, a command path, or an enum value.
	DidYouMean string `json:"did_you_mean,omitempty"`
	// UsageArgv prints the failing command's flags as a document.
	UsageArgv []string `json:"usage_argv,omitempty"`
}

// ErrorSchema builds the schema of the -j error document. error.code is the
// closed apicontract vocabulary; exit_code is one of the documented non-zero
// exit codes.
func ErrorSchema() *Schema {
	b := newBuilder()
	env := b.objectFor(ErrorEnvelope{})
	env.Properties.Set("schema_version", constSchema("integer", apicontract.SchemaVersion))
	env.Properties.Set("ok", constSchema("boolean", false))
	if body := b.resolve(propertyOf(env, "error")); body != nil {
		body.Properties.Set("exit_code", &Schema{Type: "integer", Enum: []any{
			apicontract.ExitError, apicontract.ExitUsageError, apicontract.ExitFuzzMatch,
			apicontract.ExitFailOnGate, apicontract.ExitIncomplete,
		}})
	}
	env.AdditionalProperties = jsonschema.FalseSchema
	return b.root(env, "vigolium -j error",
		"What a failed -j command prints on stdout: ok:false and an error object. Branch on error.code, never on the message.")
}

// DocumentSchema builds the schema of a registered standalone document.
func DocumentSchema(name string) (*Schema, error) {
	d, ok := LookupDocument(name)
	if !ok {
		return nil, fmt.Errorf("contract: no document %q is registered in this build", name)
	}
	b := newBuilder()
	s := b.schemaFor(d.Value)
	if s.Ref != "" {
		s = &Schema{Ref: s.Ref}
	}
	return b.root(s, "vigolium "+d.Name, d.Description), nil
}

func propertyOf(s *Schema, name string) *Schema {
	if s == nil || s.Properties == nil {
		return nil
	}
	p, _ := s.Properties.Get(name)
	return p
}
