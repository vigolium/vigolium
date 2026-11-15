package contract

import (
	"fmt"
	"reflect"

	"github.com/invopop/jsonschema"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// Envelope is the public mirror of the CLI's -j envelope spine (pkg/cli
// agentEnvelope, whose extras map and --json-legacy-keys alias cannot be
// reflected). A pkg/cli test keeps the two key sets identical.
type Envelope struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	// Kind is the document's shape: read, mutation or scan.
	Kind string `json:"kind,omitempty"`
	// OK is true exactly when the command exited 0, 3 or 4. A result document
	// whose command then failed carries false and Error.
	OK bool `json:"ok"`
	// Error is present exactly when OK is false.
	Error *ErrorBody `json:"error,omitempty"`
	// SoftFail states that --soft-fail forced the process exit status to 0.
	SoftFail bool `json:"soft_fail,omitempty"`
	// Changed, Action and DryRun are the mutation spine (kind "mutation").
	Changed *bool  `json:"changed,omitempty"`
	Action  string `json:"action,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
	// ProjectUUID is the project filter actually applied; DBPath the store the
	// command opened.
	ProjectUUID string `json:"project_uuid,omitempty"`
	DBPath      string `json:"db_path,omitempty"`
	// Total counts the whole result set; Offset/Limit describe this page.
	Total  int64 `json:"total"`
	Offset int   `json:"offset"`
	Limit  int   `json:"limit"`
	// Items is always an array, never null and never an object.
	Items []any `json:"items"`
	// Query / QueryArgv are the ready-to-run follow-up command.
	Query     string   `json:"query,omitempty"`
	QueryArgv []string `json:"query_argv,omitempty"`
	// GeneratedAt is RFC3339 UTC with exactly three fractional digits;
	// GeneratedAtMS the same instant in epoch milliseconds.
	GeneratedAt   string `json:"generated_at,omitempty"`
	GeneratedAtMS int64  `json:"generated_at_ms,omitempty"`
}

// EnvelopeCommon are the extras any envelope may carry, whatever the command.
type EnvelopeCommon struct {
	// ProjectSource says where the project selection came from.
	ProjectSource string `json:"project_source" jsonschema:"enum=flag,enum=env,enum=active_file,enum=default"`
	// ProjectScoped states whether a project filter was applied at all.
	ProjectScoped *bool `json:"project_scoped,omitempty"`
	// Warnings are advisories about how the result was produced.
	Warnings []string `json:"warnings,omitempty"`
	// GlobSources reports a --glob-db merge: matched vs loaded files.
	GlobSources *GlobSources `json:"glob_sources,omitempty"`
	// OutputBudget reports a page cut by --max-output-bytes.
	OutputBudget *OutputBudget `json:"output_budget,omitempty"`
	// SendsTraffic marks a command whose job is to send requests to a target.
	SendsTraffic bool `json:"sends_traffic,omitempty"`

	// The -o receipt: the document went to Output instead of stdout, so items
	// is empty and these describe the file.
	Artifact  string            `json:"artifact,omitempty"`
	Output    string            `json:"output,omitempty"`
	Bytes     int               `json:"bytes,omitempty"`
	SHA256    string            `json:"sha256,omitempty"`
	Complete  *bool             `json:"complete,omitempty"`
	Hint      string            `json:"hint,omitempty"`
	Artifacts []ReceiptArtifact `json:"artifacts,omitempty"`
}

// ReceiptArtifact is one file a command wrote.
type ReceiptArtifact struct {
	Format string `json:"format"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
}

// GlobSources is the glob_sources extra of a --glob-db read.
type GlobSources struct {
	Pattern     string        `json:"pattern"`
	Matched     int           `json:"matched"`
	Loaded      int           `json:"loaded"`
	Skipped     []GlobSkipped `json:"skipped"`
	ParseErrors int           `json:"parse_errors"`
}

// GlobSkipped is one --glob-db file the merge left out, and why.
type GlobSkipped struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// OutputBudget is the output_budget extra of a page --max-output-bytes cut.
type OutputBudget struct {
	MaxBytes   int `json:"max_bytes"`
	Returned   int `json:"returned"`
	Omitted    int `json:"omitted"`
	NextOffset int `json:"next_offset"`
}

// CommandSchema builds the full -j document schema for a registered command.
func CommandSchema(name string) (*Schema, error) {
	c, ok := LookupCommand(name)
	if !ok {
		return nil, fmt.Errorf("contract: no command %q is registered", name)
	}
	b := newBuilder()
	env := b.objectFor(Envelope{})
	mergeProperties(env, b.objectFor(EnvelopeCommon{}))
	if c.Extras != nil {
		if reflect.TypeOf(c.Extras).Kind() != reflect.Struct {
			return nil, fmt.Errorf("contract: command %q extras must be a struct, got %T", name, c.Extras)
		}
		mergeProperties(env, b.objectFor(c.Extras))
	}

	env.Properties.Set("schema_version", constSchema("integer", apicontract.SchemaVersion))
	env.Properties.Set("command", constSchema("string", c.Name))
	env.Properties.Set("ok", &Schema{Type: "boolean",
		Description: "true exactly when the command exited 0, 3 or 4; false documents carry error"})
	if c.Kind != "" {
		env.Properties.Set("kind", constSchema("string", c.Kind))
		env.Required = appendUnique(env.Required, "kind")
	} else {
		env.Properties.Delete("kind")
	}
	if c.Kind == KindMutation {
		env.Required = appendUnique(env.Required, "changed")
		env.Required = appendUnique(env.Required, "action")
	} else {
		for _, k := range []string{"changed", "action", "dry_run"} {
			env.Properties.Delete(k)
		}
	}
	env.Properties.Set("items", b.itemsSchema(c))
	env.AdditionalProperties = jsonschema.FalseSchema

	desc := c.Description
	if desc == "" {
		desc = "The -j document of `vigolium " + c.Name + "`."
	}
	if c.StreamFlag != "" {
		desc += " With " + c.StreamFlag + ", stdout is a stream of these documents, one per line (NDJSON), " +
			"ending with an error document if the stream stops on a failure."
	}
	return b.root(env, "vigolium "+c.Name+" -j", desc), nil
}

// itemsSchema is the `items` array of c's document.
func (b *builder) itemsSchema(c Command) *Schema {
	arr := &Schema{Type: "array"}
	if c.Item != nil {
		item := b.schemaFor(c.Item)
		if len(c.Variants) > 0 {
			alts := []*Schema{item}
			flags := ""
			for _, v := range c.Variants {
				alts = append(alts, b.schemaFor(v.Item))
				flags += " " + v.Flag
			}
			item = &Schema{AnyOf: alts, Description: "The default row, or the row shape selected by:" + flags}
		}
		arr.Items = item
	}
	if c.ItemsKind == ItemsObject {
		one := uint64(1)
		arr.MinItems, arr.MaxItems = &one, &one
		arr.Description = "Exactly one object: the command's single result."
	}
	return arr
}
