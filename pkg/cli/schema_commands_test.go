package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `schema commands -j` publishes every declared command with its traits, so a
// driver can build its reach and deny tables from it.
func TestSchemaCommandsPublishesTraits(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaCommands(schemaCommandsCmd, nil) })
	items := doc["items"].([]any)
	rows := map[string]map[string]any{}
	for _, it := range items {
		r := it.(map[string]any)
		rows[r["command"].(string)] = r
	}
	for path := range commandTraits {
		if path == "" {
			continue
		}
		_, ok := rows[path]
		assert.True(t, ok, "%q is published", path)
	}

	stop := rows["scan stop"]
	require.NotNil(t, stop)
	assert.Equal(t, true, stop["writes_global"], "scan stop drops a sentinel in the shared sessions dir")
	assert.Equal(t, true, stop["mutates"])
	assert.Equal(t, false, stop["sends_traffic"])

	fuzz := rows["fuzz"]
	assert.Equal(t, true, fuzz["sends_traffic"])
	assert.Equal(t, "write", fuzz["db"])
	assert.Equal(t, true, fuzz["reads_store"])

	traffic := rows["traffic"]
	assert.Equal(t, false, traffic["mutates"], "a store read changes nothing")
	assert.Equal(t, false, traffic["writes_global"])
	assert.Equal(t, "read", traffic["db"])

	for _, path := range []string{"config set", "scope add", "skills install", "update", "agent cancel"} {
		assert.Equal(t, true, rows[path]["writes_global"], path)
	}
	assert.Equal(t, false, rows["version"]["writes_global"])

	// Value flags: -n/--limit take a value (the drift §0 of the 0.5.7 sync
	// found), a bool such as --ignore-scope does not.
	mine := rows["kit param-mine"]["value_flags"].([]any)
	assert.Contains(t, mine, "--limit")
	assert.Contains(t, mine, "-n")
	assert.NotContains(t, mine, "--ignore-scope")
	assert.NotContains(t, mine, "--require-scope")
	assert.NotContains(t, mine, "--config", "root flags are listed once, globally")

	global := doc["global_value_flags"].([]any)
	assert.Contains(t, global, "--config")
	assert.Contains(t, global, "--db")
	assert.NotContains(t, global, "--json")
}

func TestSchemaCommandsOneRow(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaCommands(schemaCommandsCmd, []string{"scan", "stop"}) })
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, "scan stop", items[0].(map[string]any)["command"])

	err := runSchemaCommands(schemaCommandsCmd, []string{"no-such-command"})
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}
