package jsext

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTranspileTS(t *testing.T) {
	source := `
interface Greeting {
  name: string;
  message: string;
}

const greet = (g: Greeting): string => {
  return g.name + ": " + g.message;
};

module.exports = { greet };
`
	js, err := TranspileTS(source, "test.ts")
	require.NoError(t, err)
	assert.NotEmpty(t, js)

	// Type annotations should be stripped
	assert.NotContains(t, js, "interface Greeting")
	assert.NotContains(t, js, ": string")

	// Code logic should be preserved
	assert.Contains(t, js, "greet")
	assert.Contains(t, js, "module.exports")
}

func TestTranspileTSError(t *testing.T) {
	// Invalid syntax that esbuild cannot parse
	source := `
const x: = ;
`
	_, err := TranspileTS(source, "bad.ts")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TypeScript transpile error")
}

func TestTranspileTSPreservesExports(t *testing.T) {
	source := `
module.exports = {
  id: "test-module" as const,
  name: "Test Module",
  type: "active" as const,

  scanPerRequest(ctx: any): any[] | null {
    return null;
  }
};
`
	js, err := TranspileTS(source, "module.ts")
	require.NoError(t, err)

	// module.exports should survive transpilation
	assert.Contains(t, js, "module.exports")
	assert.Contains(t, js, "test-module")
	assert.Contains(t, js, "scanPerRequest")

	// TypeScript-specific syntax should be removed
	assert.NotContains(t, js, "as const")
	assert.True(t, !strings.Contains(js, ": any[]") && !strings.Contains(js, ": any"))
}
