package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// `finding -j` carries a stored recipe as proof, selectable with --fields,
// and the published schema accepts it; a finding without one omits the key.
func TestFindingViewCarriesProof(t *testing.T) {
	point := output.ProofInsertionPoint{Type: "URL_PARAM", Name: "id"}
	recipe := &output.ProofRecipe{
		Request: output.ProofRequest{Method: "GET", URL: "http://t.example/item?id=1+AND+SLEEP(6)",
			Headers: map[string]string{}, InsertionPoint: point, PayloadTemplate: "1 AND SLEEP(6)"},
		Control: output.ProofControl{Method: "GET", URL: "http://t.example/item?id=1+AND+SLEEP(0)",
			InsertionPoint: &point, PayloadTemplate: "1 AND SLEEP(0)"},
		Oracle:        output.ProofOracle{Kind: output.ProofTimingDelta, MinDeltaMS: 3000, Repeat: 2},
		Preconditions: output.ProofPreconditions{MethodSafe: true},
	}
	f := &database.Finding{ID: 7, ModuleID: "sqli-time-blind", Severity: "suspect", Proof: recipe}

	v := compactFindingView(f, nil, agentViewOptions{})
	assert.Equal(t, recipe, v["proof"])
	assert.Equal(t, recipe, compactFindingView(f, nil, agentViewOptions{fields: []string{"id", "proof"}})["proof"])
	_, has := compactFindingView(&database.Finding{ID: 8}, nil, agentViewOptions{})["proof"]
	assert.False(t, has)

	raw, err := json.Marshal(v["proof"])
	require.NoError(t, err)
	s, err := contract.DocumentSchema(output.ProofDocumentName)
	require.NoError(t, err)
	assert.NoError(t, contracttest.Check(s, raw))
}
