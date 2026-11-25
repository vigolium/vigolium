package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func proofFixture(value string) *output.ProofRecipe {
	point := output.ProofInsertionPoint{Type: "URL_PARAM", Name: "q"}
	return &output.ProofRecipe{
		Request: output.ProofRequest{Method: "GET", URL: "http://t.example.com/s?q=" + output.MarkerPlaceholder,
			Headers: map[string]string{}, InsertionPoint: point, PayloadTemplate: value},
		Control: output.ProofControl{Method: "GET", URL: "http://t.example.com/s?q=x", InsertionPoint: &point, PayloadTemplate: "x"},
		Oracle:  output.ProofOracle{Kind: output.ProofBodyContains, Value: value},
	}
}

// findings.proof round-trips, a re-detection's recipe replaces the stored one,
// and a re-detection that states none keeps it.
func TestFindingProofPersistsAndFollowsRedetection(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	rec := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/s", 200)

	load := func() *Finding {
		f := &Finding{}
		require.NoError(t, db.NewSelect().Model(f).Where("module_id = ?", "xss-light").Scan(ctx))
		return f
	}

	ev := makeFindingEvent("xss-light", "/s", severity.Low)
	ev.Proof = proofFixture("<b>" + output.MarkerPlaceholder + "</b>")
	require.NoError(t, repo.SaveFinding(ctx, ev, []string{rec}, "", DefaultProjectUUID))
	got := load()
	require.NotNil(t, got.Proof)
	assert.Equal(t, ev.Proof, got.Proof)

	again := makeFindingEvent("xss-light", "/s", severity.Low)
	again.Proof = proofFixture("<i>" + output.MarkerPlaceholder + "</i>")
	require.NoError(t, repo.SaveFinding(ctx, again, []string{rec}, "", DefaultProjectUUID))
	assert.Equal(t, again.Proof, load().Proof, "a re-detection's recipe replaces the stored one")

	bare := makeFindingEvent("xss-light", "/s", severity.Low)
	require.NoError(t, repo.SaveFinding(ctx, bare, []string{rec}, "", DefaultProjectUUID))
	assert.Equal(t, again.Proof, load().Proof, "a re-detection without a recipe keeps the stored one")

	var none Finding
	require.NoError(t, none.FromResultEvent(&output.ResultEvent{ModuleID: "m"}))
	assert.Nil(t, none.Proof)
}
