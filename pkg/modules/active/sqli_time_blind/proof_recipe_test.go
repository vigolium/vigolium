package sqli_time_blind

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func checkProofSchema(t *testing.T, r *output.ProofRecipe) {
	t.Helper()
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	s, err := contract.DocumentSchema(output.ProofDocumentName)
	require.NoError(t, err)
	require.NoError(t, contracttest.Check(s, raw), "recipe fails `schema proof`:\n%s", raw)
}

// The recipe is the high-sleep payload against the no-sleep control, with the
// delay the module credits the high sleep with as the margin, over its rounds.
func TestTimingProofRecipe(t *testing.T) {
	rr := modtest.Request(t, "http://127.0.0.1:8080/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")
	pair := timePair{context: "numeric", dbType: "mysql", template: " AND SLEEP(%d)"}

	r := timingProofRecipe(rr, ip, "1"+pair.render(sleepHigh), "1"+pair.render(0))
	require.NotNil(t, r)
	checkProofSchema(t, r)
	raw, _ := json.Marshal(r)
	t.Logf("recipe: %s", raw)
	assert.Equal(t, output.ProofTimingDelta, r.Oracle.Kind)
	assert.Equal(t, int64(sleepHigh*1000/minScaleDenom), r.Oracle.MinDeltaMS)
	assert.Equal(t, timeRounds, r.Oracle.Repeat)
	assert.Equal(t, "1 AND SLEEP(6)", r.Request.PayloadTemplate)
	assert.Equal(t, "1 AND SLEEP(0)", r.Control.PayloadTemplate)
	assert.Equal(t, output.ProofInsertionPoint{Type: "URL_PARAM", Name: "id"}, r.Request.InsertionPoint)
	assert.True(t, r.Preconditions.MethodSafe)

	// A cookie point would need the Cookie header a recipe never carries.
	ck := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(),
		[]byte("GET /item HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie: id=1\r\n\r\n")), nil)
	assert.Nil(t, timingProofRecipe(ck, modtest.InsertionPointByType(t, ck, httpmsg.INS_PARAM_COOKIE), "1 AND SLEEP(6)", "1 AND SLEEP(0)"))
}

// The recipe a real detection emits reproduces against the scaling sink.
func TestTimeBlindProofRecipeReproduces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(scalingHandler())
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	r := res[0].Proof
	require.NotNil(t, r, "a confirmed time-based finding carries its recipe")
	checkProofSchema(t, r)

	start := time.Now()
	got := modtest.ReplayProof(t, r)
	assert.True(t, got.Holds, "the timing recipe must reproduce on the scaling sink")
	assert.GreaterOrEqual(t, time.Since(start), time.Duration(r.Oracle.Repeat)*time.Duration(r.Oracle.MinDeltaMS)*time.Millisecond)
}
