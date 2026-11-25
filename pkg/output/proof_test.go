package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
)

func sampleRecipe() *ProofRecipe {
	point := ProofInsertionPoint{Type: "URL_PARAM", Name: "q"}
	return &ProofRecipe{
		Request: ProofRequest{
			Method: "GET", URL: "http://127.0.0.1:8080/search?q=%22%3E%3Csvg+onload%3Dalert%28%60{{marker}}%60%29%3E",
			Headers: map[string]string{"User-Agent": "x"}, InsertionPoint: point,
			PayloadTemplate: "\"><svg onload=alert(`{{marker}}`)>",
		},
		Control: ProofControl{
			Method: "GET", URL: "http://127.0.0.1:8080/search?q={{marker}}", InsertionPoint: &point,
			PayloadTemplate: "{{marker}}",
		},
		Oracle:        ProofOracle{Kind: ProofBodyContains, Value: "\"><svg onload=alert(`{{marker}}`)>"},
		Preconditions: ProofPreconditions{MethodSafe: true},
	}
}

func proofSchemaCheck(t *testing.T, doc []byte) error {
	t.Helper()
	s, err := contract.DocumentSchema(ProofDocumentName)
	if err != nil {
		t.Fatal(err)
	}
	return contracttest.Check(s, doc)
}

func TestProofRecipeValidatesAgainstPublishedSchema(t *testing.T) {
	raw, err := json.Marshal(sampleRecipe())
	if err != nil {
		t.Fatal(err)
	}
	if err := proofSchemaCheck(t, raw); err != nil {
		t.Fatalf("sample recipe fails `schema proof`: %v\n%s", err, raw)
	}
	timing := sampleRecipe()
	timing.Oracle = ProofOracle{Kind: ProofTimingDelta, MinDeltaMS: 3000, Repeat: 2}
	raw, _ = json.Marshal(timing)
	if err := proofSchemaCheck(t, raw); err != nil {
		t.Fatalf("timing recipe fails `schema proof`: %v", err)
	}
	baseline := sampleRecipe()
	baseline.Control = ProofControl{BaselineRecordUUID: "rec-1"}
	raw, _ = json.Marshal(baseline)
	if err := proofSchemaCheck(t, raw); err != nil {
		t.Fatalf("baseline-control recipe fails `schema proof`: %v", err)
	}
}

func TestProofSchemaRefusesMalformedRecipes(t *testing.T) {
	cases := map[string]func(r *ProofRecipe){
		"unknown oracle kind":         func(r *ProofRecipe) { r.Oracle.Kind = "error_signature" },
		"body_contains without value": func(r *ProofRecipe) { r.Oracle.Value = "" },
		"timing without repeat":       func(r *ProofRecipe) { r.Oracle = ProofOracle{Kind: ProofTimingDelta, MinDeltaMS: 3000} },
		"control in both forms":       func(r *ProofRecipe) { r.Control.BaselineRecordUUID = "rec-1" },
		"header_contains without header": func(r *ProofRecipe) {
			r.Oracle = ProofOracle{Kind: ProofHeaderContains, Value: "x"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := sampleRecipe()
			mutate(r)
			if r.Validate() == nil {
				t.Error("Validate accepted it")
			}
			raw, _ := json.Marshal(r)
			if proofSchemaCheck(t, raw) == nil {
				t.Errorf("`schema proof` accepted it:\n%s", raw)
			}
		})
	}
}

func TestProofValidateNeedsThePayloadToPlantAMarkerTheOracleReads(t *testing.T) {
	r := sampleRecipe()
	r.Request.PayloadTemplate = "\"><svg onload=alert(1)>"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "does not plant") {
		t.Fatalf("want a refusal naming the unplanted marker, got %v", err)
	}
}

func TestResultEventCarriesProof(t *testing.T) {
	ev := &ResultEvent{ModuleID: "m", Proof: sampleRecipe()}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"proof":{"request"`) {
		t.Fatalf("event JSON lacks proof: %s", raw)
	}
	raw, _ = json.Marshal(&ResultEvent{ModuleID: "m"})
	if strings.Contains(string(raw), `"proof"`) {
		t.Fatalf("an event without a recipe must omit proof: %s", raw)
	}
}
