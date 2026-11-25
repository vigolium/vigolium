package xss_light_scanner

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// A reflected-XSS finding on the e2e-expect lab's planted /search carries a
// body_contains recipe that validates against `schema proof`, reproduces when
// replayed with a fresh marker, and is refuted on the plant's escaping twin.
func TestReflectedXSSProofRecipeReproducesOnLab(t *testing.T) {
	srv := httptest.NewServer(lab.VulnApp(lab.VulnAppOptions{}))
	defer srv.Close()
	var plant lab.Plant
	for _, p := range lab.Plants() {
		if p.Class == "xss-reflected" {
			plant = p
		}
	}
	if plant.Path == "" {
		t.Fatal("the lab has no xss-reflected plant")
	}

	mod := NewURLParamsScanner()
	mod.Probe = blockedProbe
	res, err := mod.ScanPerRequest(modtest.Request(t, plant.URL(srv.URL)), modtest.Requester(t), &modkit.ScanContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 || res[0].Proof == nil {
		t.Fatalf("want a finding carrying a proof recipe, got %d findings", len(res))
	}
	r := res[0].Proof

	raw, _ := json.Marshal(r)
	s, err := contract.DocumentSchema(output.ProofDocumentName)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracttest.Check(s, raw); err != nil {
		t.Fatalf("recipe fails `schema proof`: %v\n%s", err, raw)
	}
	t.Logf("recipe: %s", raw)
	if r.Oracle.Kind != output.ProofBodyContains || !strings.Contains(r.Oracle.Value, output.MarkerPlaceholder) {
		t.Fatalf("oracle = %+v", r.Oracle)
	}
	if r.Request.InsertionPoint.Name != plant.Param || !r.Preconditions.MethodSafe {
		t.Fatalf("request = %+v, preconditions = %+v", r.Request, r.Preconditions)
	}
	if got := modtest.ReplayProof(t, r); !got.Holds {
		t.Fatalf("recipe does not reproduce on the plant: attack %q control %q", got.AttackBody, got.ControlBody)
	}

	twin := *r
	twin.Request.URL = strings.Replace(r.Request.URL, plant.Path+"?", plant.Twin+"?", 1)
	twin.Control.URL = strings.Replace(r.Control.URL, plant.Path+"?", plant.Twin+"?", 1)
	if got := modtest.ReplayProof(t, &twin); got.Holds {
		t.Fatalf("recipe holds on the escaping twin: attack %q", got.AttackBody)
	}
}

// A JS-string breakout's signature only counts when its quote is unescaped,
// which a literal cannot state, so such a finding carries no recipe.
func TestJSStringXSSCarriesNoRecipe(t *testing.T) {
	srv := httptest.NewServer(jsStringHandler(nil))
	defer srv.Close()
	mod := NewURLParamsScanner()
	mod.Probe = blockedProbe
	res, err := mod.ScanPerRequest(modtest.Request(t, srv.URL+"/?body=hi"), modtest.Requester(t), &modkit.ScanContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res))
	}
	if res[0].Proof != nil {
		t.Fatalf("a JS-string breakout must carry no recipe: %+v", res[0].Proof)
	}
}
