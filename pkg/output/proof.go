package output

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/vigolium/vigolium/pkg/contract"
)

// A proof recipe is how a module decided, exported so a caller can re-run the
// decision itself: the attack request, a control that differs from it only in
// the value at the insertion point, and a closed-set oracle that compares the
// two answers. vigolium proposes the test; the caller sends both requests
// through its own scope, rate and identity gates and judges the oracle in its
// own code. `vigolium schema proof` publishes the shape (ProofDocumentName).
//
// The caller mints the marker. A payload that must carry an unguessable token
// holds MarkerPlaceholder where it goes — in payload_template and in the
// request's url, headers or body wherever the insertion point put it — and an
// oracle that reads it back holds the placeholder in its value. The caller
// replaces every occurrence with one fresh alphanumeric token per run.
//
// Credentials never ride on a recipe: Authorization, Cookie and
// Proxy-Authorization are dropped from headers (the caller attaches its own
// principal), and a module whose payload lands in one of them emits no recipe.

// MarkerPlaceholder is where the caller's minted marker goes.
const MarkerPlaceholder = "{{marker}}"

// ProofDocumentName names the recipe document in `vigolium schema`.
const ProofDocumentName = "proof"

// ProofOracleKind is the closed oracle vocabulary.
type ProofOracleKind string

// Each oracle compares the attack response with the control response.
const (
	// ProofBodyContains: the attack body contains value; the control body does not.
	ProofBodyContains ProofOracleKind = "body_contains"
	// ProofBodyAbsent: the control body contains value; the attack body does not.
	ProofBodyAbsent ProofOracleKind = "body_absent"
	// ProofStatusDiffers: the two status codes differ.
	ProofStatusDiffers ProofOracleKind = "status_differs"
	// ProofHeaderContains: the attack's header (named by header) contains
	// value; the control's does not.
	ProofHeaderContains ProofOracleKind = "header_contains"
	// ProofTimingDelta: the attack takes at least min_delta_ms longer than the
	// control in each of repeat alternating rounds.
	ProofTimingDelta ProofOracleKind = "timing_delta"
	// ProofOASTInteraction: the caller's own collector receives a callback for
	// the marker the attack carried; the control carries none.
	ProofOASTInteraction ProofOracleKind = "oast_interaction"
	// ProofBodySimilarity: the attack and control bodies are less similar than
	// threshold (0..1).
	ProofBodySimilarity ProofOracleKind = "body_similarity"
)

// ProofOracleKinds lists the vocabulary in published order.
func ProofOracleKinds() []ProofOracleKind {
	return []ProofOracleKind{
		ProofBodyContains, ProofBodyAbsent, ProofStatusDiffers, ProofHeaderContains,
		ProofTimingDelta, ProofOASTInteraction, ProofBodySimilarity,
	}
}

// ProofRecipe is the `proof` object a result may carry (ResultEvent.Proof,
// findings.proof, `finding -j` proof).
type ProofRecipe struct {
	// Request is the attack: the scanned request with the payload at the
	// insertion point.
	Request ProofRequest `json:"request"`
	// Control is the same request with a benign value at the insertion point,
	// or the stored record of the unmutated request.
	Control ProofControl `json:"control"`
	// Oracle decides from the attack and control responses.
	Oracle ProofOracle `json:"oracle"`
	// Preconditions are what the caller must hold before sending.
	Preconditions ProofPreconditions `json:"preconditions"`
}

// ProofRequest is one request of a recipe, ready to send once the marker is
// substituted. Headers carry no credential and no Host or Content-Length: the
// url names the origin and the caller frames the body.
type ProofRequest struct {
	Method         string              `json:"method"`
	URL            string              `json:"url"`
	Headers        map[string]string   `json:"headers"`
	Body           string              `json:"body,omitempty"`
	InsertionPoint ProofInsertionPoint `json:"insertion_point"`
	// PayloadTemplate is the value placed at the insertion point, before the
	// encoding the point applies (the url, headers and body already carry it
	// encoded).
	PayloadTemplate string `json:"payload_template"`
}

// ProofInsertionPoint names the point a payload goes: an httpmsg
// insertion-point type name (URL_PARAM, BODY_PARAM, JSON_PARAM, HEADER, …) and
// the parameter or header name.
type ProofInsertionPoint struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// ProofControl is either a request of the attack's shape with a benign value,
// or baseline_record_uuid, the stored unmutated request, alone.
type ProofControl struct {
	Method             string               `json:"method,omitempty"`
	URL                string               `json:"url,omitempty"`
	Headers            map[string]string    `json:"headers,omitempty"`
	Body               string               `json:"body,omitempty"`
	InsertionPoint     *ProofInsertionPoint `json:"insertion_point,omitempty"`
	PayloadTemplate    string               `json:"payload_template,omitempty"`
	BaselineRecordUUID string               `json:"baseline_record_uuid,omitempty"`
}

// IsBaseline reports whether the control names a stored record instead of a
// request.
func (c ProofControl) IsBaseline() bool { return c.BaselineRecordUUID != "" }

// ProofOracle is one closed-set oracle and its parameters.
type ProofOracle struct {
	Kind ProofOracleKind `json:"kind"`
	// Value is the literal body_contains, body_absent and header_contains look
	// for (it may hold MarkerPlaceholder), or the callback id oast_interaction
	// waits for.
	Value string `json:"value,omitempty"`
	// Header names the response header header_contains reads.
	Header string `json:"header,omitempty"`
	// MinDeltaMS is timing_delta's margin over the control, per round.
	MinDeltaMS int64 `json:"min_delta_ms,omitempty"`
	// Repeat is how many alternating attack/control rounds timing_delta needs,
	// every one holding.
	Repeat int `json:"repeat,omitempty"`
	// Threshold is body_similarity's ceiling (0..1, exclusive).
	Threshold float64 `json:"threshold,omitempty"`
}

// ProofPreconditions are what sending the recipe requires.
type ProofPreconditions struct {
	// MethodSafe is true when the attack's method is GET, HEAD or OPTIONS.
	MethodSafe bool `json:"method_safe"`
	// Principal names the auth session the module scanned as; absent when it
	// scanned unauthenticated or the session is not named.
	Principal string `json:"principal,omitempty"`
}

// Validate reports why r cannot be executed as published, or nil.
func (r *ProofRecipe) Validate() error {
	if r == nil {
		return fmt.Errorf("proof: nil recipe")
	}
	if err := validateProofRequest("request", r.Request.Method, r.Request.URL, &r.Request.InsertionPoint); err != nil {
		return err
	}
	c := r.Control
	if c.IsBaseline() {
		if c.Method != "" || c.URL != "" || c.InsertionPoint != nil || c.PayloadTemplate != "" || c.Body != "" || len(c.Headers) > 0 {
			return fmt.Errorf("proof: control names baseline_record_uuid and a request; one or the other")
		}
	} else if err := validateProofRequest("control", c.Method, c.URL, c.InsertionPoint); err != nil {
		return err
	}
	o := r.Oracle
	switch o.Kind {
	case ProofBodyContains, ProofBodyAbsent:
		if o.Value == "" {
			return fmt.Errorf("proof: oracle %s needs value", o.Kind)
		}
	case ProofHeaderContains:
		if o.Header == "" || o.Value == "" {
			return fmt.Errorf("proof: oracle %s needs header and value", o.Kind)
		}
	case ProofTimingDelta:
		if o.MinDeltaMS <= 0 || o.Repeat <= 0 {
			return fmt.Errorf("proof: oracle %s needs min_delta_ms and repeat", o.Kind)
		}
	case ProofBodySimilarity:
		if o.Threshold <= 0 || o.Threshold >= 1 {
			return fmt.Errorf("proof: oracle %s needs a threshold between 0 and 1", o.Kind)
		}
	case ProofStatusDiffers, ProofOASTInteraction:
	default:
		return fmt.Errorf("proof: unknown oracle kind %q", o.Kind)
	}
	// An oracle reading the marker back needs an attack that plants it.
	if strings.Contains(o.Value, MarkerPlaceholder) && !strings.Contains(r.Request.PayloadTemplate, MarkerPlaceholder) {
		return fmt.Errorf("proof: oracle value reads %s but the payload does not plant it", MarkerPlaceholder)
	}
	return nil
}

func validateProofRequest(what, method, url string, ip *ProofInsertionPoint) error {
	switch {
	case method == "":
		return fmt.Errorf("proof: %s has no method", what)
	case !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://"):
		return fmt.Errorf("proof: %s url %q is not absolute http(s)", what, url)
	case ip == nil || ip.Type == "":
		return fmt.Errorf("proof: %s has no insertion point", what)
	}
	return nil
}

// JSONSchemaExtend states what reflection cannot: the closed oracle kind and
// the parameters each kind requires.
func (ProofOracle) JSONSchemaExtend(s *jsonschema.Schema) {
	kinds := ProofOracleKinds()
	enum := make([]any, len(kinds))
	for i, k := range kinds {
		enum[i] = string(k)
	}
	if p, ok := s.Properties.Get("kind"); ok && p != nil {
		p.Enum = enum
	}
	needs := func(kind ProofOracleKind, required ...string) *jsonschema.Schema {
		kindProps := jsonschema.NewProperties()
		kindProps.Set("kind", &jsonschema.Schema{Const: string(kind)})
		return &jsonschema.Schema{
			If:   &jsonschema.Schema{Properties: kindProps, Required: []string{"kind"}},
			Then: &jsonschema.Schema{Required: required},
		}
	}
	s.AllOf = append(s.AllOf,
		needs(ProofBodyContains, "value"),
		needs(ProofBodyAbsent, "value"),
		needs(ProofHeaderContains, "header", "value"),
		needs(ProofTimingDelta, "min_delta_ms", "repeat"),
		needs(ProofBodySimilarity, "threshold"),
	)
}

// JSONSchemaExtend makes the control one of its two forms.
func (ProofControl) JSONSchemaExtend(s *jsonschema.Schema) {
	s.OneOf = append(s.OneOf,
		&jsonschema.Schema{Required: []string{"method", "url", "insertion_point", "payload_template"}},
		&jsonschema.Schema{Required: []string{"baseline_record_uuid"}},
	)
}

func init() {
	contract.RegisterDocument(contract.Document{Name: ProofDocumentName, Value: ProofRecipe{},
		Description: "A finding's proof recipe (finding -j proof): the attack request, a control differing only in the " +
			"value at the insertion point (or baseline_record_uuid), a closed-set oracle over the two responses, and " +
			"preconditions. " + MarkerPlaceholder + " in payload_template, url, headers, body and oracle value is " +
			"where the caller substitutes its own minted marker. Oracles: body_contains (attack body has value, " +
			"control's does not), body_absent (the reverse), status_differs, header_contains (header has value on " +
			"the attack only), timing_delta (attack slower by min_delta_ms in each of repeat rounds), " +
			"oast_interaction (the caller's collector sees the attack's callback), body_similarity (bodies less " +
			"similar than threshold). Headers never carry credentials, Host or Content-Length."})
}
