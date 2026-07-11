package prototype_pollution

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type pollutionVariant struct {
	name    string
	payload func(property, value string) string
}

var variants = []pollutionVariant{
	{"__proto__ property injection", func(property, value string) string {
		return fmt.Sprintf(`{"__proto__":{"%s":"%s"}}`, property, value)
	}},
	{"constructor.prototype injection", func(property, value string) string {
		return fmt.Sprintf(`{"constructor":{"prototype":{"%s":"%s"}}}`, property, value)
	}},
}

type probeObservation struct {
	status   int
	body     string
	request  string
	response string
	ok       bool
}

type markerProof struct {
	variant       pollutionVariant
	injection     probeObservation
	followFirst   probeObservation
	followReplay  probeObservation
	controlFollow probeObservation
	persistent    bool
	sameRequest   bool
	property      string
	value         string
}

// Module implements the Prototype Pollution active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyDefaultRHM("prototype_pollution"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) || ctx.Request() == nil || !json.Valid(ctx.Request().Body()) {
		return false
	}
	method := strings.ToUpper(ctx.Request().Method())
	return (method == "POST" || method == "PUT" || method == "PATCH") &&
		strings.Contains(strings.ToLower(ctx.Request().Header("Content-Type")), "json")
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if utils.IsMediaAndJSURL(urlx.Path) || !m.CanProcess(ctx) {
		return nil, nil
	}
	baseline, baselineErr := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if baselineErr != nil || baseline.Response == nil {
		return nil, nil
	}
	baselineBody := baseline.Response.BodyToString()
	originalBody := ctx.Request().BodyToString()

	var bestCandidate *markerProof
	for _, variant := range variants {
		proof, ok := m.proveMarkerPersistence(ctx, httpClient, originalBody, baselineBody, variant)
		if !ok {
			continue
		}
		if proof.persistent {
			return []*output.ResultEvent{m.markerResult(urlx.Host, urlx.String(), proof)}, nil
		}
		if proof.sameRequest && bestCandidate == nil {
			copyProof := proof
			bestCandidate = &copyProof
		}
	}

	if statusResult := m.proveStatusPersistence(ctx, httpClient, originalBody, baseline.StatusCode, urlx.Host, urlx.String()); statusResult != nil {
		return []*output.ResultEvent{statusResult}, nil
	}
	if bestCandidate != nil {
		return []*output.ResultEvent{m.markerResult(urlx.Host, urlx.String(), *bestCandidate)}, nil
	}
	return nil, nil
}

func (m *Module) proveMarkerPersistence(ctx *httpmsg.HttpRequestResponse, client *http.Requester, originalBody, baselineBody string, variant pollutionVariant) (markerProof, bool) {
	property := "vgopp_" + strings.ToLower(utils.RandomString(10))
	value := "polluted_" + strings.ToLower(utils.RandomString(14))
	controlProperty := "vgopp_ctl_" + strings.ToLower(utils.RandomString(10))
	controlValue := "control_" + strings.ToLower(utils.RandomString(14))
	proof := markerProof{variant: variant, property: property, value: value}
	if strings.Contains(baselineBody, value) || strings.Contains(baselineBody, controlValue) {
		return proof, false
	}

	// Normal-property control first. If an ordinary field persists into a later
	// benign request, the endpoint is stateful in a non-prototype-specific way.
	control := m.sendBody(ctx, client, fmt.Sprintf(`{"%s":"%s"}`, controlProperty, controlValue))
	if !control.ok || strings.Contains(control.body, controlValue) {
		// Same-request reflection of an ordinary property identifies a generic
		// echo endpoint; special-key reflection there is not pollution evidence.
		return proof, false
	}
	proof.controlFollow = m.sendBody(ctx, client, originalBody)
	if !proof.controlFollow.ok || strings.Contains(proof.controlFollow.body, controlValue) {
		return proof, false
	}

	proof.injection = m.sendBody(ctx, client, variant.payload(property, value))
	if !proof.injection.ok {
		return proof, false
	}
	proof.sameRequest = strings.Contains(proof.injection.body, value)
	proof.followFirst = m.sendBody(ctx, client, originalBody)
	proof.followReplay = m.sendBody(ctx, client, originalBody)
	if !proof.followFirst.ok || !proof.followReplay.ok {
		return proof, false
	}
	proof.persistent = strings.Contains(proof.followFirst.body, value) && strings.Contains(proof.followReplay.body, value)
	return proof, proof.sameRequest || proof.persistent
}

func (m *Module) proveStatusPersistence(ctx *httpmsg.HttpRequestResponse, client *http.Requester, originalBody string, baselineStatus int, host, target string) *output.ResultEvent {
	if baselineStatus == 510 {
		return nil
	}
	// A normal top-level status field must not produce or persist the effect.
	normal := m.sendBody(ctx, client, `{"status":510}`)
	normalFollow := m.sendBody(ctx, client, originalBody)
	if !normal.ok || !normalFollow.ok || normal.status == 510 || normalFollow.status == 510 {
		return nil
	}

	injection := m.sendBody(ctx, client, `{"__proto__":{"status":510}}`)
	if !injection.ok || injection.status != 510 {
		return nil
	}
	followFirst := m.sendBody(ctx, client, originalBody)
	followReplay := m.sendBody(ctx, client, originalBody)
	if !followFirst.ok || !followReplay.ok || followFirst.status != 510 || followReplay.status != 510 {
		return nil
	}

	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindFinding,
		EvidenceGrade: output.EvidenceGradeImpact,
		Host:          host,
		URL:           target,
		Matched:       target,
		Request:       injection.request,
		Response:      injection.response,
		AdditionalEvidence: []string{
			output.BuildEvidence("benign follow-up 1", followFirst.request, followFirst.response),
			output.BuildEvidence("benign follow-up 2", followReplay.request, followReplay.response),
		},
		ExtractedResults: []string{
			fmt.Sprintf("baseline_status=%d polluted_status=510", baselineStatus),
			"two later benign requests retained status 510",
			"top-level status control did not produce or persist status 510",
		},
		Info: output.Info{
			Name:        "Persistent Server-Side Prototype Status Pollution",
			Description: "A __proto__.status payload changed the response to 510, and two later benign requests retained that status. A normal top-level status control did not. This demonstrates cross-request prototype state rather than payload-specific validation.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{"persistent_state": true, "benign_replays": 2, "control": "top-level status"},
	}
}

func (m *Module) markerResult(host, target string, proof markerProof) *output.ResultEvent {
	kind := output.RecordKindCandidate
	grade := output.EvidenceGradeDifferential
	sev := severity.Medium
	name := "Prototype-Key Handling Candidate: " + proof.variant.name
	description := "A fresh value injected through " + proof.variant.name + " appeared in the same response while a normal-property echo control stayed negative, but later benign requests did not retain it. This does not prove global prototype mutation."
	additional := []string{output.BuildEvidence("normal-property persistence control", proof.controlFollow.request, proof.controlFollow.response)}
	if proof.persistent {
		kind = output.RecordKindFinding
		grade = output.EvidenceGradeImpact
		sev = ModuleSeverity
		name = "Persistent Server-Side Prototype Pollution: " + proof.variant.name
		description = "A fresh value injected through " + proof.variant.name + " appeared in two later benign responses, while a normal top-level property did not persist. This confirms cross-request prototype state."
		additional = append(additional,
			output.BuildEvidence("benign follow-up 1", proof.followFirst.request, proof.followFirst.response),
			output.BuildEvidence("benign follow-up 2", proof.followReplay.request, proof.followReplay.response),
		)
	}
	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         kind,
		EvidenceGrade:      grade,
		Host:               host,
		URL:                target,
		Matched:            target,
		Request:            proof.injection.request,
		Response:           proof.injection.response,
		AdditionalEvidence: additional,
		ExtractedResults: []string{
			"variant=" + proof.variant.name,
			"property=" + proof.property,
			"value=" + proof.value,
			fmt.Sprintf("same_request=%t persistent_benign_replays=%t", proof.sameRequest, proof.persistent),
		},
		Info:     output.Info{Name: name, Description: description, Severity: sev, Confidence: ModuleConfidence, Tags: ModuleTags},
		Metadata: map[string]any{"persistent_state": proof.persistent, "benign_replays": 2, "normal_property_control_persisted": false},
	}
}

func (m *Module) sendBody(ctx *httpmsg.HttpRequestResponse, client *http.Requester, payload string) probeObservation {
	raw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(payload))
	if err != nil {
		return probeObservation{}
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil || resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return probeObservation{}
	}
	defer resp.Close()
	return probeObservation{
		status:   resp.Response().StatusCode,
		body:     resp.Body().String(),
		request:  string(raw),
		response: resp.FullResponseString(),
		ok:       true,
	}
}
