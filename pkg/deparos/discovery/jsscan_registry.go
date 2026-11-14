package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// ExtractedRequestTemplate keeps a fact attached to the asset that produced it.
// This prevents resolving one relative endpoint against every crawled directory.
type ExtractedRequestTemplate struct {
	ID            string
	SourceURL     string
	Request       jstangle.HTTPRequestFact
	Confidence    string
	SchemaVersion int
}

type RequestTemplateRegistry interface {
	Add(sourceURL string, fact jstangle.HTTPRequestFact) bool
	AddLegacy(sourceURL string, request jstangle.ExtractedRequest) bool
	BySource(sourceURL string) []ExtractedRequestTemplate
	PendingReplay() []ExtractedRequestTemplate
	Requeue(sourceURL, id string) bool
	All() []ExtractedRequestTemplate
	Len() int
	PendingLen() int
	// NoteOutcome records what became of a template (see TemplateOutcome). A
	// template seen through several variants or flush rounds keeps its most
	// informative note. Returns false when the template is unknown.
	NoteOutcome(sourceURL, id string, note ReplayNote) bool
	// Outcomes reports every template with its final note. A template that was
	// never noted is classified by whether it was ever claimed for replay.
	Outcomes() []TemplateOutcome
	// AddWithheld records a request that was never eligible for sending (a
	// form the replay safety policy refused): it is stored with note
	// as its outcome and never enters the pending replay set, so it survives
	// as a request stub without ever being sent.
	AddWithheld(sourceURL string, fact jstangle.HTTPRequestFact, note ReplayNote) bool
}

type requestTemplateRegistry struct {
	mu       sync.Mutex
	items    map[string]ExtractedRequestTemplate
	pending  map[string]struct{}
	outcomes map[string]ReplayNote
}

func NewRequestTemplateRegistry() RequestTemplateRegistry {
	return &requestTemplateRegistry{
		items: make(map[string]ExtractedRequestTemplate), pending: make(map[string]struct{}),
		outcomes: make(map[string]ReplayNote),
	}
}

func (r *requestTemplateRegistry) Add(sourceURL string, fact jstangle.HTTPRequestFact) bool {
	if fact.Kind == "" {
		fact.Kind = "httpRequest"
	}
	if fact.ID == "" {
		fact.ID = stableTemplateID(sourceURL, fact.URL.Rendered, fact.Method.Rendered, renderFactFields(fact.Query))
	}
	key := sourceURL + "\x00" + fact.ID
	template := ExtractedRequestTemplate{
		ID: fact.ID, SourceURL: sourceURL,
		Request: cloneRequestFact(fact), Confidence: fact.Provenance.Confidence, SchemaVersion: 2,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.items[key]; ok {
		merged := mergeRequestFacts(existing.Request, fact)
		if requestFactsEqual(existing.Request, merged) {
			return false
		}
		existing.Request = merged
		existing.Confidence = merged.Provenance.Confidence
		r.items[key] = existing
		r.pending[key] = struct{}{}
		return true
	}
	r.items[key] = template
	r.pending[key] = struct{}{}
	return true
}

func (r *requestTemplateRegistry) AddWithheld(sourceURL string, fact jstangle.HTTPRequestFact, note ReplayNote) bool {
	if fact.Kind == "" {
		fact.Kind = "httpRequest"
	}
	if fact.ID == "" {
		fact.ID = stableTemplateID(sourceURL, fact.URL.Rendered, fact.Method.Rendered, renderFactFields(fact.Query))
	}
	key := sourceURL + "\x00" + fact.ID
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[key]; ok {
		return false
	}
	r.items[key] = ExtractedRequestTemplate{
		ID: fact.ID, SourceURL: sourceURL,
		Request: cloneRequestFact(fact), Confidence: fact.Provenance.Confidence, SchemaVersion: 2,
	}
	r.outcomes[key] = note
	return true
}

func (r *requestTemplateRegistry) AddLegacy(sourceURL string, request jstangle.ExtractedRequest) bool {
	fact := jstangle.HTTPRequestFact{
		Kind:       "httpRequest",
		URL:        jstangle.ValueTemplate{Rendered: request.URL, Static: !ContainsTemplateVar(request.URL)},
		Method:     jstangle.ValueTemplate{Rendered: request.Method, Static: !ContainsTemplateVar(request.Method)},
		Client:     "generic",
		Provenance: jstangle.Provenance{Extractor: "legacy-storage", Confidence: "medium"},
	}
	if request.Params != "" {
		for name, values := range parseTemplateFields(request.Params) {
			for _, value := range values {
				fact.Query = append(fact.Query, jstangle.FieldTemplate{
					Name:  jstangle.ValueTemplate{Rendered: name, Static: !ContainsTemplateVar(name)},
					Value: jstangle.ValueTemplate{Rendered: value, Static: !ContainsTemplateVar(value)},
				})
			}
		}
	}
	for _, header := range request.Headers {
		name, value := splitHeader(header)
		fact.Headers = append(fact.Headers, jstangle.HeaderTemplate{
			Name:      jstangle.ValueTemplate{Rendered: name, Static: true},
			Value:     jstangle.ValueTemplate{Rendered: value, Static: !ContainsTemplateVar(value)},
			Sensitive: isSensitiveHeader(name),
		})
	}
	if request.Body != "" {
		fact.Body = &jstangle.BodyTemplate{Kind: inferBodyKind(request.Body, request.Headers), Value: jstangle.ValueTemplate{
			Rendered: request.Body, Static: !ContainsTemplateVar(request.Body),
		}}
	}
	fact.ID = stableTemplateID(sourceURL, request.URL, request.Method, request.Params, request.Body)
	return r.Add(sourceURL, fact)
}

func (r *requestTemplateRegistry) BySource(sourceURL string) []ExtractedRequestTemplate {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]ExtractedRequestTemplate, 0)
	for _, template := range r.items {
		if template.SourceURL == sourceURL {
			result = append(result, cloneTemplate(template))
		}
	}
	sortTemplates(result)
	return result
}

func (r *requestTemplateRegistry) PendingReplay() []ExtractedRequestTemplate {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]ExtractedRequestTemplate, 0, len(r.pending))
	for key := range r.pending {
		if template, ok := r.items[key]; ok {
			result = append(result, cloneTemplate(template))
		}
		delete(r.pending, key)
	}
	sortTemplates(result)
	return result
}

// Requeue re-marks a previously-claimed template as pending so a later replay
// round retries it. PendingReplay claims destructively (deletes on read, before
// the request is actually sent); without Requeue a transient send failure or a
// mid-flight cancellation would permanently consume that work. The template body
// still lives in items after the claim, so requeuing only needs to flip the
// pending flag back on. Returns false when the id is blank or the template is no
// longer known (already replayed to a definitive outcome and evicted).
func (r *requestTemplateRegistry) Requeue(sourceURL, id string) bool {
	if id == "" {
		return false
	}
	key := sourceURL + "\x00" + id
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[key]; !ok {
		return false
	}
	r.pending[key] = struct{}{}
	return true
}

func (r *requestTemplateRegistry) All() []ExtractedRequestTemplate {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]ExtractedRequestTemplate, 0, len(r.items))
	for _, template := range r.items {
		result = append(result, cloneTemplate(template))
	}
	sortTemplates(result)
	return result
}

func (r *requestTemplateRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}

// PendingLen reports how many templates are awaiting replay without draining
// them. Used by the end-of-scan flush to decide whether a final replay round is
// needed (facts registered by slow tail JS bundles after the last drain).
func (r *requestTemplateRegistry) PendingLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *requestTemplateRegistry) NoteOutcome(sourceURL, id string, note ReplayNote) bool {
	if id == "" || note.Outcome == "" {
		return false
	}
	key := sourceURL + "\x00" + id
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[key]; !ok {
		return false
	}
	if existing, ok := r.outcomes[key]; ok && !note.supersedes(existing) {
		return true
	}
	r.outcomes[key] = note
	return true
}

func (r *requestTemplateRegistry) Outcomes() []TemplateOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]TemplateOutcome, 0, len(r.items))
	for key, template := range r.items {
		note, ok := r.outcomes[key]
		if !ok {
			if _, pending := r.pending[key]; pending {
				// Never claimed: the end-of-scan flush cap or the target's
				// deadline arrived first.
				note = ReplayNote{Outcome: TemplateWithheldFlushCap, Reason: ReasonUnreplayed}
			} else {
				// Claimed but nothing was sent and nothing was noted: no
				// candidate URL resolved to something replayable.
				note = ReplayNote{Outcome: TemplateUnresolvable, Reason: "no-variant"}
			}
		}
		result = append(result, TemplateOutcome{Template: cloneTemplate(template), ReplayNote: note})
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Template, result[j].Template
		if a.SourceURL == b.SourceURL {
			return a.ID < b.ID
		}
		return a.SourceURL < b.SourceURL
	})
	return result
}

func sortTemplates(templates []ExtractedRequestTemplate) {
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].SourceURL == templates[j].SourceURL {
			return templates[i].ID < templates[j].ID
		}
		return templates[i].SourceURL < templates[j].SourceURL
	})
}

func stableTemplateID(parts ...string) string {
	digest := sha256.Sum256([]byte(joinIdentity(parts)))
	return "http-" + hex.EncodeToString(digest[:10])
}

func joinIdentity(parts []string) string {
	encoded, _ := json.Marshal(parts)
	return string(encoded)
}

func cloneTemplate(template ExtractedRequestTemplate) ExtractedRequestTemplate {
	template.Request = cloneRequestFact(template.Request)
	return template
}

func cloneRequestFact(fact jstangle.HTTPRequestFact) jstangle.HTTPRequestFact {
	encoded, _ := json.Marshal(fact)
	var clone jstangle.HTTPRequestFact
	_ = json.Unmarshal(encoded, &clone)
	return clone
}

func requestFactsEqual(a, b jstangle.HTTPRequestFact) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

func mergeRequestFacts(existing, incoming jstangle.HTTPRequestFact) jstangle.HTTPRequestFact {
	merged := cloneRequestFact(existing)
	merged.URL.Alternatives = unionStrings(merged.URL.Alternatives, append([]string{incoming.URL.Rendered}, incoming.URL.Alternatives...)...)
	merged.Method.Alternatives = unionStrings(merged.Method.Alternatives, append([]string{incoming.Method.Rendered}, incoming.Method.Alternatives...)...)
	merged.AlternateExtractors = unionStrings(merged.AlternateExtractors, append([]string{incoming.Provenance.Extractor}, incoming.AlternateExtractors...)...)
	if confidenceRank(incoming.Provenance.Confidence) > confidenceRank(merged.Provenance.Confidence) {
		primaryURL, primaryMethod := merged.URL, merged.Method
		merged = cloneRequestFact(incoming)
		merged.URL.Alternatives = unionStrings(merged.URL.Alternatives, append([]string{primaryURL.Rendered}, primaryURL.Alternatives...)...)
		merged.Method.Alternatives = unionStrings(merged.Method.Alternatives, append([]string{primaryMethod.Rendered}, primaryMethod.Alternatives...)...)
		merged.AlternateExtractors = unionStrings(merged.AlternateExtractors, append([]string{existing.Provenance.Extractor}, existing.AlternateExtractors...)...)
	}
	return merged
}

func unionStrings(existing []string, values ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(values))
	result := make([]string, 0, len(existing)+len(values))
	for _, value := range append(append([]string(nil), existing...), values...) {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func confidenceRank(confidence string) int {
	switch confidence {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
