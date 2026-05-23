package condition

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// TestNewEventableCondition verifies the builder initializes empty slices.
func TestNewEventableCondition(t *testing.T) {
	ec := NewEventableCondition()
	if ec.Conditions == nil {
		t.Error("Conditions should be non-nil")
	}
	if ec.LinkedInputs == nil {
		t.Error("LinkedInputs should be non-nil")
	}
	if len(ec.Conditions) != 0 {
		t.Errorf("Conditions length = %d, want 0", len(ec.Conditions))
	}
	if len(ec.LinkedInputs) != 0 {
		t.Errorf("LinkedInputs length = %d, want 0", len(ec.LinkedInputs))
	}
}

// TestEventableConditionBuilders verifies the fluent builder methods.
func TestEventableConditionBuilders(t *testing.T) {
	ec := NewEventableCondition().
		InXPathScope("/html/body/div").
		WithURLContains("admin").
		WithElementExists("#login").
		WithElementVisible("#submit").
		WithJavaScript("true").
		WithDescription("test condition")

	if ec.InXPath != "/html/body/div" {
		t.Errorf("InXPath = %q, want %q", ec.InXPath, "/html/body/div")
	}
	if ec.Description != "test condition" {
		t.Errorf("Description = %q, want %q", ec.Description, "test condition")
	}
	// 4 conditions: URLContains, ElementExists, ElementVisible, JavaScript
	if len(ec.Conditions) != 4 {
		t.Fatalf("Conditions length = %d, want 4", len(ec.Conditions))
	}

	wantTypes := []*Condition{
		URLContains("admin"),
		ElementExists("#login"),
		ElementVisible("#submit"),
		JavaScript("true"),
	}
	for i, want := range wantTypes {
		if ec.Conditions[i].Type != want.Type {
			t.Errorf("Conditions[%d].Type = %v, want %v", i, ec.Conditions[i].Type, want.Type)
		}
		if ec.Conditions[i].Value != want.Value {
			t.Errorf("Conditions[%d].Value = %q, want %q", i, ec.Conditions[i].Value, want.Value)
		}
	}
}

// TestWithCondition verifies adding a raw condition.
func TestWithCondition(t *testing.T) {
	cond := DOMRegex("error")
	ec := NewEventableCondition().WithCondition(cond)
	if len(ec.Conditions) != 1 {
		t.Fatalf("Conditions length = %d, want 1", len(ec.Conditions))
	}
	if ec.Conditions[0] != cond {
		t.Error("WithCondition did not append the same condition pointer")
	}
}

// TestAddLinkedInputVariants verifies the linked-input helpers populate
// Identification with the correct How values.
func TestAddLinkedInputVariants(t *testing.T) {
	ec := NewEventableCondition().
		AddLinkedInputByID("user", "text", "alice").
		AddLinkedInputByName("pass", "password", "secret").
		AddLinkedInputByXPath("//input[@type='checkbox']", "checkbox", "on")

	if !ec.HasLinkedInputs() {
		t.Fatal("HasLinkedInputs() = false, want true")
	}
	inputs := ec.GetLinkedInputs()
	if len(inputs) != 3 {
		t.Fatalf("GetLinkedInputs() length = %d, want 3", len(inputs))
	}

	checks := []struct {
		how    action.How
		value  string
		typ    string
		valLen int
	}{
		{action.HowID, "user", "text", 1},
		{action.HowName, "pass", "password", 1},
		{action.HowXPath, "//input[@type='checkbox']", "checkbox", 1},
	}
	for i, c := range checks {
		got := inputs[i]
		if got.Identification == nil {
			t.Fatalf("inputs[%d].Identification is nil", i)
		}
		if got.Identification.How != c.how {
			t.Errorf("inputs[%d].How = %v, want %v", i, got.Identification.How, c.how)
		}
		if got.Identification.Value != c.value {
			t.Errorf("inputs[%d].Value = %q, want %q", i, got.Identification.Value, c.value)
		}
		if got.Type != c.typ {
			t.Errorf("inputs[%d].Type = %q, want %q", i, got.Type, c.typ)
		}
		if len(got.Values) != c.valLen {
			t.Errorf("inputs[%d].Values length = %d, want %d", i, len(got.Values), c.valLen)
		}
	}
}

// TestAddLinkedInputDirect verifies AddLinkedInput with explicit Identification.
func TestAddLinkedInputDirect(t *testing.T) {
	id := action.NewIdentification(action.HowID, "field")
	ec := NewEventableCondition().AddLinkedInput(id, "text", "a", "b")
	if len(ec.LinkedInputs) != 1 {
		t.Fatalf("LinkedInputs length = %d, want 1", len(ec.LinkedInputs))
	}
	li := ec.LinkedInputs[0]
	if li.Identification != id {
		t.Error("Identification pointer mismatch")
	}
	if len(li.Values) != 2 || li.Values[0] != "a" || li.Values[1] != "b" {
		t.Errorf("Values = %v, want [a b]", li.Values)
	}
}

// TestHasLinkedInputsFalse verifies the empty case.
func TestHasLinkedInputsFalse(t *testing.T) {
	if NewEventableCondition().HasLinkedInputs() {
		t.Error("HasLinkedInputs() = true on empty condition, want false")
	}
}

// TestMatchesXPathScope verifies the strict prefix matching rules.
func TestMatchesXPathScope(t *testing.T) {
	tests := []struct {
		name    string
		scope   string
		element string
		want    bool
	}{
		{"empty scope matches all", "", "/html/body/div", true},
		{"exact prefix", "/html/body", "/html/body/div", true},
		{"exact match", "/html/body/div", "/html/body/div", true},
		{"case insensitive prefix", "/HTML/BODY", "/html/body/div/span", true},
		{"double-slash normalized prefix", "//html/body", "/html/body/a", true},
		{"not a prefix", "/html/body/div", "/html/head/title", false},
		{"contains but not prefix", "/body/div", "/html/body/div", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := NewEventableCondition().InXPathScope(tt.scope)
			if got := ec.matchesXPathScope(tt.element); got != tt.want {
				t.Errorf("matchesXPathScope(scope=%q, elem=%q) = %v, want %v",
					tt.scope, tt.element, got, tt.want)
			}
		})
	}
}

// TestEventableConditionCheckXPathScopeMiss verifies that elements outside the
// XPath scope are allowed (returns true) without touching the page. When the
// element is not in scope, Check short-circuits before evaluating any
// page-dependent condition.
func TestEventableConditionCheckXPathScopeMiss(t *testing.T) {
	ec := NewEventableCondition().
		InXPathScope("/html/body/form").
		WithURLContains("admin") // page-dependent, must not be reached

	// Element is outside scope, so Check returns true without evaluating
	// the URLContains condition (which would need a live page).
	if !ec.Check("/html/head/title", nil) {
		t.Error("Check() = false for out-of-scope element, want true")
	}
}

// TestEventableConditionCheckNoConditions verifies an in-scope element with no
// conditions is allowed without touching the page.
func TestEventableConditionCheckNoConditions(t *testing.T) {
	ec := NewEventableCondition().InXPathScope("/html/body")
	if !ec.Check("/html/body/div", nil) {
		t.Error("Check() = false for in-scope element with no conditions, want true")
	}
}

// TestEventableConditionCheckerBasics verifies the checker's Add/Count.
func TestEventableConditionCheckerBasics(t *testing.T) {
	ecc := NewEventableConditionChecker()
	if ecc.Count() != 0 {
		t.Errorf("Count() = %d, want 0", ecc.Count())
	}
	ecc.Add(NewEventableCondition().InXPathScope("/a"))
	ecc.Add(NewEventableCondition().InXPathScope("/b"))
	if ecc.Count() != 2 {
		t.Errorf("Count() = %d, want 2", ecc.Count())
	}
}

// TestEventableConditionCheckerCheckScopeMiss verifies the checker allows
// elements when all member conditions are out of scope.
func TestEventableConditionCheckerCheckScopeMiss(t *testing.T) {
	ecc := NewEventableConditionChecker()
	ecc.Add(NewEventableCondition().
		InXPathScope("/html/body/form").
		WithURLContains("admin"))

	if !ecc.Check("/html/head", nil) {
		t.Error("Check() = false for out-of-scope element, want true")
	}
}

// TestCheckerGetLinkedInputs verifies linked inputs are gathered from matching
// scopes only.
func TestCheckerGetLinkedInputs(t *testing.T) {
	ecc := NewEventableConditionChecker()
	ecc.Add(NewEventableCondition().
		InXPathScope("/html/body/form").
		AddLinkedInputByID("user", "text", "alice"))
	ecc.Add(NewEventableCondition().
		InXPathScope("/html/body/other").
		AddLinkedInputByID("ignored", "text", "x"))

	matched := ecc.GetLinkedInputs("/html/body/form/input")
	if len(matched) != 1 {
		t.Fatalf("GetLinkedInputs length = %d, want 1", len(matched))
	}
	if matched[0].Identification.Value != "user" {
		t.Errorf("matched input value = %q, want %q", matched[0].Identification.Value, "user")
	}

	none := ecc.GetLinkedInputs("/html/head/title")
	if len(none) != 0 {
		t.Errorf("GetLinkedInputs for non-matching path length = %d, want 0", len(none))
	}
}

// TestCheckerGetFormInputs verifies conversion of LinkedInputs to FormInputs.
func TestCheckerGetFormInputs(t *testing.T) {
	ecc := NewEventableConditionChecker()
	ecc.Add(NewEventableCondition().
		AddLinkedInputByName("q", "text", "v1", "v2"))
	// A linked input without identification should be skipped.
	ec := NewEventableCondition()
	ec.LinkedInputs = append(ec.LinkedInputs, LinkedInput{Type: "text", Values: []string{"z"}})
	ecc.Add(ec)

	formInputs := ecc.GetFormInputs()
	if len(formInputs) != 1 {
		t.Fatalf("GetFormInputs length = %d, want 1 (nil-id input skipped)", len(formInputs))
	}
	fi := formInputs[0]
	if fi.Type != action.InputType("text") {
		t.Errorf("FormInput.Type = %q, want %q", fi.Type, "text")
	}
	if fi.Identification.Value != "q" {
		t.Errorf("FormInput.Identification.Value = %q, want %q", fi.Identification.Value, "q")
	}
	if len(fi.InputValues) != 2 {
		t.Fatalf("InputValues length = %d, want 2", len(fi.InputValues))
	}
	if fi.InputValues[0].Value != "v1" || fi.InputValues[1].Value != "v2" {
		t.Errorf("InputValues = %v, want [v1 v2]", fi.InputValues)
	}
}

// TestGetCandidateElementsForInputsNoInputs verifies the base candidate is
// returned unchanged when there are no linked inputs in scope.
func TestGetCandidateElementsForInputsNoInputs(t *testing.T) {
	ecc := NewEventableConditionChecker()
	base := &action.CandidateElement{
		Identification: action.NewIdentification(action.HowXPath, "/html/body/a"),
		TagName:        "a",
	}
	got := ecc.GetCandidateElementsForInputs("/html/body/a", base)
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	if got[0] != base {
		t.Error("expected the base candidate to be returned unchanged")
	}
}

// TestGetCandidateElementsForInputsCombinations verifies the combinatorial
// expansion based on the longest value list.
func TestGetCandidateElementsForInputsCombinations(t *testing.T) {
	ecc := NewEventableConditionChecker()
	ecc.Add(NewEventableCondition().
		InXPathScope("/html/body/form").
		AddLinkedInputByName("color", "select", "red", "green", "blue"))

	base := &action.CandidateElement{
		Identification: action.NewIdentification(action.HowXPath, "/html/body/form/select"),
		TagName:        "select",
		RelatedFrame:   "frame0",
		EventType:      action.EventTypeClick,
	}

	got := ecc.GetCandidateElementsForInputs("/html/body/form/select", base)
	// 3 values => 3 combinations.
	if len(got) != 3 {
		t.Fatalf("got %d candidates, want 3", len(got))
	}

	wantValues := []string{"red", "green", "blue"}
	for i, cand := range got {
		if cand == base {
			t.Errorf("candidate %d is the base candidate; expected a clone", i)
		}
		if cand.TagName != "select" {
			t.Errorf("candidate %d TagName = %q, want %q", i, cand.TagName, "select")
		}
		if cand.RelatedFrame != "frame0" {
			t.Errorf("candidate %d RelatedFrame = %q, want %q", i, cand.RelatedFrame, "frame0")
		}
		if len(cand.FormInputs) != 1 {
			t.Fatalf("candidate %d FormInputs length = %d, want 1", i, len(cand.FormInputs))
		}
		fi := cand.FormInputs[0]
		if len(fi.InputValues) != 1 || fi.InputValues[0].Value != wantValues[i] {
			t.Errorf("candidate %d value = %v, want %q", i, fi.InputValues, wantValues[i])
		}
	}
}
