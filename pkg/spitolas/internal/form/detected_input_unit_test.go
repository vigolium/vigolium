package form

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

func TestNewDetectedInputWithType(t *testing.T) {
	id := action.NewIdentification(action.HowID, "email")
	d := NewDetectedInputWithType(action.InputTypeEmail, id)
	if d.FormInput == nil {
		t.Fatal("FormInput should be set")
	}
	if d.Type != action.InputTypeEmail {
		t.Errorf("Type = %q, want %q", d.Type, action.InputTypeEmail)
	}
	if d.Identification != id {
		t.Error("Identification pointer mismatch")
	}
}

func TestDetectedInputToFormInput(t *testing.T) {
	fi := action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowName, "q"))
	d := NewDetectedInput(fi)
	if d.ToFormInput() != fi {
		t.Error("ToFormInput should return the wrapped FormInput")
	}
}

func TestDetectedInputSetGetValues(t *testing.T) {
	d := NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowID, "x"))
	d.SetValues([]string{"a", "b", "c"})

	got := d.GetValues()
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("GetValues = %v, want [a b c]", got)
	}
	if !d.HasValues() {
		t.Error("HasValues should be true after SetValues")
	}

	// SetValues on a nil FormInput is a no-op (no panic).
	bare := &DetectedInput{}
	bare.SetValues([]string{"x"})
	if bare.GetValues() != nil {
		t.Error("GetValues with nil FormInput should be nil")
	}
}

func TestDetectedInputValueRotation(t *testing.T) {
	d := NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowID, "x"))
	d.SetValues([]string{"v1", "v2"})

	if d.CurrentValue() != "v1" {
		t.Errorf("CurrentValue = %q, want v1", d.CurrentValue())
	}
	if d.NextValue() != "v1" {
		t.Error("first NextValue should be v1")
	}
	if d.NextValue() != "v2" {
		t.Error("second NextValue should be v2")
	}
	if d.NextValue() != "v1" {
		t.Error("NextValue should wrap around to v1")
	}

	d.ResetValueIndex()
	if d.CurrentValue() != "v1" {
		t.Error("ResetValueIndex should reset to first value")
	}
}

func TestFromFormInput(t *testing.T) {
	// nil returns nil.
	if FromFormInput(nil) != nil {
		t.Error("FromFormInput(nil) should be nil")
	}

	tests := []struct {
		how       action.How
		value     string
		wantName  string
		wantID    string
		wantXPath string
	}{
		{action.HowID, "user", "", "user", ""},
		{action.HowName, "q", "q", "", ""},
		{action.HowXPath, "/html/body/input", "", "", "/html/body/input"},
	}
	for _, tt := range tests {
		fi := action.NewFormInput(action.InputTypeText, action.NewIdentification(tt.how, tt.value))
		d := FromFormInput(fi)
		if d.Name != tt.wantName || d.ID != tt.wantID || d.XPath != tt.wantXPath {
			t.Errorf("how=%v: got name=%q id=%q xpath=%q", tt.how, d.Name, d.ID, d.XPath)
		}
	}
}

func TestFromFormInputs(t *testing.T) {
	if FromFormInputs(nil) != nil {
		t.Error("FromFormInputs(nil) should be nil")
	}
	inputs := []*action.FormInput{
		action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowID, "a")),
		nil, // skipped
		action.NewFormInput(action.InputTypeText, action.NewIdentification(action.HowName, "b")),
	}
	got := FromFormInputs(inputs)
	if len(got) != 2 {
		t.Fatalf("FromFormInputs len = %d, want 2 (nil skipped)", len(got))
	}
}

func TestFormGetFormInputs(t *testing.T) {
	f := NewForm("/html/body/form")
	f.AddInput(NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowID, "a")))
	f.AddInput(NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowName, "b")))

	inputs := f.GetFormInputs()
	if len(inputs) != 2 {
		t.Errorf("GetFormInputs len = %d, want 2", len(inputs))
	}
}
