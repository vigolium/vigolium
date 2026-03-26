package state

import (
	"testing"
	"time"
)

func TestStateCreation(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		rawHTML     string
		strippedDOM string
		depth       int
		wantID      string
		wantName    string
	}{
		{
			name:        "basic state",
			url:         "http://test.com",
			rawHTML:     "<html><body>Hello</body></html>",
			strippedDOM: "HTML BODY Hello",
			depth:       0,
			wantID:      "fd0e08de1e3c89d9",
			wantName:    "state_001",
		},
		{
			name:        "deep state",
			url:         "http://test.com/page/deep",
			rawHTML:     "<html><body><div>Content</div></body></html>",
			strippedDOM: "HTML BODY DIV Content",
			depth:       5,
			wantID:      "7e22766955441618",
			wantName:    "state_001",
		},
		{
			name:        "empty content",
			url:         "http://test.com/empty",
			rawHTML:     "",
			strippedDOM: "",
			depth:       1,
			wantID:      "e3b0c44298fc1c14",
			wantName:    "state_001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ResetCounter() // Ensure clean state for each test

			s := New(tt.url, tt.rawHTML, tt.strippedDOM, tt.depth)

			if s == nil {
				t.Fatal("expected non-nil state")
			}

			// Check ID matches expected hash
			if s.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", s.ID, tt.wantID)
			}

			// Check name is exact
			if s.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", s.Name, tt.wantName)
			}

			// Check URL is set
			if s.URL != tt.url {
				t.Errorf("URL = %q, want %q", s.URL, tt.url)
			}

			// Check HTML content is stored
			if s.RawHTML != tt.rawHTML {
				t.Errorf("RawHTML = %q, want %q", s.RawHTML, tt.rawHTML)
			}

			if s.StrippedDOM != tt.strippedDOM {
				t.Errorf("StrippedDOM = %q, want %q", s.StrippedDOM, tt.strippedDOM)
			}

			// Check depth
			if s.Depth != tt.depth {
				t.Errorf("Depth = %d, want %d", s.Depth, tt.depth)
			}

			// Check timestamp is set
			if s.CreatedAt.IsZero() {
				t.Error("CreatedAt should not be zero")
			}

			// Check near-duplicate fields are initialized empty
			wantNearestStateID := ""
			if s.NearestStateID != wantNearestStateID {
				t.Errorf("NearestStateID = %q, want %q", s.NearestStateID, wantNearestStateID)
			}
			if s.IsNearDuplicate {
				t.Error("IsNearDuplicate should be false initially")
			}
		})
	}
}

func TestStateSequentialNaming(t *testing.T) {
	ResetCounter()

	s1 := New("http://test.com", "html1", "stripped1", 0)
	s2 := New("http://test.com", "html2", "stripped2", 0)
	s3 := New("http://test.com", "html3", "stripped3", 0)

	if s1.Name != "state_001" {
		t.Errorf("s1.Name = %q, want state_001", s1.Name)
	}
	if s2.Name != "state_002" {
		t.Errorf("s2.Name = %q, want state_002", s2.Name)
	}
	if s3.Name != "state_003" {
		t.Errorf("s3.Name = %q, want state_003", s3.Name)
	}
}

func TestStateIndex(t *testing.T) {
	ResetCounter()

	index := NewIndex("http://test.com/", "<html></html>", "HTML")

	if index == nil {
		t.Fatal("expected non-nil index state")
	}

	// Index should have special name
	if index.Name != "index" {
		t.Errorf("Name = %q, want 'index'", index.Name)
	}

	// Index should have depth 0
	if index.Depth != 0 {
		t.Errorf("Depth = %d, want 0", index.Depth)
	}

	// IsIndex should return true
	if !index.IsIndex() {
		t.Error("IsIndex() should return true")
	}

	// Regular state should not be index
	ResetCounter()
	regular := New("http://test.com/page", "<html></html>", "HTML", 1)
	if regular.IsIndex() {
		t.Error("regular state IsIndex() should return false")
	}
}

func TestStateIndexWithDepthZero(t *testing.T) {
	ResetCounter()

	// A state at depth 0 should also be considered index
	s := New("http://test.com", "<html></html>", "HTML", 0)

	if !s.IsIndex() {
		t.Error("state at depth 0 should be considered index")
	}
}

func TestStateEquality(t *testing.T) {
	ResetCounter()

	// Same stripped DOM should produce same ID
	s1 := New("http://test.com/page1", "<html>raw1</html>", "same stripped", 0)
	s2 := New("http://test.com/page2", "<html>raw2</html>", "same stripped", 1)

	if s1.ID != s2.ID {
		t.Errorf("same stripped DOM should produce same ID: %s vs %s", s1.ID, s2.ID)
	}

	if !s1.Equals(s2) {
		t.Error("Equals() should return true for same ID")
	}

	// Different stripped DOM should produce different ID
	s3 := New("http://test.com", "<html></html>", "different stripped", 0)
	if s1.ID == s3.ID {
		t.Error("different stripped DOM should produce different ID")
	}

	if s1.Equals(s3) {
		t.Error("Equals() should return false for different ID")
	}

	// Equals with nil should return false
	if s1.Equals(nil) {
		t.Error("Equals(nil) should return false")
	}
}

func TestStateClone(t *testing.T) {
	ResetCounter()

	original := New("http://test.com", "<html>raw</html>", "stripped", 2)
	original.SetNearestState("other-id", 0.5)
	original.MarkAsNearDuplicate()

	clone := original.Clone()

	if clone == nil {
		t.Fatal("Clone() returned nil")
	}

	// Clone should be a different pointer
	if clone == original {
		t.Error("Clone() should return a different pointer")
	}

	// All fields should be equal
	if clone.ID != original.ID {
		t.Errorf("ID: clone=%q, original=%q", clone.ID, original.ID)
	}
	if clone.Name != original.Name {
		t.Errorf("Name: clone=%q, original=%q", clone.Name, original.Name)
	}
	if clone.URL != original.URL {
		t.Errorf("URL: clone=%q, original=%q", clone.URL, original.URL)
	}
	if clone.StrippedDOM != original.StrippedDOM {
		t.Errorf("StrippedDOM: clone=%q, original=%q", clone.StrippedDOM, original.StrippedDOM)
	}
	if clone.RawHTML != original.RawHTML {
		t.Errorf("RawHTML: clone=%q, original=%q", clone.RawHTML, original.RawHTML)
	}
	if clone.Depth != original.Depth {
		t.Errorf("Depth: clone=%d, original=%d", clone.Depth, original.Depth)
	}
	if clone.NearestStateID != original.NearestStateID {
		t.Errorf("NearestStateID: clone=%q, original=%q", clone.NearestStateID, original.NearestStateID)
	}
	if clone.DistToNearest != original.DistToNearest {
		t.Errorf("DistToNearest: clone=%f, original=%f", clone.DistToNearest, original.DistToNearest)
	}
	if clone.IsNearDuplicate != original.IsNearDuplicate {
		t.Errorf("IsNearDuplicate: clone=%v, original=%v", clone.IsNearDuplicate, original.IsNearDuplicate)
	}

	// Modifying clone should not affect original
	clone.URL = "http://modified.com"
	if original.URL == "http://modified.com" {
		t.Error("modifying clone affected original")
	}
}

func TestStateDOMSize(t *testing.T) {
	ResetCounter()

	rawHTML := "<html><body><div>Hello World</div></body></html>"
	strippedDOM := "HTML BODY DIV Hello World"

	s := New("http://test.com", rawHTML, strippedDOM, 0)

	if s.DOMSize() != len(strippedDOM) {
		t.Errorf("DOMSize() = %d, want %d", s.DOMSize(), len(strippedDOM))
	}

	if s.RawSize() != len(rawHTML) {
		t.Errorf("RawSize() = %d, want %d", s.RawSize(), len(rawHTML))
	}
}

func TestStateNearDuplicate(t *testing.T) {
	ResetCounter()

	s := New("http://test.com", "<html></html>", "HTML", 0)

	// Initially not a near-duplicate
	if s.IsNearDuplicate {
		t.Error("should not be near-duplicate initially")
	}
	if s.NearestStateID != "" {
		t.Error("NearestStateID should be empty initially")
	}
	if s.DistToNearest != 0 {
		t.Error("DistToNearest should be 0 initially")
	}

	// Set nearest state
	s.SetNearestState("nearest-123", 0.75)

	if s.NearestStateID != "nearest-123" {
		t.Errorf("NearestStateID = %q, want 'nearest-123'", s.NearestStateID)
	}
	if s.DistToNearest != 0.75 {
		t.Errorf("DistToNearest = %f, want 0.75", s.DistToNearest)
	}

	// Mark as near-duplicate
	s.MarkAsNearDuplicate()

	if !s.IsNearDuplicate {
		t.Error("IsNearDuplicate should be true after MarkAsNearDuplicate()")
	}
}

func TestStateString(t *testing.T) {
	ResetCounter()

	s := New("http://test.com/page", "<html></html>", "HTML", 2)

	str := s.String()

	// Verify exact format: "State{ID:07239dbd2a1a1dd7, Name:state_001, URL:http://test.com/page, Depth:2}"
	want := "State{ID:07239dbd2a1a1dd7, Name:state_001, URL:http://test.com/page, Depth:2}"
	if str != want {
		t.Errorf("String() = %q, want %q", str, want)
	}
}

func TestResetCounter(t *testing.T) {
	// Create some states
	New("http://test.com", "", "", 0)
	New("http://test.com", "", "", 0)
	New("http://test.com", "", "", 0)

	// Reset counter
	ResetCounter()

	// Next state should be state_001
	s := New("http://test.com", "", "", 0)
	if s.Name != "state_001" {
		t.Errorf("after reset, Name = %q, want state_001", s.Name)
	}
}

func TestStateIDDeterministic(t *testing.T) {
	ResetCounter()

	// Same input should always produce same ID
	dom1 := "deterministic content"
	dom2 := "deterministic content"

	s1 := New("http://test.com", "", dom1, 0)
	s2 := New("http://test.com", "", dom2, 0)

	if s1.ID != s2.ID {
		t.Errorf("same content should produce same ID: %s vs %s", s1.ID, s2.ID)
	}
}

func TestStateIDFromStrippedDOM(t *testing.T) {
	ResetCounter()

	// ID should be based on stripped DOM, not raw HTML
	s1 := New("http://test.com", "<html>different raw 1</html>", "same stripped", 0)
	s2 := New("http://test.com", "<html>different raw 2</html>", "same stripped", 0)

	if s1.ID != s2.ID {
		t.Error("ID should be based on stripped DOM, not raw HTML")
	}
}

// ============================================================================
// ============================================================================

func TestStateHashCode(t *testing.T) {
	// States with same stripped DOM should have same hash (ID)
	ResetCounter()
	dom := "<body></body>"

	state1 := New("http://test.com/foo", "", dom, 1)
	state2 := New("http://test.com/bar", "", dom, 2)

	// Hash based on DOM, not name or URL
	if state1.ID != state2.ID {
		t.Errorf("states with same DOM should have same ID: %s vs %s", state1.ID, state2.ID)
	}
}

func TestStateVertexConstructor(t *testing.T) {
	ResetCounter()

	// Test with empty DOM
	sv1 := New("http://test.com", "", "", 0)
	if sv1 == nil {
		t.Fatal("expected non-nil state with empty DOM")
	}

	// Test with content
	sv2 := New("http://test.com", "<html>raw</html>", "<body></body>", 1)
	if sv2 == nil {
		t.Fatal("expected non-nil state with content")
	}
}

func TestGetName(t *testing.T) {
	ResetCounter()

	index := NewIndex("http://test.com", "", "<body></body>")
	if index.Name != "index" {
		t.Errorf("Name = %q, want 'index'", index.Name)
	}

	// NewIndex increments counter, so next state is state_002
	s := New("http://test.com", "", "dom", 1)
	if s.Name != "state_002" {
		t.Errorf("Name = %q, want 'state_002'", s.Name)
	}
}

func TestGetDom(t *testing.T) {
	ResetCounter()

	dom := "<body><div>content</div></body>"
	s := New("http://test.com", "<html>"+dom+"</html>", dom, 0)

	if s.StrippedDOM != dom {
		t.Errorf("StrippedDOM = %q, want %q", s.StrippedDOM, dom)
	}
}

func TestEqualsObject(t *testing.T) {
	ResetCounter()

	dom := "<body></body>"
	differentDom := "<table><div>bla</div></table>"

	stateEqual := New("http://test.com/foo", "", dom, 1)
	stateNotEqual := New("http://test.com/foo", "", differentDom, 2)
	sv := New("http://test.com/bar", "", dom, 1)

	// Same DOM = equal
	if !stateEqual.Equals(sv) {
		t.Error("states with same DOM should be equal")
	}

	// Different DOM = not equal
	if stateNotEqual.Equals(sv) {
		t.Error("states with different DOM should not be equal")
	}

	// Nil = not equal
	if stateEqual.Equals(nil) {
		t.Error("state should not equal nil")
	}
}

func TestToString(t *testing.T) {
	ResetCounter()

	s := New("http://test.com", "", "<body></body>", 0)

	str := s.String()
	// Verify exact format
	want := "State{ID:0c62c11e910d7c0d, Name:state_001, URL:http://test.com, Depth:0}"
	if str != want {
		t.Errorf("String() = %q, want %q", str, want)
	}
}

func TestGetDomSize(t *testing.T) {
	HTML := "<SCRIPT src='js/jquery-1.2.1.js' type='text/javascript'></SCRIPT> " +
		"<SCRIPT src='js/jquery-1.2.3.js' type='text/javascript'></SCRIPT>" +
		"<body><div id='firstdiv' class='orange'></div><div><span id='thespan'>" +
		"<a id='thea'>test</a></span></div></body>"

	ResetCounter()
	sv := New("http://test.com", HTML, HTML, 1)

	count := sv.DOMSize()
	expectedCount := len(HTML)

	if count != expectedCount {
		t.Errorf("DOMSize() = %d, want %d", count, expectedCount)
	}
}

func TestSerializability(t *testing.T) {
	HTML := "<SCRIPT src='js/jquery-1.2.1.js' type='text/javascript'></SCRIPT> " +
		"<SCRIPT src='js/jquery-1.2.3.js' type='text/javascript'></SCRIPT>" +
		"<body><div id='firstdiv' class='orange'></div><div><span id='thespan'>" +
		"<a id='thea'>test</a></span></div></body>"

	ResetCounter()
	sv := New("http://test.com", HTML, HTML, 2)

	// Clone is Go's equivalent of serialize/deserialize
	cloned := sv.Clone()

	// Should be equal
	if !cloned.Equals(sv) {
		t.Error("cloned state should equal original")
	}
	if cloned.Name != sv.Name {
		t.Errorf("cloned Name = %q, want %q", cloned.Name, sv.Name)
	}
	if cloned.StrippedDOM != sv.StrippedDOM {
		t.Errorf("cloned StrippedDOM should match original")
	}
}

// ============================================================================
// Additional state tests for comprehensive coverage
// ============================================================================

func TestStateNotEqualToDifferentType(t *testing.T) {
	// States should only equal other states (or compare by ID)
	ResetCounter()
	s := New("http://test.com", "", "<body></body>", 0)

	// Equals only compares with other State pointers
	if s.Equals(nil) {
		t.Error("state should not equal nil")
	}

	// Two states with same DOM
	s2 := New("http://test.com", "", "<body></body>", 0)
	if !s.Equals(s2) {
		t.Error("states with same DOM should be equal")
	}
}

func TestStateImmutability(t *testing.T) {
	// Verify Clone provides proper isolation
	ResetCounter()
	original := New("http://test.com", "raw", "stripped", 1)
	original.SetNearestState("near", 0.5)

	clone := original.Clone()
	clone.NearestStateID = "modified"
	clone.URL = "http://modified.com"

	if original.NearestStateID != "near" {
		t.Error("modifying clone should not affect original NearestStateID")
	}
	if original.URL != "http://test.com" {
		t.Error("modifying clone should not affect original URL")
	}
}

func TestStateCreatedAtTimestamp(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)

	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	// Timestamp should be recent (within last second)
	elapsed := time.Since(s.CreatedAt)
	if elapsed > time.Second {
		t.Errorf("CreatedAt should be recent, but was %v ago", elapsed)
	}
}

func TestStateDepthTracking(t *testing.T) {
	ResetCounter()

	tests := []struct {
		depth   int
		isIndex bool
	}{
		{0, true},
		{1, false},
		{5, false},
		{100, false},
	}

	for _, tt := range tests {
		s := New("http://test.com", "", "dom_"+string(rune('A'+tt.depth)), tt.depth)
		if s.Depth != tt.depth {
			t.Errorf("Depth = %d, want %d", s.Depth, tt.depth)
		}
		if s.IsIndex() != tt.isIndex {
			t.Errorf("depth %d: IsIndex() = %v, want %v", tt.depth, s.IsIndex(), tt.isIndex)
		}
	}
}
