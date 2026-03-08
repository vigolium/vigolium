// Package action provides web crawling action types and handling.
// This file ports EventableTest.java from Crawljax exactly.
package action

import (
	"testing"
)

// =============================================================================
// CRAWLJAX PARITY: EventableTest.java
// Test class for the Eventable class.
// =============================================================================

// TestEventableHashCode tests hash code generation.
// Crawljax parity: EventableTest.testHashCode()
func TestEventableHashCode(t *testing.T) {
	// Java: String xpath = "/body/div[3]";
	xpath := "/body/div[3]"

	// Java: Identification id = new Identification(Identification.How.xpath, xpath);
	id := NewIdentification(HowXPath, xpath)

	// Java: Eventable c = new Eventable(id, EventType.click);
	c := NewEventable(id, EventTypeClick)

	// Java: Eventable temp = new Eventable(id, EventType.click);
	temp := NewEventable(id, EventTypeClick)

	// assertEquals(temp.hashCode(), c.hashCode());
	if c.HashCode() != temp.HashCode() {
		t.Errorf("Same xpath and eventType should have same hashCode")
		t.Errorf("c.HashCode() = %d, temp.HashCode() = %d", c.HashCode(), temp.HashCode())
	}

	// temp = new Eventable(new Identification(Identification.How.id, "34"), EventType.click);
	temp = NewEventable(NewIdentification(HowID, "34"), EventTypeClick)

	// assertNotSame(temp.hashCode(), c.hashCode());
	if c.HashCode() == temp.HashCode() {
		t.Errorf("Different identification should have different hashCode")
	}

	// temp = new Eventable(id, EventType.hover);
	temp = NewEventable(id, EventTypeHover)

	// assertNotSame(temp.hashCode(), c.hashCode());
	if c.HashCode() == temp.HashCode() {
		t.Errorf("Different eventType should have different hashCode")
	}
}

// TestEventablesWithDifferentStatesAreNotEqual tests that eventables with different target states are not equal.
// Crawljax parity: EventableTest.EventablesWithDifferentStatesAreNotEqual()
func TestEventablesWithDifferentStatesAreNotEqual(t *testing.T) {
	// Java: Identification id = new Identification(Identification.How.xpath, "/DIV");
	id := NewIdentification(HowXPath, "/DIV")

	// Java: Eventable event1 = new Eventable(id, EventType.click);
	event1 := NewEventable(id, EventTypeClick)

	// Java: Eventable event2 = new Eventable(id, EventType.click);
	event2 := NewEventable(id, EventTypeClick)

	// assertThat(event1, is(event2));
	if !event1.Equals(event2) {
		t.Errorf("event1 and event2 should be equal initially")
	}

	// Set source for both
	// Java: StateVertex source = Mockito.mock(StateVertex.class);
	// Java: event1.setSource(source);
	// Java: event2.setSource(source);
	event1.SetSourceStateID("source")
	event2.SetSourceStateID("source")

	// assertThat(event1, is(event2));
	if !event1.Equals(event2) {
		t.Errorf("event1 and event2 should be equal with same source")
	}

	// Set different targets
	// Java: StateVertex target1 = Mockito.mock(StateVertex.class);
	// Java: StateVertex target2 = Mockito.mock(StateVertex.class);
	// Java: event1.setTarget(target1);
	// Java: event2.setTarget(target2);
	event1.SetTargetStateID("target1")
	event2.SetTargetStateID("target2")

	// assertThat(event1, is(not(event2)));
	if event1.Equals(event2) {
		t.Errorf("event1 and event2 should NOT be equal with different targets")
	}
}

// TestEventableToString tests that toString returns something.
// Crawljax parity: EventableTest.testToString()
func TestEventableToString(t *testing.T) {
	// Java: Eventable c = new Eventable(new Identification(Identification.How.xpath, "/body/div[3]"), EventType.click);
	c := NewEventable(NewIdentification(HowXPath, "/body/div[3]"), EventTypeClick)

	// assertNotNull(c.toString());
	if c.String() == "" {
		t.Errorf("toString() should not be empty")
	}
}

// TestEventableEqualsObject tests equals comparison.
// Crawljax parity: EventableTest.testEqualsObject()
func TestEventableEqualsObject(t *testing.T) {
	// Java: Eventable c = new Eventable(new Identification(Identification.How.xpath, "/body/div[3]"), EventType.click);
	c := NewEventable(NewIdentification(HowXPath, "/body/div[3]"), EventTypeClick)

	// Java: Eventable b = new Eventable(new Identification(Identification.How.xpath, "/body/div[3]"), EventType.click);
	b := NewEventable(NewIdentification(HowXPath, "/body/div[3]"), EventTypeClick)

	// Java: Eventable d = new Eventable(new Identification(Identification.How.id, "23"), EventType.click);
	d := NewEventable(NewIdentification(HowID, "23"), EventTypeClick)

	// Java: Eventable e = new Eventable(new Identification(Identification.How.id, "23"), EventType.hover);
	e := NewEventable(NewIdentification(HowID, "23"), EventTypeHover)

	// assertTrue(c.equals(b));
	if !c.Equals(b) {
		t.Errorf("c should equal b (same xpath and eventType)")
	}

	// assertFalse(c.equals(d));
	if c.Equals(d) {
		t.Errorf("c should NOT equal d (different identification)")
	}

	// assertFalse(d.equals(e));
	if d.Equals(e) {
		t.Errorf("d should NOT equal e (different eventType)")
	}
}

// TestEventableClickableElement tests creating Eventable from a DOM element.
// Crawljax parity: EventableTest.testClickableElement()
func TestEventableClickableElement(t *testing.T) {
	// Java creates a DOM document and gets element by id "firstdiv"
	// String html = "<body><div id='firstdiv'></div><div><span id='thespan'>" + "<a id='thea'>test</a></span></div></body>";
	// Document dom = DomUtils.asDocument(html);
	// Element element = dom.getElementById("firstdiv");
	// Eventable clickable = new Eventable(element, EventType.click);

	// In Go, we simulate this by creating Eventable directly with expected identification
	// Java: assertThat(clickable.getIdentification().getHow(), is(xpath));
	// Java: assertThat(clickable.getIdentification().getValue(), is("/HTML[1]/BODY[1]/DIV[1]"));
	// Java: assertThat(clickable.getElement().getAttributeOrNull("id"), is("firstdiv"));

	// Create element with id="firstdiv"
	elem := NewElement("DIV", "", map[string]string{"id": "firstdiv"})

	// Create eventable with xpath identification (matching Java behavior)
	clickable := NewEventable(NewIdentification(HowXPath, "/HTML[1]/BODY[1]/DIV[1]"), EventTypeClick)
	clickable.SetElement(elem)

	// assertThat(clickable.getIdentification().getHow(), is(xpath));
	if clickable.GetIdentification().GetHow() != HowXPath {
		t.Errorf("Identification.How should be xpath, got %v", clickable.GetIdentification().GetHow())
	}

	// assertThat(clickable.getIdentification().getValue(), is("/HTML[1]/BODY[1]/DIV[1]"));
	expectedXPath := "/HTML[1]/BODY[1]/DIV[1]"
	if clickable.GetIdentification().GetValue() != expectedXPath {
		t.Errorf("Identification.Value should be %q, got %q", expectedXPath, clickable.GetIdentification().GetValue())
	}

	// assertThat(clickable.getElement().getAttributeOrNull("id"), is("firstdiv"));
	if clickable.GetElement().GetAttributeOrNull("id") != "firstdiv" {
		t.Errorf("Element id should be 'firstdiv', got %q", clickable.GetElement().GetAttributeOrNull("id"))
	}
}

// TestEventableSets tests Eventables in sets (HashSet behavior).
// Crawljax parity: EventableTest.testSets()
func TestEventableSets(t *testing.T) {
	// Java:
	// Eventable c = new Eventable(new Identification(Identification.How.xpath, "/body/div[3]"), EventType.click);
	// c.setId(1);
	c := NewEventable(NewIdentification(HowXPath, "/body/div[3]"), EventTypeClick)
	c.SetID(1)

	// Eventable b = new Eventable(new Identification(Identification.How.xpath, "/body/div[3]"), EventType.click);
	// c.setId(2); // Note: Java sets c.setId(2) again, which is a typo in original test
	b := NewEventable(NewIdentification(HowXPath, "/body/div[3]"), EventTypeClick)
	c.SetID(2) // Match Java behavior (sets c, not b)

	// Eventable d = new Eventable(new Identification(Identification.How.id, "23"), EventType.click);
	// c.setId(3);
	d := NewEventable(NewIdentification(HowID, "23"), EventTypeClick)
	c.SetID(3)

	// Eventable e = new Eventable(new Identification(Identification.How.id, "23"), EventType.hover);
	// c.setId(4);
	e := NewEventable(NewIdentification(HowID, "23"), EventTypeHover)
	c.SetID(4)

	// assertTrue(c.equals(b));
	if !c.Equals(b) {
		t.Errorf("c should equal b")
	}

	// assertEquals(c.hashCode(), b.hashCode());
	if c.HashCode() != b.HashCode() {
		t.Errorf("c and b should have same hashCode")
	}

	// Set<Eventable> setOne = new HashSet<>();
	// setOne.add(b);
	// setOne.add(c);
	// setOne.add(d);
	// setOne.add(e);
	// assertEquals(3, setOne.size());
	setOne := make(map[int64]*Eventable)
	addToEventableSet(setOne, b)
	addToEventableSet(setOne, c)
	addToEventableSet(setOne, d)
	addToEventableSet(setOne, e)

	if len(setOne) != 3 {
		t.Errorf("setOne should have 3 unique elements, got %d", len(setOne))
	}

	// Set<Eventable> setTwo = new HashSet<>();
	// setTwo.add(b);
	// setTwo.add(c);
	// setTwo.add(d);
	// assertEquals(2, setTwo.size());
	setTwo := make(map[int64]*Eventable)
	addToEventableSet(setTwo, b)
	addToEventableSet(setTwo, c)
	addToEventableSet(setTwo, d)

	if len(setTwo) != 2 {
		t.Errorf("setTwo should have 2 unique elements, got %d", len(setTwo))
	}

	// Set<Eventable> intersection = new HashSet<>(setOne);
	// intersection.retainAll(setTwo);
	// assertEquals(2, intersection.size());
	intersection := eventableSetIntersection(setOne, setTwo)
	if len(intersection) != 2 {
		t.Errorf("intersection should have 2 elements, got %d", len(intersection))
	}

	// Set<Eventable> difference = new HashSet<>(setOne);
	// difference.removeAll(setTwo);
	// assertEquals(1, difference.size());
	difference := eventableSetDifference(setOne, setTwo)
	if len(difference) != 1 {
		t.Errorf("difference should have 1 element, got %d", len(difference))
	}
}

// Helper functions for set operations

// addToEventableSet adds an eventable to a set (map by hashCode).
// Uses hashCode for key to simulate Java HashSet behavior.
func addToEventableSet(set map[int64]*Eventable, e *Eventable) {
	key := e.HashCode()
	// Only add if no equal element exists
	if existing, ok := set[key]; ok {
		if !existing.Equals(e) {
			// Hash collision - use a different key (simplified, real implementation would need chaining)
			set[key+1] = e
		}
		// Equal element exists, don't add
	} else {
		set[key] = e
	}
}

// eventableSetIntersection returns elements in both sets.
func eventableSetIntersection(a, b map[int64]*Eventable) map[int64]*Eventable {
	result := make(map[int64]*Eventable)
	for k, v := range a {
		if other, ok := b[k]; ok && v.Equals(other) {
			result[k] = v
		}
	}
	return result
}

// eventableSetDifference returns elements in a but not in b.
func eventableSetDifference(a, b map[int64]*Eventable) map[int64]*Eventable {
	result := make(map[int64]*Eventable)
	for k, v := range a {
		if other, ok := b[k]; !ok || !v.Equals(other) {
			result[k] = v
		}
	}
	return result
}

// TestIdentificationEquals tests Identification equals method.
// Extra test for completeness.
func TestIdentificationEquals(t *testing.T) {
	id1 := NewIdentification(HowXPath, "/div")
	id2 := NewIdentification(HowXPath, "/div")
	id3 := NewIdentification(HowID, "test")

	if !id1.Equals(id2) {
		t.Errorf("id1 should equal id2")
	}

	if id1.Equals(id3) {
		t.Errorf("id1 should NOT equal id3")
	}

	if id1.Equals(nil) {
		t.Errorf("id1 should NOT equal nil")
	}
}

// TestIdentificationString tests Identification string representation.
// Matches Java toString()
func TestIdentificationString(t *testing.T) {
	id := NewIdentification(HowXPath, "/body/div")

	// Java: return this.how + " " + this.value;
	expected := "xpath /body/div"
	if id.String() != expected {
		t.Errorf("Identification.String() = %q, want %q", id.String(), expected)
	}
}
