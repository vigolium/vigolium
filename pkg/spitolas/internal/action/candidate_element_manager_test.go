// Package action provides web crawling action types and handling.
// This file ports CandidateElementManagerTest.java from Crawljax exactly.
package action

import (
	"sync"
	"testing"
	"time"
)

// =============================================================================
// CRAWLJAX PARITY: CandidateElementManagerTest.java
// Test for the CandidateElementManager.
// Author: Stefan Lenselink <S.R.Lenselink@student.tudelft.nl>
// =============================================================================

// TestContainsElement tests basic element checking and marking.
// Crawljax parity: CandidateElementManagerTest.testContainsElement()
func TestContainsElement(t *testing.T) {
	// Java: CandidateElementManager manager = new CandidateElementManager(null, null);
	manager := NewCandidateElementManager(nil, nil)

	// Java: Element e = document.createElement("test");
	// Java: e.setAttribute("id", "abc");
	// Java: CandidateElement c = new CandidateElement(e, "", noFormInput);
	c := newTestCandidateElement("TEST", map[string]string{"id": "abc"})

	// Assert.assertFalse("CandidateElement.GeneralString not yet checked in CandidateElementManager",
	//     manager.isChecked(c.getGeneralString()));
	if manager.IsChecked(c.GetGeneralString()) {
		t.Errorf("CandidateElement.GeneralString should not be checked yet")
	}

	// Assert.assertFalse("CandidateElement.UniqueString not yet checked in CandidateElementManager",
	//     manager.isChecked(c.getUniqueString()));
	if manager.IsChecked(c.GetUniqueString()) {
		t.Errorf("CandidateElement.UniqueString should not be checked yet")
	}

	// Assert.assertTrue("CandidateElement correctly added", manager.markChecked(c));
	if !manager.MarkChecked(c) {
		t.Errorf("CandidateElement should be correctly added (markChecked should return true)")
	}

	// Assert.assertTrue("CandidateElement.GeneralString checked in CandidateElementManager",
	//     manager.isChecked(c.getGeneralString()));
	if !manager.IsChecked(c.GetGeneralString()) {
		t.Errorf("CandidateElement.GeneralString should be checked now")
	}

	// Assert.assertTrue("CandidateElement.UniqueString checked in CandidateElementManager",
	//     manager.isChecked(c.getUniqueString()));
	if !manager.IsChecked(c.GetUniqueString()) {
		t.Errorf("CandidateElement.UniqueString should be checked now")
	}

	// Second element with different id
	// Java: e.setAttribute("id", "def");
	// Java: CandidateElement c2 = new CandidateElement(e, "", noFormInput);
	c2 := newTestCandidateElement("TEST", map[string]string{"id": "def"})

	// Assert.assertFalse("CandidateElement.GeneralString not yet checked in CandidateElementManager",
	//     manager.isChecked(c2.getGeneralString()));
	if manager.IsChecked(c2.GetGeneralString()) {
		t.Errorf("c2.GeneralString should not be checked yet")
	}

	// Assert.assertFalse("CandidateElement.UniqueString not yet checked in CandidateElementManager",
	//     manager.isChecked(c2.getUniqueString()));
	if manager.IsChecked(c2.GetUniqueString()) {
		t.Errorf("c2.UniqueString should not be checked yet")
	}

	// Assert.assertTrue("CandidateElement correctly added", manager.markChecked(c2));
	if !manager.MarkChecked(c2) {
		t.Errorf("c2 should be correctly added (markChecked should return true)")
	}

	// Assert.assertTrue("CandidateElement.GeneralString checked in CandidateElementManager",
	//     manager.isChecked(c2.getGeneralString()));
	if !manager.IsChecked(c2.GetGeneralString()) {
		t.Errorf("c2.GeneralString should be checked now")
	}

	// Assert.assertTrue("CandidateElement.UniqueString checked in CandidateElementManager",
	//     manager.isChecked(c2.getUniqueString()));
	if !manager.IsChecked(c2.GetUniqueString()) {
		t.Errorf("c2.UniqueString should be checked now")
	}

	// Try to add c2 again - should fail
	// Assert.assertFalse("CandidateElement already added", manager.markChecked(c2));
	if manager.MarkChecked(c2) {
		t.Errorf("c2 already added, markChecked should return false")
	}

	// Assert.assertTrue("CandidateElement.GeneralString checked in CandidateElementManager",
	//     manager.isChecked(c2.getGeneralString()));
	if !manager.IsChecked(c2.GetGeneralString()) {
		t.Errorf("c2.GeneralString should still be checked")
	}

	// Assert.assertTrue("CandidateElement.UniqueString checked in CandidateElementManager",
	//     manager.isChecked(c2.getUniqueString()));
	if !manager.IsChecked(c2.GetUniqueString()) {
		t.Errorf("c2.UniqueString should still be checked")
	}
}

// TestContainsElementAtusa tests element checking with atusa attribute.
// Crawljax parity: CandidateElementManagerTest.testContainsElementAtusa()
func TestContainsElementAtusa(t *testing.T) {
	// Java: CandidateElementManager manager = new CandidateElementManager(null, null);
	manager := NewCandidateElementManager(nil, nil)

	// Java: Element e = document.createElement("test");
	// Java: e.setAttribute("id", "abc");
	// Java: e.setAttribute("atusa", "def");
	// Java: CandidateElement c = new CandidateElement(e, "", noFormInput);
	c := newTestCandidateElement("TEST", map[string]string{"id": "abc", "atusa": "def"})

	// Assert.assertFalse("CandidateElement.GeneralString not yet checked in CandidateElementManager",
	//     manager.isChecked(c.getGeneralString()));
	if manager.IsChecked(c.GetGeneralString()) {
		t.Errorf("CandidateElement.GeneralString should not be checked yet")
	}

	// Assert.assertFalse("CandidateElement.UniqueString not yet checked in CandidateElementManager",
	//     manager.isChecked(c.getUniqueString()));
	if manager.IsChecked(c.GetUniqueString()) {
		t.Errorf("CandidateElement.UniqueString should not be checked yet")
	}

	// Assert.assertTrue("CandidateElement correctly added", manager.markChecked(c));
	if !manager.MarkChecked(c) {
		t.Errorf("CandidateElement should be correctly added")
	}

	// Assert.assertTrue("CandidateElement.GeneralString checked in CandidateElementManager",
	//     manager.isChecked(c.getGeneralString()));
	if !manager.IsChecked(c.GetGeneralString()) {
		t.Errorf("CandidateElement.GeneralString should be checked now")
	}

	// Assert.assertTrue("CandidateElement.UniqueString checked in CandidateElementManager",
	//     manager.isChecked(c.getUniqueString()));
	if !manager.IsChecked(c.GetUniqueString()) {
		t.Errorf("CandidateElement.UniqueString should be checked now")
	}

	// Change only atusa attribute - generalString stays the same, uniqueString changes
	// Java: e.setAttribute("atusa", "ghi");
	// Java: CandidateElement c2 = new CandidateElement(e, "", noFormInput);
	c2 := newTestCandidateElement("TEST", map[string]string{"id": "abc", "atusa": "ghi"})

	// Assert.assertTrue("CandidateElement.GeneralString checked in CandidateElementManager",
	//     manager.isChecked(c2.getGeneralString()));
	// Note: GeneralString excludes atusa, so it's the same as c's GeneralString
	if !manager.IsChecked(c2.GetGeneralString()) {
		t.Errorf("c2.GeneralString should already be checked (same as c's since atusa is excluded)")
	}

	// Assert.assertFalse("CandidateElement.UniqueString not yet checked in CandidateElementManager",
	//     manager.isChecked(c2.getUniqueString()));
	// Note: UniqueString includes atusa, so it's different from c's UniqueString
	if manager.IsChecked(c2.GetUniqueString()) {
		t.Errorf("c2.UniqueString should NOT be checked yet (different atusa value)")
	}

	// Assert.assertTrue("CandidateElement correctly added", manager.markChecked(c2));
	if !manager.MarkChecked(c2) {
		t.Errorf("c2 should be correctly added (new uniqueString)")
	}

	// Assert.assertTrue("CandidateElement.GeneralString checked in CandidateElementManager",
	//     manager.isChecked(c2.getGeneralString()));
	if !manager.IsChecked(c2.GetGeneralString()) {
		t.Errorf("c2.GeneralString should be checked")
	}

	// Assert.assertTrue("CandidateElement.UniqueString checked in CandidateElementManager",
	//     manager.isChecked(c2.getUniqueString()));
	if !manager.IsChecked(c2.GetUniqueString()) {
		t.Errorf("c2.UniqueString should be checked now")
	}
}

// TestConcurrentIncrement tests thread-safe counter increment.
// Crawljax parity: CandidateElementManagerTest.testConcurrentIncrement()
// Note: This does not 100% guarantee that thread-interleaving happens but its better than not testing at all.
func TestConcurrentIncrement(t *testing.T) {
	const (
		// Crawljax exact values:
		// for (int i = 0; i < 10; i++) {
		//     new Thread(() -> {
		//         for (int j = 0; j < 10; j++) {
		//             manager.increaseElementsCounter();
		//         }
		//     }).start();
		// }
		// Assert.assertEquals("100 Elements should be checked", 100, manager.numberOfExaminedElements());
		NUM_THREADS       = 10
		INCREMENTS_EACH   = 10
		EXPECTED_ELEMENTS = 100 // NUM_THREADS * INCREMENTS_EACH
	)

	manager := NewCandidateElementManager(nil, nil)

	var wg sync.WaitGroup
	for i := 0; i < NUM_THREADS; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < INCREMENTS_EACH; j++ {
				manager.IncreaseElementsCounter()
				// Java: Thread.sleep(10);
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Assert.assertEquals("100 Elements should be checked", 100, manager.numberOfExaminedElements());
	actual := manager.NumberOfExaminedElements()
	if actual != EXPECTED_ELEMENTS {
		t.Errorf("NumberOfExaminedElements() = %d, want %d", actual, EXPECTED_ELEMENTS)
	}
}
