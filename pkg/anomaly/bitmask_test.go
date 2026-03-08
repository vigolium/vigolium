package anomaly

import (
	"reflect"
	"sort"
	"testing"
)

func Test_FindMatchingItems(t *testing.T) {
	tests := []struct {
		name            string
		existingItems   [][]int64
		newItem         []uint32
		expectedMatches []int
	}{
		{
			name: "Basic case",
			existingItems: [][]int64{
				{0, 9, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
				{1, -1, 3, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
				{1, -1, -1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
			newItem:         []uint32{0, 9, 5, 7, 3, 2, 8, 6, 4, 1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			expectedMatches: []int{0},
		},
		{
			name: "No matching results",
			existingItems: [][]int64{
				{1, 2, 3, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
				{5, 6, 7, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
			newItem:         []uint32{9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8},
			expectedMatches: []int{},
		},
		{
			name: "Multiple matching results",
			existingItems: [][]int64{
				{0, 1, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
				{0, 1, 2, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
				{0, 1, 2, 3, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			},
			newItem:         []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			expectedMatches: []int{0, 1, 2},
		},
		{
			name: "Different one field",
			existingItems: [][]int64{
				{-1, -1, 312, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
				{-1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 30, -1},
			},
			newItem:         []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			expectedMatches: []int{1},
		},
		{
			name: "Short fingerprint",
			existingItems: [][]int64{
				{-1, -1, 312, -1, -1, -1, -1},
				{-1, -1, -1, -1, -1, 2345, -1},
			},
			newItem:         []uint32{0, 1, 2, 3, 4, 2345, 6},
			expectedMatches: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var items []Item
			numFields := len(tt.existingItems[0])
			for id, data := range tt.existingItems {
				item := CreateItemFromData(id, data, numFields)
				t.Logf("item: %v", item)
				items = append(items, item)
			}

			itemsMap := BuildItemsMap(items)
			t.Logf("itemsMap: %v", itemsMap)
			matches := FindMatchingItems(tt.newItem, itemsMap, numFields)

			var matchIDs []int
			for _, match := range matches {
				matchIDs = append(matchIDs, match.ID)
			}
			t.Logf("matchIDs: %v", matchIDs)
			if len(tt.expectedMatches) == 0 && len(matchIDs) == 0 {
				return
			}
			sort.Ints(matchIDs)

			if !reflect.DeepEqual(matchIDs, tt.expectedMatches) {
				t.Errorf("FindMatchingItems() = %v, want %v", matchIDs, tt.expectedMatches)
			}
		})
	}
}
