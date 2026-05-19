package anomaly

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type Item struct {
	ID                int      // Unique identifier for the item
	FixedFieldsMask   uint32   // Bitmask indicating which fields are fixed
	FixedFieldsValues []uint32 // Values of the fixed fields
}

func GetFixedFieldsIndices(mask uint32, numFields int) []int {
	var indices []int
	for i := 0; i < numFields; i++ {
		if mask&(1<<uint(i)) != 0 {
			indices = append(indices, i)
		}
	}
	return indices
}

func ComputeFixedFieldsValuesHash(values []uint32) string {
	h := sha256.New()
	for _, v := range values {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], v)
		h.Write(buf[:])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func CreateItemFromData(id int, data []int64, numFields int) Item {
	var mask uint32
	var values []uint32
	for i := 0; i < numFields; i++ {
		if data[i] != -1 {
			mask |= 1 << uint32(i)
			values = append(values, uint32(data[i]))
		}
	}
	return Item{
		ID:                id,
		FixedFieldsMask:   mask,
		FixedFieldsValues: values,
	}
}

func BuildItemsMap(items []Item) map[uint32]map[string][]Item {
	itemsMap := make(map[uint32]map[string][]Item)
	for _, item := range items {
		mask := item.FixedFieldsMask
		hash := ComputeFixedFieldsValuesHash(item.FixedFieldsValues)

		// Initialize map for this mask if necessary
		if _, ok := itemsMap[mask]; !ok {
			itemsMap[mask] = make(map[string][]Item)
		}

		itemsMap[mask][hash] = append(itemsMap[mask][hash], item)
	}
	return itemsMap
}

func FindMatchingItems(newItemValues []uint32, itemsMap map[uint32]map[string][]Item, numFields int) []Item {
	var matches []Item
	for mask, hashMap := range itemsMap {
		indices := GetFixedFieldsIndices(mask, numFields)
		var values []uint32
		for _, idx := range indices {
			values = append(values, newItemValues[idx])
		}
		hash := ComputeFixedFieldsValuesHash(values)
		if items, ok := hashMap[hash]; ok {
			matches = append(matches, items...)
		}
	}
	return matches
}

func FindFirstMatchingItem(newItemValues []uint32, itemsMap map[uint32]map[string][]Item, numFields int) Item {
	for mask, hashMap := range itemsMap {
		indices := GetFixedFieldsIndices(mask, numFields)
		var values []uint32
		for _, idx := range indices {
			values = append(values, newItemValues[idx])
		}
		hash := ComputeFixedFieldsValuesHash(values)
		if items, ok := hashMap[hash]; ok && len(items) > 0 {
			return items[0]
		}
	}
	return Item{}
}
