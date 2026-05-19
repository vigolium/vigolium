package diffscan

import (
	"fmt"
	"math"
	"sort"
)

type QuantitativeMeasurements struct {
	Measurements []int64
	Key          string
	Factor       int
}

func NewQuantitativeMeasurements(key string, factor int) *QuantitativeMeasurements {
	return &QuantitativeMeasurements{
		Measurements: make([]int64, 0),
		Key:          key,
		Factor:       factor,
	}
}

func (qm *QuantitativeMeasurements) UpdateWith(val int64) {
	qm.Measurements = append(qm.Measurements, val)
	sort.Slice(qm.Measurements, func(i, j int) bool { return qm.Measurements[i] < qm.Measurements[j] })
}

func (qm *QuantitativeMeasurements) Merge(newMeasurements *QuantitativeMeasurements) {
	qm.Measurements = append(qm.Measurements, newMeasurements.Measurements...)
	sort.Slice(qm.Measurements, func(i, j int) bool { return qm.Measurements[i] < qm.Measurements[j] })
}

func (qm *QuantitativeMeasurements) String() string {
	return fmt.Sprintf("%v", qm.Measurements)
}

func (qm *QuantitativeMeasurements) BasicOverlap(o *QuantitativeMeasurements) bool {
	const OFFSET = 0
	return minInt64(o.Measurements) < maxInt64(qm.Measurements)+OFFSET &&
		maxInt64(o.Measurements) > minInt64(qm.Measurements)-OFFSET
}

func (qm *QuantitativeMeasurements) QuantileOverlap(compareMeasurements *QuantitativeMeasurements) bool {
	compare := compareMeasurements.Measurements
	if len(compare) == 0 || len(qm.Measurements) == 0 {
		return false
	}
	return compare[0] <= qm.GetQuantileTop(qm.Measurements) &&
		qm.GetQuantileTop(compare) >= qm.Measurements[0]
}

func (qm *QuantitativeMeasurements) GetQuantileTop(list []int64) int64 {
	if len(list) == 0 {
		return 0
	}
	FACTOR := qm.Factor
	if FACTOR <= 0 {
		FACTOR = 1
	}
	idx := int(math.Ceil(float64(len(list))/float64(FACTOR))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(list) {
		idx = len(list) - 1
	}
	return list[idx]
}

func (qm *QuantitativeMeasurements) Equals(o interface{}) bool {
	if qm == o {
		return true
	}
	if otherQm, ok := o.(*QuantitativeMeasurements); ok {
		return qm.QuantileOverlap(otherQm)
	}
	return false
}

func minInt64(slice []int64) int64 {
	if len(slice) == 0 {
		return 0
	}
	minVal := slice[0]
	for _, v := range slice {
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}

func maxInt64(slice []int64) int64 {
	if len(slice) == 0 {
		return 0
	}
	maxVal := slice[0]
	for _, v := range slice {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}
