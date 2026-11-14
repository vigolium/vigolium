package anomaly_ranking

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLowerSharePercentiles(t *testing.T) {
	same := make([]int, 50)
	for i := range same {
		same[i] = 7
	}
	for _, p := range lowerSharePercentiles(same) {
		assert.Equal(t, 0, p, "identical responses must share one percentile")
	}
	got := lowerSharePercentiles([]int{9, 5, 5, 1})
	assert.Equal(t, []int{75, 25, 25, 0}, got)
}
