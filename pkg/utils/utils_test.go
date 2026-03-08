package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitPathRecursive(t *testing.T) {
	a := SplitPathRecursive("/admin/password/aaaa")
	assert.Len(t, a, 2)
	b := SplitPathRecursive("/admin/password/index.php")
	assert.Len(t, b, 2)
	c := SplitPathRecursive("/admin/password/index.php?id=1")
	assert.Len(t, c, 2)
	d := SplitPathRecursive("/admin/password/aaaa/")
	// [/admin /admin/password /admin/password/aaaa]

	assert.Len(t, d, 3)

}
