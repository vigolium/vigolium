package diffscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCanaryKeys(t *testing.T) {
	t.Run("empty canary returns default keys", func(t *testing.T) {
		keys := GetCanaryKeys("")
		assert.Len(t, keys, 33) // canaryKeys has 33 default elements
		assert.Equal(t, canaryKeys, keys)
	})

	t.Run("custom canary prepended", func(t *testing.T) {
		keys := GetCanaryKeys("mycanary")
		assert.Len(t, keys, 34) // 1 custom + 33 defaults
		assert.Equal(t, "mycanary", keys[0])
		assert.Equal(t, canaryKeys[0], keys[1])
	})

	t.Run("first key is custom canary when provided", func(t *testing.T) {
		customCanary := "test-canary-value"
		keys := GetCanaryKeys(customCanary)
		assert.Equal(t, customCanary, keys[0])
	})
}

func TestCanaryKeysContent(t *testing.T) {
	t.Run("verify security keywords present", func(t *testing.T) {
		keys := GetCanaryKeys("")

		securityKeywords := []string{
			"error",
			"exception",
			"sql syntax",
			"stack",
			"invalid",
			"warning",
			"divisor",
			"ora-",
			"SQL",
			"ODBC",
			"varchar",
		}

		for _, keyword := range securityKeywords {
			assert.Contains(t, keys, keyword, "missing keyword: %s", keyword)
		}
	})

	t.Run("verify HTML/script keywords present", func(t *testing.T) {
		keys := GetCanaryKeys("")

		htmlKeywords := []string{
			"</html>",
			"<script",
			"<div",
		}

		for _, keyword := range htmlKeywords {
			assert.Contains(t, keys, keyword, "missing keyword: %s", keyword)
		}
	})

	t.Run("verify JSON keywords present", func(t *testing.T) {
		keys := GetCanaryKeys("")

		jsonKeywords := []string{
			"\",\"",
			"true",
			"false",
			"\"\"",
			"[]",
		}

		for _, keyword := range jsonKeywords {
			assert.Contains(t, keys, keyword, "missing keyword: %s", keyword)
		}
	})
}
