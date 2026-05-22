package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSFuncDefFullName(t *testing.T) {
	d := JSFuncDef{Namespace: NsUtils, Name: "sha256"}
	assert.Equal(t, "vigolium.utils.sha256", d.FullName())
}

func TestAPIFunctionFullName(t *testing.T) {
	f := APIFunction{Namespace: NsLog, Name: "info"}
	assert.Equal(t, "vigolium.log.info", f.FullName())
}

// TestNamespaceConstants asserts every namespace constant is non-empty, is
// rooted at the vigolium root namespace, and is unique.
func TestNamespaceConstants(t *testing.T) {
	namespaces := []string{
		NsRoot, NsLog, NsUtils, NsParse, NsHTTP, NsScan, NsIngest, NsAgent,
		NsDB, NsDBRecords, NsDBFindings, NsOAST, NsRecord, NsConfig, NsMCP,
	}

	assert.Equal(t, "vigolium", NsRoot)

	seen := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		assert.NotEmpty(t, ns)
		assert.True(t, ns == NsRoot || strings.HasPrefix(ns, NsRoot+"."),
			"namespace %q must be rooted at %q", ns, NsRoot)
		assert.False(t, seen[ns], "duplicate namespace constant %q", ns)
		seen[ns] = true
	}
}

// TestNestedNamespaceConsistency verifies the db sub-namespaces nest under db.
func TestNestedNamespaceConsistency(t *testing.T) {
	assert.True(t, strings.HasPrefix(NsDBRecords, NsDB+"."))
	assert.True(t, strings.HasPrefix(NsDBFindings, NsDB+"."))
}
