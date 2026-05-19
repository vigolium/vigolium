package anomaly

import (
	"testing"
)

var canaryKeys = []string{"\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"}

var resp1 = `<!DOCTYPE html>
<html>
<head>
    <base href="http://example.com/sample/">
    <meta charset="UTF-8">
    <title>Area Elements - Spider HTML Parser</title>
</head>
<body>
<map>
    <area href="//area.example.com/base/scheme"/>
    <area href="http://area.example.com:8000/b"/>
    <area href="https://area.example.com/c?a=b#fragment"/>
    <area href="area/relative"/>
    <area href=""/>
    <area href="/area/absolute"/>
    <area href="ftp://area.example.com/"/>
</map>

<!--  Ignored: -->
<map>
    <area/>
    <area href="mailto:area@example.com"/>
    <area href="javascript:hello();"/>
    <area href="scheme://area.example.com/invalid"/>
</map>

</body>
</html>
`
var resp2 = `<!DOCTYPE html>
<html>
<body>
</body>
</html>
`

var resp3 = `<!DOCTYPE html>
<html>
<body>
</body>
</html>
`

func Test_ResponseKeywords(t *testing.T) {
	keywordsAnalyser := NewResponseKeywords(canaryKeys)

	keywordsAnalyser.UpdateWith([]byte(resp1))

	keywordsAnalyser.UpdateWith([]byte(resp2))

	keywordsAnalyser.UpdateWith([]byte(resp3))

	for _, s := range canaryKeys {
		amount := keywordsAnalyser.GetKeywordCount(s)
		t.Logf("%s: %d", s, amount)
	}

	in := stringInSlice(keywordsAnalyser.GetStaticKeywords(), "</html>")
	t.Log(in)
	t.Logf("Static: %v", keywordsAnalyser.GetStaticKeywords())
	t.Logf("Dynamic: %v", keywordsAnalyser.GetDynamicKeywords())
}

// string in slice
func stringInSlice(list []string, a string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
