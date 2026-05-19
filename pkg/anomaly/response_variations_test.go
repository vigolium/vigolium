package anomaly

import "testing"

func Test_fastResponseDetails(t *testing.T) {
	a := NewFastResponseVariations()
	raw := `HTTP/1.1 200 OK
Content-Type: text/html

<html><body>a a</body></html>
	`
	a.UpdateWith([]byte(raw))
	t.Log(a.attributes)

}
