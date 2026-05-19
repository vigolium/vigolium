package anomaly

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

// func printInvariantAttributes(base *Fingerprint) {
// 	for _, s := range base.GetStaticAttributes() {
// 		point, found := base.GetAttributeValue(s)
// 		if found && point > 0 {
// 			fmt.Printf("%s: %d\n", s, point)
// 		}
// 	}
// }

func TestFingerprint_UpdateWith(t *testing.T) {
	tests := []struct {
		name           string
		fingerprints   []map[Type]uint32
		expectedIgnore []Type
		variantSize    int
	}{
		{"2 fingerprint", []map[Type]uint32{
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 123, SET_COOKIE_NAMES: 999},
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 12, SET_COOKIE_NAMES: 999},
		}, []Type{STATUS_CODE, ETAG_HEADER, SET_COOKIE_NAMES}, 3},
		{"3 fingerprint - different size", []map[Type]uint32{
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 123, SET_COOKIE_NAMES: 999},
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 12, SET_COOKIE_NAMES: 999},
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 12, SET_COOKIE_NAMES: 999},
		}, []Type{STATUS_CODE, ETAG_HEADER, SET_COOKIE_NAMES}, 3},
		{"3 fingerprint", []map[Type]uint32{
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 0, SET_COOKIE_NAMES: 0},
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 123, SET_COOKIE_NAMES: 0},
			{STATUS_CODE: 201, ETAG_HEADER: 100, SERVER_HEADER: 0, SET_COOKIE_NAMES: 9990},
		}, []Type{ETAG_HEADER}, 1},
		{"4 fingerprint - different size", []map[Type]uint32{
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 0, SET_COOKIE_NAMES: 0},
			{STATUS_CODE: 200, ETAG_HEADER: 100, SERVER_HEADER: 123, SET_COOKIE_NAMES: 0, HEADER_TAGS: 4, OUTBOUND_EDGE_COUNT: 10},
			{STATUS_CODE: 201, ETAG_HEADER: 100, SERVER_HEADER: 0, SET_COOKIE_NAMES: 9990, OUTBOUND_EDGE_COUNT: 5},
		}, []Type{ETAG_HEADER}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprintTypes := lo.Keys(tt.fingerprints[0])

			base := NewFingerprint(fingerprintTypes)

			for _, f := range tt.fingerprints {
				base.update(f)
			}
			t.Log(base.GetStaticAttributes())
			t.Log(base.GetDynamicAttributes())
			for _, enum := range tt.expectedIgnore {
				assert.Contains(t, base.GetStaticAttributes(), enum)
			}
			// assert.Equal(t, tt.variantSize, len(base.GetDynamicAttributes()))
			// assert.Equal(t, len(GetAllFingerprintAttributes())-tt.variantSize, len(base.GetStaticAttributes()))
		})
	}
}

func TestFingerprint_UpdateFromFingerprint(t *testing.T) {
	type record struct {
		statusCode int
		headers    map[string][]string
		// cookies     map[string][]string
	}
	tests := []struct {
		name       string
		records    []record
		staticSize int
	}{
		{"2 same", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"100"},
					"Server":        {"123"},
					"Last-Modified": {"999"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"100"},
					"Server":        {"123"},
					"Last-Modified": {"999"},
				}},
		}, 4},
		{"2 different", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"100"},
					"Server":        {"123"},
					"Last-Modified": {"999"},
				}},
			{
				201,
				map[string][]string{
					"Etag":          {"101"},
					"Server":        {"124"},
					"Last-Modified": {"998"},
				}},
		}, 0},
		{"3 mixed - different all", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"100"},
					"Server":        {"123"},
					"Last-Modified": {"999"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"100"},
					"Server":        {"123"},
					"Last-Modified": {"999"},
				}},
			{
				202,
				map[string][]string{
					"Etag":          {"102"},
					"Server":        {"125"},
					"Last-Modified": {"997"},
				}},
		}, 0},
		{"all headers different", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"200"},
					"Server":        {"Apache"},
					"Last-Modified": {"1000"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"201"},
					"Server":        {"Nginx"},
					"Last-Modified": {"1001"},
				}},
		}, 1},
		{"status code different", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"300"},
					"Server":        {"Apache"},
					"Last-Modified": {"1100"},
				}},
			{
				404,
				map[string][]string{
					"Etag":          {"300"},
					"Server":        {"Apache"},
					"Last-Modified": {"1100"},
				}},
		}, 3},
		{"mixed attributes", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"400"},
					"Server":        {"IIS"},
					"Last-Modified": {"1200"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"401"},
					"Server":        {"IIS"},
					"Last-Modified": {"1201"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"402"},
					"Server":        {"Apache"},
					"Last-Modified": {"1202"},
				}},
		}, 1},
		{"history attributes", []record{
			{
				200,
				map[string][]string{
					"Etag":          {"400"},
					"Server":        {"Apache"},
					"Last-Modified": {"1200"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"401"},
					"Server":        {"IIS"},
					"Last-Modified": {"1200"},
				}},
			{
				200,
				map[string][]string{
					"Etag":          {"401"}, // equal to previous
					"Server":        {"IIS"},
					"Last-Modified": {"1202"},
				}},
		}, 1},
	}

	fingerprintTypes := []Type{STATUS_CODE, ETAG_HEADER, SERVER_HEADER, LAST_MODIFIED_HEADER}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var base *Fingerprint
			for _, f := range tt.records {
				if base == nil {
					base = NewFingerprint2(f.statusCode, "", f.headers, fingerprintTypes)
				} else {
					toUpdate := NewFingerprint2(f.statusCode, "", f.headers, fingerprintTypes)
					base.updateFromFingerprint(toUpdate)
				}

			}

			assert.Equal(t, tt.staticSize, len(base.GetStaticAttributes()))
			t.Log(base.GetStaticAttributes())
			t.Log(base.GetDynamicAttributes())
			// assert.Equal(t, tt.variantSize, len(base.GetDynamicAttributes()))
			// assert.Equal(t, len(GetAllFingerprintAttributes())-tt.variantSize, len(base.GetStaticAttributes()))
		})
	}
}
