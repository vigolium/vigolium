package ssr_data_exposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestExtractState(t *testing.T) {
	tests := []struct {
		name string
		body string
		blob ssrStateBlob
		want string
	}{
		{
			name: "NEXT_DATA",
			body: `<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script>`,
			blob: stateBlobs[0],
			want: `{"buildId":"abc"}`,
		},
		{
			name: "no match",
			body: `<html><body>hello</body></html>`,
			blob: stateBlobs[0],
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractState(tt.body, tt.blob)
			if got != tt.want {
				t.Errorf("extractState() = %q, want %q", got, tt.want)
			}
		})
	}
}

func makeSSRCtx(state string) *httpmsg.HttpRequestResponse {
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	)
	body := `<script id="__NEXT_DATA__" type="application/json">` + state + `</script>`
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestScanPerRequest_PrivateTokenIsCandidate(t *testing.T) {
	m := New()
	results, err := m.ScanPerRequest(makeSSRCtx(`{"api_key":"sk_live_01` + `23456789ab` + `cdef"}`), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.NotContains(t, results[0].ExtractedResults[0], "sk_live_01" + "23456789ab" + "cdef")
}

func TestScanPerRequest_RoutineClientStateIsObservation(t *testing.T) {
	m := New()
	state := `{"isAdmin":true,"email":"user@example.test","aws_key":"AKIAIOSFODNN7EXAMPLE"}`
	results, err := m.ScanPerRequest(makeSSRCtx(state), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}
