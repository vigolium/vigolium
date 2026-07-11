package insecure_deserialization

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// javaDeserErrorHandler simulates a backend that deserializes attacker input and
// leaks a Java ObjectInputStream stack trace — the error signature the module's
// error-based detection keys on.
func javaDeserErrorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if !strings.HasPrefix(r.FormValue("data"), "\xac\xed\x00\x05") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid value"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Exception in thread: java.io.ObjectInputStream.readObject failed: " +
			"java.io.InvalidClassException local class incompatible"))
	}
}

// TestScanPerInsertionPoint_DetectsDeserError drives the real scan method against
// a server that leaks a deserialization error on a body parameter.
func TestScanPerInsertionPoint_DetectsDeserError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(javaDeserErrorHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=eyJhIjoxfQ==")
	ip := modtest.InsertionPoint(t, rr, "data")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a deserialization finding when a Java ObjectInputStream error is leaked")
	assert.Equal(t, "data", res[0].FuzzingParameter)
	assert.Contains(t, res[0].Info.Description, "Java")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding(), "an exception does not prove gadget execution")
}

func TestGenericDeserializationErrorForEveryInputIsSuppressed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("java.io.ObjectInputStream.readObject failed: java.io.InvalidClassException"))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=x")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "data"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint returning the same deserialization error for a plain control has no payload-specific differential")
}

func TestTransientDeserializationErrorDoesNotConfirm(t *testing.T) {
	t.Parallel()
	var javaAttempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if strings.HasPrefix(r.FormValue("data"), "\xac\xed\x00\x05") && javaAttempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("java.io.ObjectInputStream.readObject failed: java.io.InvalidClassException"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid value"))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=x")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "data"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a one-off exception must fail the replay gate")
}

func TestPayloadsAreInertTypeProbes(t *testing.T) {
	for _, payload := range payloads {
		assert.NotContains(t, payload.payload, "os.system")
		assert.NotContains(t, payload.payload, "ObjectDataProvider")
		assert.NotContains(t, payload.payload, "AxHost+State")
		assert.NotContains(t, payload.payload, "DeprecatedInstanceVariableProxy")
	}
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never emits a
// deserialization error yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=eyJhIjoxfQ==")
	ip := modtest.InsertionPoint(t, rr, "data")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never leaks a deser error must not yield a finding")
}

// TestCheckDeserError exercises the pure error-matching helper, including the
// baseline-suppression branch and per-framework classification.
func TestCheckDeserError(t *testing.T) {
	t.Parallel()

	fw, ok := checkDeserError("java.io.ObjectInputStream.readObject", "", "")
	require.True(t, ok)
	assert.Equal(t, "Java", fw)

	fw, ok = checkDeserError(`PHP Fatal error in unserialize() at O:8:"stdClass"`, "", "")
	require.True(t, ok)
	assert.Equal(t, "PHP", fw)

	_, ok = checkDeserError("nothing interesting here", "", "")
	assert.False(t, ok, "benign body must not match")

	// Error already present in the baseline is suppressed.
	_, ok = checkDeserError("java.io.ObjectInputStream", "java.io.ObjectInputStream", "")
	assert.False(t, ok, "error present in baseline must be suppressed")
}

// TestCheckDeserError_ReflectedPayloadNotMatched pins the reflection false
// positive: the PHP probe `O:8:"stdClass":0:{}` is itself matched by the
// `O:\d+:"[^"]+"` framework pattern, so an endpoint that merely echoes the
// rejected payload back must NOT be reported as insecure deserialization. Passing
// the payload lets the helper strip the reflection before matching.
func TestCheckDeserError_ReflectedPayloadNotMatched(t *testing.T) {
	t.Parallel()
	phpPayload := `O:8:"stdClass":0:{}`

	// Pure reflection of the probe in an error/echo — no deserialization occurred.
	_, ok := checkDeserError(`invalid input: `+phpPayload+` is not accepted`, "", phpPayload)
	assert.False(t, ok, "a bare reflection of the injected PHP payload must not be flagged")

	// Reflection that also echoes a benign JSON body must likewise stay quiet.
	_, ok = checkDeserError(`{"error":"bad value","value":"`+phpPayload+`"}`, "", phpPayload)
	assert.False(t, ok, "reflecting the payload inside a JSON error body must not be flagged")

	// A GENUINE server-side error that happens to quote the payload amid a real
	// unserialize() signature still matches on the surviving keyword.
	fw, ok := checkDeserError(`PHP Warning: unserialize(): Error at offset 0 of `+phpPayload, "", phpPayload)
	require.True(t, ok, "a real unserialize() error must still be detected even when it quotes the payload")
	assert.Equal(t, "PHP", fw)
}

// TestCheckDeserError_LargeBenignBodyNoSpanFP pins the loosely-anchored-span false
// positive class (the sibling of the Oracle.*?Driver FP): two anchor words of a
// two-anchor signature occurring far apart in a large benign single-line body —
// e.g. a minified SPA shell — must NOT be matched as a spanning "error". A genuine
// compact signature in the same page still matches.
func TestCheckDeserError_LargeBenignBodyNoSpanFP(t *testing.T) {
	t.Parallel()

	// "ClassCastException" and "deserializ" 60KB apart in unrelated content: the old
	// unbounded ".*deserializ" would bridge them; the bounded pattern + span guard
	// must not.
	spanBody := `java.lang.ClassCastException occurred while rendering; ` +
		strings.Repeat(`this is ordinary page content that mentions neither anchor. `, 1200) +
		` deserializ-ation settings panel`
	_, ok := checkDeserError(spanBody, "", "")
	assert.False(t, ok, "two anchors far apart in a large benign body must not match")

	// A genuine, compact Java deserialization error still matches.
	fw, ok := checkDeserError(
		`java.lang.ClassCastException: cannot be cast during deserialization of payload`, "", "")
	require.True(t, ok, "a compact ClassCastException deserialization error must still match")
	assert.Equal(t, "Java", fw)

	// Spring FQCN filler must stay within the class-name character set: a
	// "org.springframework." token and a distant "SerializationException" word
	// separated by JSON/HTML must not bridge.
	springSpan := `"org.springframework.boot":true,` +
		strings.Repeat(`"feature.someFlagEnabled":false,`, 400) +
		`"label":"SerializationException docs"`
	_, ok = checkDeserError(springSpan, "", "")
	assert.False(t, ok, "spring FQCN and a distant SerializationException word must not bridge")
}

// TestScanPerInsertionPoint_ReflectedPayloadNoFinding drives the full scan against
// a server that reflects the rejected serialized payload verbatim in a 400 error
// (the struts-class reflection FP): the PHP probe's own `O:N:"..."` shape would
// self-match the detector, but stripping the reflection keeps it quiet.
func TestScanPerInsertionPoint_ReflectedPayloadNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.WriteHeader(http.StatusBadRequest)
		// Echo whatever value was posted, exactly like a validation error page.
		_, _ = w.Write([]byte("Bad Request: could not process value " + r.FormValue("data")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/load", "data=x")
	ip := modtest.InsertionPoint(t, rr, "data")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a validation error that reflects the injected serialized payload must not be flagged")
}
