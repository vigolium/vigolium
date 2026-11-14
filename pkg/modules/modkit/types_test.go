package modkit

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestInsertionPointTypeSet_HighNumberedTypes is a regression guard for the
// uint32-overflow bug: insertion-point type values >= 32 (header, URL path
// segments, parameter names, entire body) must be storable in and matchable by
// the set. With a uint32 backing mask, `1 << t` for t >= 32 truncated to 0, so
// those types were silently dropped — per-insertion-point modules never fuzzed
// headers or URL path segments even when they declared those types.
func TestInsertionPointTypeSet_HighNumberedTypes(t *testing.T) {
	highTypes := []httpmsg.InsertionPointType{
		httpmsg.INS_HEADER,            // 32
		httpmsg.INS_URL_PATH_FOLDER,   // 33
		httpmsg.INS_PARAM_NAME_URL,    // 34
		httpmsg.INS_PARAM_NAME_BODY,   // 35
		httpmsg.INS_ENTIRE_BODY,       // 36
		httpmsg.INS_URL_PATH_FILENAME, // 37
	}
	for _, ty := range highTypes {
		if got := NewInsertionPointTypeSet(ty); !got.Contains(ty) {
			t.Errorf("NewInsertionPointTypeSet(%d) does not Contain %d", ty, ty)
		}
		// The opt-in extras (names, entire body) are representable but not in
		// AllInsertionPointTypes.
		inAll := (AllInsertionPointTypes | ExtraInsertionPointTypes).Contains(ty)
		if !inAll {
			t.Errorf("AllInsertionPointTypes|ExtraInsertionPointTypes does not Contain type %d", ty)
		}
	}
	for _, ty := range []httpmsg.InsertionPointType{httpmsg.INS_PARAM_NAME_URL, httpmsg.INS_PARAM_NAME_BODY, httpmsg.INS_ENTIRE_BODY} {
		if AllInsertionPointTypes.Contains(ty) || URLParamTypes.Contains(ty) || BodyParamTypes.Contains(ty) {
			t.Errorf("opt-in type %d must not be in the default presets", ty)
		}
	}
	if !ParamNameTypes.Contains(httpmsg.INS_PARAM_NAME_URL) || !EntireBodyTypes.Contains(httpmsg.INS_ENTIRE_BODY) {
		t.Error("opt-in presets must contain their types")
	}

	// Presets must actually contain the types they declare.
	if !HeaderTypes.Contains(httpmsg.INS_HEADER) {
		t.Error("HeaderTypes must contain INS_HEADER")
	}
	if !URLParamTypes.Contains(httpmsg.INS_URL_PATH_FOLDER) {
		t.Error("URLParamTypes must contain INS_URL_PATH_FOLDER")
	}
	if !URLParamTypes.Contains(httpmsg.INS_URL_PATH_FILENAME) {
		t.Error("URLParamTypes must contain INS_URL_PATH_FILENAME")
	}
	if !AllParamTypes.Contains(httpmsg.INS_HEADER) {
		t.Error("AllParamTypes must contain INS_HEADER (it includes HeaderTypes)")
	}

	// Low-numbered types still work, and a type that wasn't added is absent.
	urlOnly := NewInsertionPointTypeSet(httpmsg.INS_PARAM_URL)
	if !urlOnly.Contains(httpmsg.INS_PARAM_URL) {
		t.Error("set must contain the low-numbered type it was built from")
	}
	if urlOnly.Contains(httpmsg.INS_HEADER) {
		t.Error("set must not contain a type that was never added")
	}

	// Non-fuzzable marker types (>= 64) are intentionally unrepresentable and
	// must not be reported as present in the all-types set.
	if AllInsertionPointTypes.Contains(httpmsg.INS_USER_PROVIDED) {
		t.Error("marker type INS_USER_PROVIDED (64) should not be representable")
	}
}
