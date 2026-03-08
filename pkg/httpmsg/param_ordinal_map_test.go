package httpmsg

import "testing"

// TestParamTypeToIPType tests conversion from ParamType to InsertionPointType
func TestParamTypeToIPType(t *testing.T) {
	tests := []struct {
		name       string
		paramType  ParamType
		wantIPType InsertionPointType
	}{
		{
			name:       "URL param",
			paramType:  ParamURL,
			wantIPType: INS_PARAM_URL,
		},
		{
			name:       "Body param",
			paramType:  ParamBody,
			wantIPType: INS_PARAM_BODY,
		},
		{
			name:       "Cookie param",
			paramType:  ParamCookie,
			wantIPType: INS_PARAM_COOKIE,
		},
		{
			name:       "JSON param",
			paramType:  ParamJSON,
			wantIPType: INS_PARAM_JSON,
		},
		{
			name:       "XML param",
			paramType:  ParamXML,
			wantIPType: INS_PARAM_XML,
		},
		{
			name:       "XML attr param",
			paramType:  ParamXMLAttr,
			wantIPType: INS_PARAM_XML_ATTR,
		},
		{
			name:       "Multipart attr param",
			paramType:  ParamMultipartAttr,
			wantIPType: INS_PARAM_MULTIPART_ATTR,
		},
		{
			name:       "Body multipart param",
			paramType:  ParamBodyMultipart,
			wantIPType: INS_PARAM_BODY,
		},
		{
			name:       "Path folder param",
			paramType:  ParamPathFolder,
			wantIPType: INS_URL_PATH_FOLDER,
		},
		{
			name:       "Path filename param",
			paramType:  ParamPathFilename,
			wantIPType: INS_URL_PATH_FILENAME,
		},
		{
			name:       "None param",
			paramType:  ParamNone,
			wantIPType: INS_UNKNOWN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIPType := tt.paramType.ToInsertionPointType()
			if gotIPType != tt.wantIPType {
				t.Errorf("ParamType.ToInsertionPointType(%v) = %v, want %v",
					tt.paramType, gotIPType, tt.wantIPType)
			}
		})
	}
}

// TestInsertionPointTypeToParamType tests reverse conversion
func TestInsertionPointTypeToParamType(t *testing.T) {
	tests := []struct {
		name          string
		ipType        InsertionPointType
		wantParamType ParamType
	}{
		{
			name:          "URL insertion point",
			ipType:        INS_PARAM_URL,
			wantParamType: ParamURL,
		},
		{
			name:          "Body insertion point",
			ipType:        INS_PARAM_BODY,
			wantParamType: ParamBody,
		},
		{
			name:          "Cookie insertion point",
			ipType:        INS_PARAM_COOKIE,
			wantParamType: ParamCookie,
		},
		{
			name:          "JSON insertion point",
			ipType:        INS_PARAM_JSON,
			wantParamType: ParamJSON,
		},
		{
			name:          "XML insertion point",
			ipType:        INS_PARAM_XML,
			wantParamType: ParamXML,
		},
		{
			name:          "Header insertion point (no param type)",
			ipType:        INS_HEADER,
			wantParamType: ParamNone,
		},
		{
			name:          "Entire body insertion point (no param type)",
			ipType:        INS_ENTIRE_BODY,
			wantParamType: ParamNone,
		},
		{
			name:          "Unknown insertion point",
			ipType:        INS_UNKNOWN,
			wantParamType: ParamNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotParamType := InsertionPointTypeToParamType(tt.ipType)
			if gotParamType != tt.wantParamType {
				t.Errorf("InsertionPointTypeToParamType(%v) = %v, want %v",
					tt.ipType, gotParamType, tt.wantParamType)
			}
		})
	}
}

// TestParameterInsertionPointRoundTrip tests round-trip conversions
func TestParameterInsertionPointRoundTrip(t *testing.T) {
	paramTypes := []ParamType{
		ParamURL,
		ParamBody,
		ParamCookie,
		ParamXML,
		ParamXMLAttr,
		ParamMultipartAttr,
		ParamJSON,
		ParamPathFolder,
		ParamPathFilename,
	}

	for _, paramType := range paramTypes {
		t.Run(paramType.String(), func(t *testing.T) {
			// Convert paramType -> ipType -> paramType
			ipType := paramType.ToInsertionPointType()
			roundTrip := InsertionPointTypeToParamType(ipType)

			// They should match for types that have direct mapping
			if roundTrip != paramType {
				t.Errorf("Round trip mismatch: %v -> %v -> %v",
					paramType, ipType, roundTrip)
			}
		})
	}
}

// TestAllParamTypesHaveMapping verifies all parameter types can be mapped
func TestAllParamTypesHaveMapping(t *testing.T) {
	allParamTypes := []ParamType{
		ParamNone,
		ParamURL,
		ParamBody,
		ParamCookie,
		ParamXML,
		ParamXMLAttr,
		ParamMultipartAttr,
		ParamPathFolder,
		ParamJSON,
		ParamBodyMultipart,
		ParamPathFilename,
	}

	for _, paramType := range allParamTypes {
		t.Run(paramType.String(), func(t *testing.T) {
			// Just verify it doesn't panic
			ipType := paramType.ToInsertionPointType()

			// ParamNone should map to INS_UNKNOWN
			if paramType == ParamNone && ipType != INS_UNKNOWN {
				t.Errorf("ParamNone should map to INS_UNKNOWN, got %v", ipType)
			}
		})
	}
}
