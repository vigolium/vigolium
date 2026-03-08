package httpmsg

import "testing"

// TestNewParameterDescriptor tests parameter descriptor creation
func TestNewParameterDescriptor(t *testing.T) {
	tests := []struct {
		name      string
		ipType    InsertionPointType
		paramName string
	}{
		{
			name:      "URL parameter descriptor",
			ipType:    INS_PARAM_URL,
			paramName: "id",
		},
		{
			name:      "JSON parameter descriptor",
			ipType:    INS_PARAM_JSON,
			paramName: "user.name",
		},
		{
			name:      "Cookie parameter descriptor",
			ipType:    INS_PARAM_COOKIE,
			paramName: "session",
		},
		{
			name:      "Header parameter descriptor",
			ipType:    INS_HEADER,
			paramName: "Authorization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := NewParameterDescriptor(tt.ipType, tt.paramName)

			if pd == nil {
				t.Fatal("NewParameterDescriptor returned nil")
			}

			// Test Name() method
			gotName := pd.Name()
			if gotName != tt.paramName {
				t.Errorf("Name() = %v, want %v", gotName, tt.paramName)
			}

			// Test Type() method
			gotType := pd.Type()
			if gotType != tt.ipType {
				t.Errorf("Type() = %v, want %v", gotType, tt.ipType)
			}
		})
	}
}

// TestParameterDescriptorFields tests direct field access
func TestParameterDescriptorFields(t *testing.T) {
	ipType := INS_PARAM_JSON
	paramName := "data.value"

	pd := NewParameterDescriptor(ipType, paramName)

	// Verify internal fields are set correctly
	if pd.name != paramName {
		t.Errorf("internal name field = %v, want %v", pd.name, paramName)
	}

	if pd.ipType != ipType {
		t.Errorf("internal ipType field = %v, want %v", pd.ipType, ipType)
	}
}

// TestParameterDescriptorList tests creating a list of descriptors
func TestParameterDescriptorList(t *testing.T) {
	descriptors := []ParameterDescriptor{
		*NewParameterDescriptor(INS_PARAM_URL, "id"),
		*NewParameterDescriptor(INS_PARAM_URL, "name"),
		*NewParameterDescriptor(INS_PARAM_COOKIE, "session"),
		*NewParameterDescriptor(INS_HEADER, "User-Agent"),
	}

	if len(descriptors) != 4 {
		t.Fatalf("Expected 4 descriptors, got %v", len(descriptors))
	}

	// Verify first descriptor
	if descriptors[0].Name() != "id" {
		t.Errorf("descriptors[0].Name() = %v, want 'id'", descriptors[0].Name())
	}
	if descriptors[0].Type() != INS_PARAM_URL {
		t.Errorf("descriptors[0].Type() = %v, want INS_PARAM_URL", descriptors[0].Type())
	}

	// Verify last descriptor
	if descriptors[3].Name() != "User-Agent" {
		t.Errorf("descriptors[3].Name() = %v, want 'User-Agent'", descriptors[3].Name())
	}
	if descriptors[3].Type() != INS_HEADER {
		t.Errorf("descriptors[3].Type() = %v, want INS_HEADER", descriptors[3].Type())
	}
}

// TestParameterDescriptorWithAllIPTypes tests descriptors with various insertion point types
func TestParameterDescriptorWithAllIPTypes(t *testing.T) {
	ipTypes := []InsertionPointType{
		INS_PARAM_URL,
		INS_PARAM_BODY,
		INS_PARAM_COOKIE,
		INS_PARAM_XML,
		INS_PARAM_XML_ATTR,
		INS_PARAM_MULTIPART_ATTR,
		INS_PARAM_JSON,
		INS_HEADER,
		INS_URL_PATH_FOLDER,
		INS_URL_PATH_FILENAME,
		INS_ENTIRE_BODY,
	}

	for _, ipType := range ipTypes {
		t.Run(ipType.String(), func(t *testing.T) {
			paramName := "test_param"
			pd := NewParameterDescriptor(ipType, paramName)

			if pd.Type() != ipType {
				t.Errorf("Type() = %v, want %v", pd.Type(), ipType)
			}

			if pd.Name() != paramName {
				t.Errorf("Name() = %v, want %v", pd.Name(), paramName)
			}
		})
	}
}

// TestParameterDescriptorEmptyName tests descriptor with empty name
func TestParameterDescriptorEmptyName(t *testing.T) {
	pd := NewParameterDescriptor(INS_PARAM_URL, "")

	if pd.Name() != "" {
		t.Errorf("Name() = %v, want empty string", pd.Name())
	}
}

// TestParameterDescriptorPointerBehavior tests pointer vs value behavior
func TestParameterDescriptorPointerBehavior(t *testing.T) {
	// Create as pointer
	pdPtr := NewParameterDescriptor(INS_PARAM_URL, "id")

	// Access methods on pointer
	if pdPtr.Name() != "id" {
		t.Errorf("Pointer: Name() = %v, want 'id'", pdPtr.Name())
	}
	if pdPtr.Type() != INS_PARAM_URL {
		t.Errorf("Pointer: Type() = %v, want INS_PARAM_URL", pdPtr.Type())
	}

	// Create as value (dereferenced)
	pdVal := *NewParameterDescriptor(INS_PARAM_COOKIE, "session")

	// Access methods on value
	if pdVal.Name() != "session" {
		t.Errorf("Value: Name() = %v, want 'session'", pdVal.Name())
	}
	if pdVal.Type() != INS_PARAM_COOKIE {
		t.Errorf("Value: Type() = %v, want INS_PARAM_COOKIE", pdVal.Type())
	}
}
