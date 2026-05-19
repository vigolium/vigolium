package httpmsg

// param_descriptor.go - Parameter descriptor for scanner configuration

// ParameterDescriptor represents a parameter descriptor with name and type information.
// Used for parameter filtering in scanner configuration.
type ParameterDescriptor struct {
	name   string
	ipType InsertionPointType
}

// NewParameterDescriptor creates a new parameter descriptor.
//
// Parameters:
//   - ipType: Insertion point type
//   - name: Parameter name
//
// Returns:
//   - New ParameterDescriptor instance
func NewParameterDescriptor(ipType InsertionPointType, name string) *ParameterDescriptor {
	return &ParameterDescriptor{
		name:   name,
		ipType: ipType,
	}
}

// Name returns the parameter name.
func (pd *ParameterDescriptor) Name() string {
	return pd.name
}

// Type returns the insertion point type.
func (pd *ParameterDescriptor) Type() InsertionPointType {
	return pd.ipType
}
