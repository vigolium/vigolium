package anomaly

// AttributeSet stores extracted attribute values from an HTTP response.
// This is the core data structure used for anomaly detection.
// Memory efficient: Only stores non-zero values using a map.
type AttributeSet struct {
	values map[Type]uint32
}

// NewAttributeSet creates a new empty AttributeSet.
func NewAttributeSet() *AttributeSet {
	return &AttributeSet{
		values: make(map[Type]uint32),
	}
}

// Set stores a value for a specific attribute type.
func (as *AttributeSet) Set(attrType Type, value uint32) {
	if value != 0 {
		as.values[attrType] = value
	}
}

// Get retrieves the value for a specific attribute type.
// Returns the value and true if it exists, or 0 and false if not set.
func (as *AttributeSet) Get(attrType Type) (uint32, bool) {
	value, ok := as.values[attrType]
	return value, ok && value != 0
}

// GetAll returns all attribute values indexed by type.
// Only includes non-zero values.
func (as *AttributeSet) GetAll() map[Type]uint32 {
	result := make(map[Type]uint32, len(as.values))
	for k, v := range as.values {
		if v != 0 {
			result[k] = v
		}
	}
	return result
}

// ResponseRecord represents a response with its attributes, user metadata, and anomaly score.
// This is the main data structure users work with.
type ResponseRecord struct {
	Attributes AttributeSet
	Metadata   interface{} // User-defined metadata: index, URL, RequestID, custom struct, etc.
	Score      int         // Anomaly score (filled by Engine.Rank)
}

// NewResponseRecord creates a new ResponseRecord.
func NewResponseRecord(attrs AttributeSet, metadata interface{}) *ResponseRecord {
	return &ResponseRecord{
		Attributes: attrs,
		Metadata:   metadata,
		Score:      0,
	}
}
