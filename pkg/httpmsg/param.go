package httpmsg

// Param represents an HTTP parameter with its location information in the request.
// Uses unexported fields with getter methods to ensure immutability after creation.
//
// Design rationale:
//   - Unexported fields prevent direct mutation
//   - Getter methods provide read-only access
//   - Constructor functions control valid creation
//   - Position tracking enables precise payload injection
type Param struct {
	ptype      ParamType     // Parameter type (URL, body, cookie, etc.)
	name       string        // Parameter name
	value      string        // Parameter value (decoded)
	nameStart  int           // Byte offset where name starts in request
	nameEnd    int           // Byte offset where name ends in request
	valueStart int           // Byte offset where value starts in request
	valueEnd   int           // Byte offset where value ends in request
	metadata   string        // Additional metadata (e.g., JSON path, multipart headers)
	jsonType   JSONValueType // Original JSON value type for ParamJSON parameters
}

// ============== Getter Methods ==============

// Type returns the parameter type.
func (p *Param) Type() ParamType {
	return p.ptype
}

// Name returns the parameter name.
func (p *Param) Name() string {
	return p.name
}

// Value returns the parameter value.
func (p *Param) Value() string {
	return p.value
}

// NameStart returns the byte offset where the name starts in the request.
func (p *Param) NameStart() int {
	return p.nameStart
}

// NameEnd returns the byte offset where the name ends in the request.
func (p *Param) NameEnd() int {
	return p.nameEnd
}

// ValueStart returns the byte offset where the value starts in the request.
func (p *Param) ValueStart() int {
	return p.valueStart
}

// ValueEnd returns the byte offset where the value ends in the request.
func (p *Param) ValueEnd() int {
	return p.valueEnd
}

// Metadata returns additional metadata (e.g., JSON path for JSON params).
func (p *Param) Metadata() string {
	return p.metadata
}

// JSONType returns the original JSON value type for JSON parameters.
func (p *Param) JSONType() JSONValueType {
	return p.jsonType
}

// ============== Computed Methods ==============

// HasOffsets returns whether this parameter has valid byte offsets.
// Some parameters (like path segments) may not have name offsets.
func (p *Param) HasOffsets() bool {
	return p.valueStart > 0 || p.valueEnd > 0
}

// HasNameOffsets returns whether this parameter has valid name offsets.
func (p *Param) HasNameOffsets() bool {
	return p.nameStart >= 0 && p.nameEnd > p.nameStart
}

// IsPathParameter returns whether this parameter is a REST-style path parameter.
func (p *Param) IsPathParameter() bool {
	return p.ptype.IsPathParam()
}

// RequiresContentLengthUpdate returns whether modifying this parameter requires
// updating the Content-Length header.
func (p *Param) RequiresContentLengthUpdate() bool {
	return p.ptype.RequiresContentLengthUpdate()
}

// CanURLEncode returns whether this parameter type supports URL encoding.
func (p *Param) CanURLEncode() bool {
	return p.ptype.CanURLEncode()
}

// ToInsertionPointType returns the corresponding InsertionPointType for scanning.
func (p *Param) ToInsertionPointType() InsertionPointType {
	return p.ptype.ToInsertionPointType()
}

// ============== Constructors - Public API ==============

// NewParam creates a new Param with basic fields.
// Use this for simple parameter creation without byte offsets.
func NewParam(ptype ParamType, name, value string) *Param {
	return &Param{
		ptype:     ptype,
		name:      name,
		value:     value,
		nameStart: -1,
		nameEnd:   -1,
	}
}

// NewURLParam creates a new URL query parameter.
func NewURLParam(name, value string) *Param {
	return NewParam(ParamURL, name, value)
}

// NewBodyParam creates a new URL-encoded body parameter.
func NewBodyParam(name, value string) *Param {
	return NewParam(ParamBody, name, value)
}

// NewCookieParam creates a new cookie parameter.
func NewCookieParam(name, value string) *Param {
	return NewParam(ParamCookie, name, value)
}

// NewJSONParam creates a new JSON parameter.
func NewJSONParam(name, value string) *Param {
	return NewParam(ParamJSON, name, value)
}

// NewXMLParam creates a new XML element parameter.
func NewXMLParam(name, value string) *Param {
	return NewParam(ParamXML, name, value)
}

// NewPathFolderParam creates a new REST path folder parameter.
func NewPathFolderParam(name, value string) *Param {
	return NewParam(ParamPathFolder, name, value)
}

// NewPathFilenameParam creates a new REST path filename parameter.
func NewPathFilenameParam(name, value string) *Param {
	return NewParam(ParamPathFilename, name, value)
}

// ============== Constructors - Internal API (for parsers) ==============

// NewParsedParam creates a Param with all fields including byte offsets.
// This is the internal constructor used by parsers that track positions.
func NewParsedParam(ptype ParamType, name, value string, nameStart, nameEnd, valueStart, valueEnd int) *Param {
	return &Param{
		ptype:      ptype,
		name:       name,
		value:      value,
		nameStart:  nameStart,
		nameEnd:    nameEnd,
		valueStart: valueStart,
		valueEnd:   valueEnd,
	}
}

// NewParsedParamWithMetadata creates a Param with all fields including metadata.
// Used by parsers that need to store additional context (e.g., JSON path).
func NewParsedParamWithMetadata(ptype ParamType, name, value string, nameStart, nameEnd, valueStart, valueEnd int, metadata string) *Param {
	return &Param{
		ptype:      ptype,
		name:       name,
		value:      value,
		nameStart:  nameStart,
		nameEnd:    nameEnd,
		valueStart: valueStart,
		valueEnd:   valueEnd,
		metadata:   metadata,
	}
}

// NewJSONParsedParam creates a JSON parameter with type information.
// Used by the JSON parser to preserve original value type for correct encoding.
func NewJSONParsedParam(name, value string, nameStart, nameEnd, valueStart, valueEnd int, metadata string, jsonType JSONValueType) *Param {
	return &Param{
		ptype:      ParamJSON,
		name:       name,
		value:      value,
		nameStart:  nameStart,
		nameEnd:    nameEnd,
		valueStart: valueStart,
		valueEnd:   valueEnd,
		metadata:   metadata,
		jsonType:   jsonType,
	}
}

// ============== Builder Pattern (for mutations) ==============

// WithValue returns a new Param with the value changed.
// The original Param is not modified.
func (p *Param) WithValue(value string) *Param {
	return &Param{
		ptype:      p.ptype,
		name:       p.name,
		value:      value,
		nameStart:  p.nameStart,
		nameEnd:    p.nameEnd,
		valueStart: p.valueStart,
		valueEnd:   p.valueEnd,
		metadata:   p.metadata,
		jsonType:   p.jsonType,
	}
}

// WithJSONType returns a new Param with the JSON type set.
// The original Param is not modified.
func (p *Param) WithJSONType(jsonType JSONValueType) *Param {
	return &Param{
		ptype:      p.ptype,
		name:       p.name,
		value:      p.value,
		nameStart:  p.nameStart,
		nameEnd:    p.nameEnd,
		valueStart: p.valueStart,
		valueEnd:   p.valueEnd,
		metadata:   p.metadata,
		jsonType:   jsonType,
	}
}

// WithOffsets returns a new Param with adjusted offsets.
// Useful when embedding a parameter in a larger context.
func (p *Param) WithOffsets(nameStart, nameEnd, valueStart, valueEnd int) *Param {
	return &Param{
		ptype:      p.ptype,
		name:       p.name,
		value:      p.value,
		nameStart:  nameStart,
		nameEnd:    nameEnd,
		valueStart: valueStart,
		valueEnd:   valueEnd,
		metadata:   p.metadata,
		jsonType:   p.jsonType,
	}
}

// WithAdjustedOffsets returns a new Param with all offsets adjusted by delta.
// Useful when the parameter is part of a larger request and needs repositioning.
func (p *Param) WithAdjustedOffsets(delta int) *Param {
	return &Param{
		ptype:      p.ptype,
		name:       p.name,
		value:      p.value,
		nameStart:  p.nameStart + delta,
		nameEnd:    p.nameEnd + delta,
		valueStart: p.valueStart + delta,
		valueEnd:   p.valueEnd + delta,
		metadata:   p.metadata,
		jsonType:   p.jsonType,
	}
}

// WithMetadata returns a new Param with the metadata changed.
func (p *Param) WithMetadata(metadata string) *Param {
	return &Param{
		ptype:      p.ptype,
		name:       p.name,
		value:      p.value,
		nameStart:  p.nameStart,
		nameEnd:    p.nameEnd,
		valueStart: p.valueStart,
		valueEnd:   p.valueEnd,
		metadata:   metadata,
		jsonType:   p.jsonType,
	}
}
