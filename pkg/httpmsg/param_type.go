package httpmsg

// JSONValueType represents the original JSON value type for ParamJSON parameters.
// Used for type-aware payload injection to ensure valid JSON output.
type JSONValueType int

const (
	JSONTypeUnknown JSONValueType = iota
	JSONTypeString
	JSONTypeNumber
	JSONTypeBool
	JSONTypeNull
)

// ParamType represents the source location of an HTTP parameter during parsing.
// This is used for parameter EXTRACTION (where the parameter came from).
// For payload INJECTION points, use InsertionPointType instead.
//
// Key difference:
//   - ParamType: describes WHERE a parameter was parsed FROM (URL query, body, cookie, etc.)
//   - InsertionPointType: describes HOW to inject a payload (encoding, position, etc.)
type ParamType uint8

const (
	ParamURL           ParamType = 0   // URL query parameter value
	ParamBody          ParamType = 1   // URL-encoded body parameter
	ParamCookie        ParamType = 2   // Cookie value
	ParamXML           ParamType = 3   // XML element content
	ParamXMLAttr       ParamType = 4   // XML attribute value
	ParamMultipartAttr ParamType = 5   // Multipart form field attribute (e.g., filename)
	ParamJSON          ParamType = 6   // JSON value
	ParamPathFolder    ParamType = 7   // REST path folder segment
	ParamBodyMultipart ParamType = 8   // Multipart form field value
	ParamPathFilename  ParamType = 9   // REST path filename segment
	ParamNone          ParamType = 255 // No parameter / placeholder
)

// String returns a human-readable name for the parameter type.
func (pt ParamType) String() string {
	switch pt {
	case ParamURL:
		return "URL_PARAM"
	case ParamBody:
		return "BODY_PARAM"
	case ParamCookie:
		return "COOKIE"
	case ParamXML:
		return "XML_PARAM"
	case ParamXMLAttr:
		return "XML_ATTR"
	case ParamMultipartAttr:
		return "MULTIPART_ATTR"
	case ParamJSON:
		return "JSON_PARAM"
	case ParamPathFolder:
		return "PATH_FOLDER"
	case ParamBodyMultipart:
		return "BODY_MULTIPART"
	case ParamPathFilename:
		return "PATH_FILENAME"
	case ParamNone:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// paramTypeInfo holds metadata about each parameter type.
type paramTypeInfo struct {
	canURLEncode   bool
	isPathParam    bool
	requiresUpdate bool
}

// paramTypeInfoMap maps ParamType to its metadata.
var paramTypeInfoMap = map[ParamType]paramTypeInfo{
	ParamNone:          {canURLEncode: false, isPathParam: false, requiresUpdate: false},
	ParamURL:           {canURLEncode: true, isPathParam: true, requiresUpdate: false},
	ParamBody:          {canURLEncode: true, isPathParam: false, requiresUpdate: true},
	ParamCookie:        {canURLEncode: true, isPathParam: false, requiresUpdate: false},
	ParamXML:           {canURLEncode: false, isPathParam: false, requiresUpdate: true},
	ParamXMLAttr:       {canURLEncode: false, isPathParam: false, requiresUpdate: true},
	ParamMultipartAttr: {canURLEncode: false, isPathParam: false, requiresUpdate: true},
	ParamJSON:          {canURLEncode: false, isPathParam: false, requiresUpdate: true},
	ParamBodyMultipart: {canURLEncode: false, isPathParam: false, requiresUpdate: true},
	ParamPathFolder:    {canURLEncode: true, isPathParam: true, requiresUpdate: false},
	ParamPathFilename:  {canURLEncode: true, isPathParam: true, requiresUpdate: false},
}

// CanURLEncode returns whether this parameter type supports URL encoding.
func (pt ParamType) CanURLEncode() bool {
	if info, ok := paramTypeInfoMap[pt]; ok {
		return info.canURLEncode
	}
	return false
}

// IsPathParam returns whether this parameter is a REST-style path parameter.
func (pt ParamType) IsPathParam() bool {
	if info, ok := paramTypeInfoMap[pt]; ok {
		return info.isPathParam
	}
	return false
}

// RequiresContentLengthUpdate returns whether modifying this parameter requires
// updating the Content-Length header.
func (pt ParamType) RequiresContentLengthUpdate() bool {
	if info, ok := paramTypeInfoMap[pt]; ok {
		return info.requiresUpdate
	}
	return false
}

// ToInsertionPointType converts ParamType to the corresponding InsertionPointType.
// This centralized mapping function handles the translation between the two type systems.
func (pt ParamType) ToInsertionPointType() InsertionPointType {
	switch pt {
	case ParamURL:
		return INS_PARAM_URL
	case ParamBody:
		return INS_PARAM_BODY
	case ParamCookie:
		return INS_PARAM_COOKIE
	case ParamXML:
		return INS_PARAM_XML
	case ParamXMLAttr:
		return INS_PARAM_XML_ATTR
	case ParamMultipartAttr:
		return INS_PARAM_MULTIPART_ATTR
	case ParamJSON:
		return INS_PARAM_JSON
	case ParamPathFolder:
		return INS_URL_PATH_FOLDER
	case ParamBodyMultipart:
		return INS_PARAM_BODY
	case ParamPathFilename:
		return INS_URL_PATH_FILENAME
	default:
		return INS_UNKNOWN
	}
}

// InsertionPointTypeToParamType converts InsertionPointType back to ParamType.
// Note: This is a lossy conversion since multiple ParamTypes can map to the same InsertionPointType.
func InsertionPointTypeToParamType(ipt InsertionPointType) ParamType {
	switch ipt {
	case INS_PARAM_URL:
		return ParamURL
	case INS_PARAM_BODY:
		return ParamBody
	case INS_PARAM_COOKIE:
		return ParamCookie
	case INS_PARAM_XML:
		return ParamXML
	case INS_PARAM_XML_ATTR:
		return ParamXMLAttr
	case INS_PARAM_MULTIPART_ATTR:
		return ParamMultipartAttr
	case INS_PARAM_JSON:
		return ParamJSON
	case INS_URL_PATH_FOLDER:
		return ParamPathFolder
	case INS_URL_PATH_FILENAME:
		return ParamPathFilename
	default:
		return ParamNone
	}
}
