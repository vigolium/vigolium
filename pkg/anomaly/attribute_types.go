package anomaly

type Type int

const (
	UNDEFINED Type = iota
	STATUS_CODE
	LINE_COUNT
	WORD_COUNT
	WHOLE_BODY_CONTENT
	LIMITED_BODY_CONTENT
	INITIAL_BODY_CONTENT
	CONTENT_TYPE
	CONTENT_LENGTH
	CONTENT_LOCATION
	ETAG_HEADER
	SERVER_HEADER
	STATUS_CODE_TEXT
	LAST_MODIFIED_HEADER
	LOCATION
	SET_COOKIE_NAMES
	PAGE_TITLE
	COMMENTS
	CSS_CLASSES
	CANONICAL_LINK
	FIRST_HEADER_TAG
	HEADER_TAGS
	DIV_IDS
	TAG_IDS
	TAG_NAMES
	VISIBLE_TEXT
	VISIBLE_WORD_COUNT
	OUTBOUND_EDGE_TAG_NAMES
	OUTBOUND_EDGE_COUNT
	ANCHOR_LABELS
	INPUT_IMAGE_LABELS
	INPUT_SUBMIT_LABELS
	BUTTON_SUBMIT_LABELS
	NON_HIDDEN_FORM_INPUT_TYPES
)

func FromString(s string) Type {
	switch s {
	case "undefined":
		return UNDEFINED
	case "status_code":
		return STATUS_CODE
	case "line_count":
		return LINE_COUNT
	case "word_count":
		return WORD_COUNT
	case "whole_body_content":
		return WHOLE_BODY_CONTENT
	case "limited_body_content":
		return LIMITED_BODY_CONTENT
	case "initial_body_content":
		return INITIAL_BODY_CONTENT
	case "content_type":
		return CONTENT_TYPE
	case "content_length":
		return CONTENT_LENGTH
	case "content_location":
		return CONTENT_LOCATION
	case "etag_header":
		return ETAG_HEADER
	case "server_header":
		return SERVER_HEADER
	case "status_code_text":
		return STATUS_CODE_TEXT
	case "last_modified_header":
		return LAST_MODIFIED_HEADER
	case "location":
		return LOCATION
	case "set_cookie_names":
		return SET_COOKIE_NAMES
	case "page_title":
		return PAGE_TITLE
	case "comments":
		return COMMENTS
	case "css_classes":
		return CSS_CLASSES
	case "canonical_link":
		return CANONICAL_LINK
	case "first_header_tag":
		return FIRST_HEADER_TAG
	case "header_tags":
		return HEADER_TAGS
	case "div_ids":
		return DIV_IDS
	case "tag_ids":
		return TAG_IDS
	case "tag_names":
		return TAG_NAMES
	case "visible_text":
		return VISIBLE_TEXT
	case "visible_word_count":
		return VISIBLE_WORD_COUNT
	case "outbound_edge_tag_names":
		return OUTBOUND_EDGE_TAG_NAMES
	case "outbound_edge_count":
		return OUTBOUND_EDGE_COUNT
	case "anchor_labels":
		return ANCHOR_LABELS
	case "input_image_labels":
		return INPUT_IMAGE_LABELS
	case "input_submit_labels":
		return INPUT_SUBMIT_LABELS
	case "button_submit_labels":
		return BUTTON_SUBMIT_LABELS
	case "non_hidden_form_input_types":
		return NON_HIDDEN_FORM_INPUT_TYPES
	default:
		return UNDEFINED
	}
}

func (f Type) String() string {
	switch f {
	case UNDEFINED:
		return "undefined"
	case STATUS_CODE:
		return "status_code"
	case LINE_COUNT:
		return "line_count"
	case WORD_COUNT:
		return "word_count"
	case WHOLE_BODY_CONTENT:
		return "whole_body_content"
	case LIMITED_BODY_CONTENT:
		return "limited_body_content"
	case INITIAL_BODY_CONTENT:
		return "initial_body_content"
	case CONTENT_TYPE:
		return "content_type"
	case CONTENT_LENGTH:
		return "content_length"
	case CONTENT_LOCATION:
		return "content_location"
	case ETAG_HEADER:
		return "etag_header"
	case SERVER_HEADER:
		return "server_header"
	case STATUS_CODE_TEXT:
		return "status_code_text"
	case LAST_MODIFIED_HEADER:
		return "last_modified_header"
	case LOCATION:
		return "location"
	case SET_COOKIE_NAMES:
		return "set_cookie_names"
	case PAGE_TITLE:
		return "page_title"
	case COMMENTS:
		return "comments"
	case CSS_CLASSES:
		return "css_classes"
	case CANONICAL_LINK:
		return "canonical_link"
	case FIRST_HEADER_TAG:
		return "first_header_tag"
	case HEADER_TAGS:
		return "header_tags"
	case DIV_IDS:
		return "div_ids"
	case TAG_IDS:
		return "tag_ids"
	case TAG_NAMES:
		return "tag_names"
	case VISIBLE_TEXT:
		return "visible_text"
	case VISIBLE_WORD_COUNT:
		return "visible_word_count"
	case OUTBOUND_EDGE_TAG_NAMES:
		return "outbound_edge_tag_names"
	case OUTBOUND_EDGE_COUNT:
		return "outbound_edge_count"
	case ANCHOR_LABELS:
		return "anchor_labels"
	case INPUT_IMAGE_LABELS:
		return "input_image_labels"
	case INPUT_SUBMIT_LABELS:
		return "input_submit_labels"
	case BUTTON_SUBMIT_LABELS:
		return "button_submit_labels"
	case NON_HIDDEN_FORM_INPUT_TYPES:
		return "non_hidden_form_input_types"
	default:
		return "unknown"
	}
}

var AllFingerprintAttributes = []Type{
	STATUS_CODE,
	LINE_COUNT,
	WORD_COUNT,
	WHOLE_BODY_CONTENT,
	LIMITED_BODY_CONTENT,
	INITIAL_BODY_CONTENT,
	CONTENT_TYPE,
	CONTENT_LENGTH,
	CONTENT_LOCATION,
	ETAG_HEADER,
	SERVER_HEADER,
	STATUS_CODE_TEXT,
	LAST_MODIFIED_HEADER,
	LOCATION,
	SET_COOKIE_NAMES,
	PAGE_TITLE,
	COMMENTS,
	CSS_CLASSES,
	CANONICAL_LINK,
	FIRST_HEADER_TAG,
	HEADER_TAGS,
	DIV_IDS,
	TAG_IDS,
	TAG_NAMES,
	VISIBLE_TEXT,
	VISIBLE_WORD_COUNT,
	OUTBOUND_EDGE_TAG_NAMES,
	OUTBOUND_EDGE_COUNT,
	ANCHOR_LABELS,
	INPUT_IMAGE_LABELS,
	INPUT_SUBMIT_LABELS,
	BUTTON_SUBMIT_LABELS,
	NON_HIDDEN_FORM_INPUT_TYPES,
}

var TotalFingerprintAttributes = len(AllFingerprintAttributes)
