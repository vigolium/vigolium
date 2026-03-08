package xss_light_scanner

import "strings"

// EventHandlers contains all JavaScript event handler attributes
var EventHandlers = map[string]bool{
	// Mouse events
	"onclick":       true,
	"ondblclick":    true,
	"onmousedown":   true,
	"onmouseup":     true,
	"onmousemove":   true,
	"onmouseover":   true,
	"onmouseout":    true,
	"onmouseenter":  true,
	"onmouseleave":  true,
	"onmousewheel":  true,
	"onwheel":       true,
	"oncontextmenu": true,

	// Keyboard events
	"onkeydown":  true,
	"onkeypress": true,
	"onkeyup":    true,

	// Form events
	"onchange":     true,
	"oninput":      true,
	"onsubmit":     true,
	"onreset":      true,
	"onselect":     true,
	"onfocus":      true,
	"onblur":       true,
	"onfocusin":    true,
	"onfocusout":   true,
	"oninvalid":    true,
	"onformchange": true,
	"onforminput":  true,

	// Drag events
	"ondrag":      true,
	"ondragend":   true,
	"ondragenter": true,
	"ondragleave": true,
	"ondragover":  true,
	"ondragstart": true,
	"ondrop":      true,

	// Clipboard events
	"oncopy":  true,
	"oncut":   true,
	"onpaste": true,

	// Media events
	"onabort":          true,
	"oncanplay":        true,
	"oncanplaythrough": true,
	"ondurationchange": true,
	"onemptied":        true,
	"onended":          true,
	"onerror":          true,
	"onloadeddata":     true,
	"onloadedmetadata": true,
	"onloadstart":      true,
	"onpause":          true,
	"onplay":           true,
	"onplaying":        true,
	"onprogress":       true,
	"onratechange":     true,
	"onseeked":         true,
	"onseeking":        true,
	"onstalled":        true,
	"onsuspend":        true,
	"ontimeupdate":     true,
	"onvolumechange":   true,
	"onwaiting":        true,
	"oncuechange":      true,

	// Window events
	"onload":         true,
	"onunload":       true,
	"onbeforeunload": true,
	"onresize":       true,
	"onscroll":       true,
	"onhashchange":   true,
	"onpopstate":     true,
	"ononline":       true,
	"onoffline":      true,
	"onstorage":      true,
	"onmessage":      true,
	"onafterprint":   true,
	"onbeforeprint":  true,
	"onpagehide":     true,
	"onpageshow":     true,

	// Touch events
	"ontouchstart":  true,
	"ontouchend":    true,
	"ontouchmove":   true,
	"ontouchcancel": true,
	"ontouchenter":  true,
	"ontouchleave":  true,

	// Animation events
	"onanimationend":       true,
	"onanimationiteration": true,
	"onanimationstart":     true,
	"ontransitionend":      true,

	// Other events
	"oncancel":         true,
	"onclose":          true,
	"onshow":           true,
	"ontoggle":         true,
	"onactivate":       true,
	"onbeforeactivate": true,
	"onpropertychange": true,
	"onredo":           true,
	"onundo":           true,

	// DOM events
	"ondomactivate":                 true,
	"ondomattributenamechanged":     true,
	"ondomattrmodified":             true,
	"ondomcharacterdatamodified":    true,
	"ondomcontentloaded":            true,
	"ondomelementnamechanged":       true,
	"ondomfocusin":                  true,
	"ondomfocusout":                 true,
	"ondomnodeinserted":             true,
	"ondomnodeinsertedintodocument": true,
	"ondomnoderemoved":              true,
	"ondomnoderemovedfromdocument":  true,
	"ondomsubtreemodified":          true,

	// SVG events
	"onsvgabort":    true,
	"onsvgerror":    true,
	"onsvgload":     true,
	"onsvgresize":   true,
	"onsvgscroll":   true,
	"onsvgunload":   true,
	"onsvgzoom":     true,
	"onbeginevent":  true,
	"onendevent":    true,
	"onrepeatevent": true,

	// Device events
	"ondevicelight":             true,
	"ondevicemotion":            true,
	"ondeviceorientation":       true,
	"ondeviceproximity":         true,
	"onorientationchange":       true,
	"oncompassneedscalibration": true,
	"onuserproximity":           true,

	// Fullscreen events
	"onfullscreenchange":  true,
	"onfullscreenerror":   true,
	"onpointerlockchange": true,
	"onpointerlockerror":  true,

	// Gamepad events
	"ongamepadconnected":    true,
	"ongamepaddisconnected": true,

	// App cache events
	"oncached":      true,
	"onchecking":    true,
	"ondownloading": true,
	"onnoupdate":    true,
	"onobsolete":    true,
	"onupdateready": true,

	// IndexedDB events
	"onblocked":       true,
	"onsuccess":       true,
	"onupgradeneeded": true,
	"onversionchange": true,

	// Battery events
	"onchargingchange":        true,
	"onchargingtimechange":    true,
	"ondischargingtimechange": true,
	"onlevelchange":           true,

	// Composition events
	"oncompositionend":    true,
	"oncompositionstart":  true,
	"oncompositionupdate": true,

	// Audio events
	"onaudioprocess": true,

	// Misc events
	"onloadend":          true,
	"onreadystatechange": true,
	"ontimeout":          true,
	"onvisibilitychange": true,
}

// IsEventHandler checks if the attribute name is an event handler
func IsEventHandler(attributeName string) bool {
	if attributeName == "" {
		return false
	}
	return EventHandlers[strings.ToLower(attributeName)]
}

// IsURLAttribute checks if the attribute can execute JavaScript URLs
func IsURLAttribute(tagName, attributeName string) bool {
	if tagName == "" || attributeName == "" {
		return false
	}

	tag := strings.ToLower(tagName)
	attr := strings.ToLower(attributeName)

	// src attribute - can use javascript: protocol in many contexts
	if attr == "src" {
		switch tag {
		case "iframe", "frame", "embed", "script", "img", "audio", "video", "source", "track":
			return true
		}
	}

	// data attribute for embedding content
	if attr == "data" {
		switch tag {
		case "object":
			return true
		}
	}

	// href attribute
	if attr == "href" {
		switch tag {
		case "a", "area", "base", "link", "math":
			return true
		}
	}

	// formaction attribute
	if attr == "formaction" {
		switch tag {
		case "button", "input":
			return true
		}
	}

	// action attribute
	if attr == "action" && tag == "form" {
		return true
	}

	// poster attribute for video
	if attr == "poster" && tag == "video" {
		return true
	}

	// srcset for responsive images (less common vector)
	if attr == "srcset" && tag == "img" {
		return true
	}

	// SVG xlink:href
	if attr == "xlink:href" {
		switch tag {
		case "a", "use", "image", "animate", "set", "animatemotion", "animatetransform":
			return true
		}
	}

	return false
}

// GetAllEventHandlers returns a list of all event handler names
func GetAllEventHandlers() []string {
	handlers := make([]string, 0, len(EventHandlers))
	for handler := range EventHandlers {
		handlers = append(handlers, handler)
	}
	return handlers
}
