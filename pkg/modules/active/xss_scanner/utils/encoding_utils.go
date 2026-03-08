package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// --- Static Fields and Initializer ---

// HtmlEntitiesMap corresponds to 'public static final Map<String, Character> a' in cy.java
var HtmlEntitiesMap map[string]rune

// init function for package-level static initialization for cy.
func init() {
	HtmlEntitiesMap = make(map[string]rune)
	// static { a.put("quot", new Character('"')); ... }
	HtmlEntitiesMap["quot"] = '"'
	HtmlEntitiesMap["amp"] = '&'
	HtmlEntitiesMap["lt"] = '<'
	HtmlEntitiesMap["gt"] = '>'
	HtmlEntitiesMap["apos"] = '\''
	HtmlEntitiesMap["nbsp"] = ' '
	HtmlEntitiesMap["iexcl"] = '¡'
	HtmlEntitiesMap["cent"] = '¢'
	HtmlEntitiesMap["pound"] = '£'
	HtmlEntitiesMap["curren"] = '¤'
	HtmlEntitiesMap["yen"] = '¥'
	HtmlEntitiesMap["brvbar"] = '¦'
	HtmlEntitiesMap["sect"] = '§'
	HtmlEntitiesMap["uml"] = '¨'
	HtmlEntitiesMap["copy"] = '©'
	HtmlEntitiesMap["ordf"] = 'ª'
	HtmlEntitiesMap["laquo"] = '«'
	HtmlEntitiesMap["not"] = '¬'
	HtmlEntitiesMap["shy"] = '\u00ad' // Soft hyphen
	HtmlEntitiesMap["reg"] = '®'
	HtmlEntitiesMap["macr"] = '¯'
	HtmlEntitiesMap["deg"] = '°'
	HtmlEntitiesMap["plusmn"] = '±'
	HtmlEntitiesMap["sup2"] = '²'
	HtmlEntitiesMap["sup3"] = '³'
	HtmlEntitiesMap["acute"] = '´'
	HtmlEntitiesMap["micro"] = 'µ'
	HtmlEntitiesMap["para"] = '¶'
	HtmlEntitiesMap["middot"] = '·'
	HtmlEntitiesMap["cedil"] = '¸'
	HtmlEntitiesMap["sup1"] = '¹'
	HtmlEntitiesMap["ordm"] = 'º'
	HtmlEntitiesMap["raquo"] = '»'
	HtmlEntitiesMap["frac14"] = '¼'
	HtmlEntitiesMap["frac12"] = '½'
	HtmlEntitiesMap["frac34"] = '¾'
	HtmlEntitiesMap["iquest"] = '¿'
	HtmlEntitiesMap["Agrave"] = 'À'
	HtmlEntitiesMap["Aacute"] = 'Á'
	HtmlEntitiesMap["Acirc"] = 'Â'
	HtmlEntitiesMap["Atilde"] = 'Ã'
	HtmlEntitiesMap["Auml"] = 'Ä'
	HtmlEntitiesMap["Aring"] = 'Å'
	HtmlEntitiesMap["AElig"] = 'Æ'
	HtmlEntitiesMap["Ccedil"] = 'Ç'
	HtmlEntitiesMap["Egrave"] = 'È'
	HtmlEntitiesMap["Eacute"] = 'É'
	HtmlEntitiesMap["Ecirc"] = 'Ê'
	HtmlEntitiesMap["Euml"] = 'Ë'
	HtmlEntitiesMap["Igrave"] = 'Ì'
	HtmlEntitiesMap["Iacute"] = 'Í'
	HtmlEntitiesMap["Icirc"] = 'Î'
	HtmlEntitiesMap["Iuml"] = 'Ï'
	HtmlEntitiesMap["ETH"] = 'Ð'
	HtmlEntitiesMap["Ntilde"] = 'Ñ'
	HtmlEntitiesMap["Ograve"] = 'Ò'
	HtmlEntitiesMap["Oacute"] = 'Ó'
	HtmlEntitiesMap["Ocirc"] = 'Ô'
	HtmlEntitiesMap["Otilde"] = 'Õ'
	HtmlEntitiesMap["Ouml"] = 'Ö'
	HtmlEntitiesMap["times"] = '×'
	HtmlEntitiesMap["Oslash"] = 'Ø'
	HtmlEntitiesMap["Ugrave"] = 'Ù'
	HtmlEntitiesMap["Uacute"] = 'Ú'
	HtmlEntitiesMap["Ucirc"] = 'Û'
	HtmlEntitiesMap["Uuml"] = 'Ü'
	HtmlEntitiesMap["Yacute"] = 'Ý'
	HtmlEntitiesMap["THORN"] = 'Þ'
	HtmlEntitiesMap["szlig"] = 'ß'
	HtmlEntitiesMap["agrave"] = 'à'
	HtmlEntitiesMap["aacute"] = 'á'
	HtmlEntitiesMap["acirc"] = 'â'
	HtmlEntitiesMap["atilde"] = 'ã'
	HtmlEntitiesMap["auml"] = 'ä'
	HtmlEntitiesMap["aring"] = 'å'
	HtmlEntitiesMap["aelig"] = 'æ'
	HtmlEntitiesMap["ccedil"] = 'ç'
	HtmlEntitiesMap["egrave"] = 'è'
	HtmlEntitiesMap["eacute"] = 'é'
	HtmlEntitiesMap["ecirc"] = 'ê'
	HtmlEntitiesMap["euml"] = 'ë'
	HtmlEntitiesMap["igrave"] = 'ì'
	HtmlEntitiesMap["iacute"] = 'í'
	HtmlEntitiesMap["icirc"] = 'î'
	HtmlEntitiesMap["iuml"] = 'ï'
	HtmlEntitiesMap["eth"] = 'ð'
	HtmlEntitiesMap["ntilde"] = 'ñ'
	HtmlEntitiesMap["ograve"] = 'ò'
	HtmlEntitiesMap["oacute"] = 'ó'
	HtmlEntitiesMap["ocirc"] = 'ô'
	HtmlEntitiesMap["otilde"] = 'õ'
	HtmlEntitiesMap["ouml"] = 'ö'
	HtmlEntitiesMap["divide"] = '÷'
	HtmlEntitiesMap["oslash"] = 'ø'
	HtmlEntitiesMap["ugrave"] = 'ù'
	HtmlEntitiesMap["uacute"] = 'ú'
	HtmlEntitiesMap["ucirc"] = 'û'
	HtmlEntitiesMap["uuml"] = 'ü'
	HtmlEntitiesMap["yacute"] = 'ý'
	HtmlEntitiesMap["thorn"] = 'þ'
	HtmlEntitiesMap["yuml"] = 'ÿ'
}

// --- Public Static Methods ---

// NetPortswiggerCyAUrlEncodeAll corresponds to 'public static String a(String var0)' in cy.java
// Encodes a string for use in a URL, encoding almost all non-alphanumeric characters.
func NetPortswiggerCyAUrlEncodeAll(s string) string {
	// String[] var10000 = h9.b(); // Ignored
	length := len(s)
	var sb strings.Builder
	sb.Grow(length * 3) // Max expansion: %XX for each char

	for i := 0; i < length; i++ {
		c := s[i] // In Go, this is a byte
		if c == ' ' {
			sb.WriteByte('+')
		} else if (c >= '0' && c <= '9') ||
			(c >= '@' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			c == '*' || c == '-' || c == '.' || c == '_' {
			sb.WriteByte(c)
		} else {
			// String var6 = "0" + Integer.toHexString(var5);
			// var6 = var6.substring(var6.length() - 2);
			// var3.append("%").append(var6);
			fmt.Fprintf(&sb, "%%%02X", c) // %XX format
		}
	}
	// if (!agd.e()) { h9.b(new String[1]); } // Ignored
	return sb.String()
}

// NetPortswiggerCyDUrlDecodeSpacesOnly corresponds to 'public static String d(String var0)'
func NetPortswiggerCyDUrlDecodeSpacesOnly(s string) string {
	return netPortswiggerCyAUrlDecodeInternal(s, true)
}

// NetPortswiggerCyBUrlDecode corresponds to 'public static String b(String var0)'
func NetPortswiggerCyBUrlDecode(s string) string {
	return netPortswiggerCyAUrlDecodeInternal(s, false)
}

// netPortswiggerCyAUrlDecodeInternal corresponds to 'private static String a(String var0, boolean var1)'
func netPortswiggerCyAUrlDecodeInternal(s string, decodePlusToSpace bool) string {
	length := len(s)
	var sb strings.Builder
	sb.Grow(length) // Decoded string is likely shorter or same length

	for i := 0; i < length; i++ {
		c := s[i]
		if decodePlusToSpace && c == '+' {
			sb.WriteByte(' ')
		} else if c == '%' && i+2 < length { // Check for %XX form
			hex := s[i+1 : i+3]
			if byteVal, err := strconv.ParseUint(hex, 16, 8); err == nil {
				sb.WriteByte(byte(byteVal))
				i += 2 // Advance past XX
			} else {
				// m5.a(var7, rr.IGNORED); // Java logs NumberFormatException
				sb.WriteByte(c) // Append '%' if not valid hex
			}
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// NetPortswiggerCyCHtmlEntityDecode corresponds to 'public static String c(String var0)'
func NetPortswiggerCyCHtmlEntityDecode(s string) string {
	return netPortswiggerCyAHtmlEntityDecodeWithOffsets(s, nil)
}

// netPortswiggerCyAHtmlEntityDecodeWithOffsets corresponds to 'public static String a(String var0, int[] var1)'
// The offset logic (var1) is complex and tied to Java array mutation. For a direct Go port,
// returning modified offsets in a Go-idiomatic way (e.g., a slice of structs or multiple return values)
// would be different. Given the current usage context, if var1 is nil in most calls (like c() does),
// we can simplify this to not handle offset mapping for now, or implement it if a specific need arises.
// For now, var1 (offsets) is ignored as per the c() method calling it with null.
func netPortswiggerCyAHtmlEntityDecodeWithOffsets(s string, offsets []int) string {
	if s == "" { // Java null check
		return "" // Go equivalent for null string
	}

	var sb strings.Builder
	// int var3 = 0; // Original offset tracking, not directly used if offsets array is nil

	for i := 0; i < len(s); {
		if s[i] == '&' {
			semicolonIdx := strings.IndexByte(s[i:], ';')
			if semicolonIdx != -1 {
				entityName := s[i+1 : i+semicolonIdx]
				if strings.HasPrefix(entityName, "#") {
					var charCode int64
					var err error
					if len(entityName) > 1 && (entityName[1] == 'x' || entityName[1] == 'X') {
						if len(entityName) > 2 {
							charCode, err = strconv.ParseInt(entityName[2:], 16, 32)
						}
					} else {
						if len(entityName) > 1 {
							charCode, err = strconv.ParseInt(entityName[1:], 10, 32)
						}
					}

					if err == nil && charCode >= ' ' { // Java also checks if charCode < ' '
						sb.WriteRune(rune(charCode))
						i += semicolonIdx + 1
						continue
					}
					// Parse error or invalid charCode - fall through to append '&' as literal
				} else {
					if r, ok := HtmlEntitiesMap[strings.ToLower(entityName)]; ok {
						sb.WriteRune(r)
						i += semicolonIdx + 1
						// if (var1 != null) { var3 = a(var1, var3, sb.length(), i); } // Offset logic ignored
						continue
					}
					// If not found or not numeric, fall through to append '&' as literal
				}
			} // else, no semicolon found, fall through to append '&'
		}
		sb.WriteByte(s[i])
		i++
		// if (var1 != null) { var3 = a(var1, var3, sb.length(), i); } // Offset logic ignored
	}
	return sb.String()
}
