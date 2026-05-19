package linkfinder

import "regexp"

// Regex patterns compiled at package init time for performance.
var (
	// LinkFinder main pattern - broad catch-all for quoted URLs/paths
	linkfdPattern = regexp.MustCompile("(?i)(?:\"|'|`)(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|htm|js|txt|xml|cgi)(?:[\\?|#][^\"|']{0,}|))|(?:\\$\\{[^\\}]+\\}|[a-zA-Z0-9_\\-/])+(?:\\/[a-zA-Z0-9_\\-/]+)+)(?:\"|'|`)")

	// Direct URL pattern
	urlRegex = regexp.MustCompile(`(?i)(https?://[^\x00-\x1f"'\s<>#()\[\]{}]+)`)

	// String extraction patterns
	stringInDoubleQuotes = regexp.MustCompile(`"(?P<href>.+?)"`)
	stringInSingleQuotes = regexp.MustCompile(`'(?P<href>.+?)'`)
	stringInBackticks    = regexp.MustCompile("`(?P<href>.+?)`")

	// HTML attributes pattern (href, src, action)
	htmlHrefPattern = regexp.MustCompile(`(?i)\s(?:[a-z0-9.-_]+|)(href|src|action)(?:[a-z0-9.-_]+|)\s*=\s*(?:["']|)(?P<href>[^>"'() ]+)`)

	// window.open pattern
	windowOpenRegex = regexp.MustCompile("(?i)window\\.open\\([\"'](?P<href>(?:.+?)[^)\"']+)[\"']")

	// JS-specific patterns for context-aware extraction - merged for performance
	// Originally 14 patterns, now merged into 4 groups

	// Group 1: HTTP Method Calls (merged patterns 0, 1, 5, 6, 7, 8, 10, 11)
	// Matches: fetch(), axios.get(), $.post(), http.delete(), request.open(), var + '/path'
	jsHTTPMethodPattern = regexp.MustCompile(`(?im)(?:` +
		// fetch(...) standalone or with comma
		`fetch\s*\(\s*['"\x60](?P<href1>[^'"\x60]+)['"\x60]` +
		// [a-zA-Z].(get|post|...) - generic method calls
		`|[a-zA-Z]\.(get|post|fetch|patch|delete|option|put|ajax)\(\s*['"\x60](?P<href2>[a-zA-Z0-9\-_\\/:\?=]+)['"\x60]` +
		// (axios|jquery|$|http|instance).(method)('url')
		`|(?:axios|jquery|instance|http|\$)\.(get|post|delete|put|ajax)\(['"\x60](?P<href3>.*?)['"\x60]` +
		// (axios|...).(method)(variable, - captures variable name
		`|(?:axios|jquery|instance|http|\$)\.(get|post|delete|put|ajax)\((?P<href4>[a-zA-Z0-9._]+),` +
		// XMLHttpRequest: (req|request).open('GET|POST', 'url')
		`|(?:req|request)\.open\(['"\x60](?:GET|POST)['"\x60],\s*['"\x60](?P<href5>.*?)['"\x60]` +
		// Concatenation: axios.get(var + '/path')
		`|(?:axios|jquery|instance|http|\$)\.(get|post|delete|put|ajax)\([a-zA-Z0-9_]+\s*\+\s*['"\x60](?P<href6>.*?)['"\x60]` +
		// Template path: axios.get('/path/' + var + '/')
		`|(?:axios|jquery|instance|http|\$)\.(get|post|delete|put|ajax)\(['"\x60](?P<href7>/.*?\s*\+\s*[a-zA-Z0-9_]+\s*\+\s*)['"\x60]` +
		`)`)

	// Group 2: Property Assignments (merged patterns 2, 3, 4, 12)
	// Matches: url: '/path', path = '/value', file: './data'
	jsPropertyPattern = regexp.MustCompile(`(?im)(?:` +
		// (url|path|file)'...: '...' - object property notation
		`(?:url|path|file)['"\x60]\s*:\s*['"\x60](?P<href1>[^'"\x60]*)['"\x60]` +
		// url: 'value' or url: var + 'value'
		`|url\s*:\s*(?:[a-zA-Z0-9]+\s*\+\s*)?['"\x60](?P<href2>[^'"\x60]*)['"\x60]` +
		// (path|pathname|file) (:|=) 'value'
		`|(?:path|pathname|file)\s*[=:]\s*['"\x60](?P<href3>[^'"\x60]*)['"\x60]` +
		`)`)

	// Group 3: Variable Declarations (pattern 9)
	// Matches: const apiUrl = '/api/v1', let url = 'https://...'
	jsVariablePattern = regexp.MustCompile(`(?i)(?:const|let|var)\s*[a-zA-Z0-9_]+\s*=\s*['"](?P<href>(?:https?://|/|\./)[^'"]*?)['"]`)

	// Group 4: HTML Attributes (pattern 13)
	// Matches: href="/path", src="/script.js", action="/submit", xlink:href="/svg"
	jsAttributePattern = regexp.MustCompile(`(?i)\s(?:[a-z0-9.\-_:]*)(href|src|action)(?:[a-z0-9.\-_:]*)\s*=\s*(?:["'])?(?P<href>[^>"'()\s]+)`)

	// Preprocessing patterns - combined for performance
	// Matches: import/require(), import...from, export...from statements
	jsImportExportPattern = regexp.MustCompile(`(?:` +
		// CommonJS: require("module") or import("module")
		`(?:import|require)\s*\(["'\x60][^"'\x60]+["'\x60]\)` +
		// ES6: import x from "y", import "y", export x from "y"
		`|(?:import|export)\s+(?:[^"'\x60]+\s+from\s+)?["'\x60][^"'\x60]+["'\x60]` +
		`)`)
	// Bundled language dictionaries (webpack-style)
	bundledLanguagePattern = regexp.MustCompile(`\{\s*"\./[a-zA-Z-]+"\s*:\s*"[^"]+(?:\s*,\s*"\./[a-zA-Z-]+(?:\.js)?"\s*:\s*"[^"]+")* \s*\}`)

	// Timezone pattern (for filtering)
	timezonePattern = regexp.MustCompile(`^([A-Za-z/_\-0-9+]+\|[A-Za-z/_\-0-9+]+)$`)

	// Spam detection patterns - merged for performance (was 10 patterns)
	// Group 1: Spam character patterns
	// Detects: X_Y patterns, repeated underscores, consecutive special chars
	spamCharPattern = regexp.MustCompile(`(?:` +
		// Pattern 1: X_Y (uppercase/digit _ uppercase/digit/!)
		`[A-Z0-9]_[A-Z0-9!]` +
		// Pattern 2+2b: alphanumeric_alphanumeric repeated 3+ times
		`|(?:[0-9A-Z]_){3,}` +
		// Pattern 3b: 4+ consecutive special chars
		`|[_:.<>\-]{4,}` +
		`)`)

	// Group 2: HTML tag pattern
	// Detects: opening tags, closing tags, self-closing tags
	htmlTagPattern = regexp.MustCompile(`</?[a-zA-Z][^>]*>|</[a-zA-Z]+>`)

	// Special characters pattern
	onlySpecialCharsPattern = regexp.MustCompile("^[\\(\\)\\[\\]\\{\\}=\\?\\.\\-_,/\\\\:;!@#$%^&*+|<>~`'\"\\s]+$")

	// Ignored prefixes - not valid paths
	ignorePrefix = regexp.MustCompile(`(?i)^(mailto|tel|data|javascript|blob|about|chrome|file|vbscript|ms-|git\+ssh):`)

	// CSS/JS noise pattern - combined single regex for performance (was 21 separate patterns)
	// Matches: CSS units, colors, functions, keywords, JS literals, MIME types, etc.
	cssValuePattern = regexp.MustCompile(`(?i)^(?:` +
		// CSS units: 10px, 5em, 2rem, 50%
		`\d+(?:px|em|rem|%)` +
		// Hex colors: #fff, #ffffff, #ffffffff
		`|#[0-9a-f]{3,8}` +
		// CSS functions: rgb(, rgba(, hsl(, hsla(
		`|(?:rgba?|hsla?)\(.*` +
		// CSS keywords
		`|(?:none|auto|inherit|initial|normal|unset)` +
		// JS literals
		`|(?:true|false|null|undefined|NaN|Infinity)` +
		// Pure numbers
		`|\d+` +
		// Short lowercase (css shorthand like "px", "em")
		`|[a-z]{1,3}` +
		// ISO date prefix: 2024-01-15...
		`|\d{4}-\d{2}-\d{2}.*` +
		// Time: 12:30...
		`|\d{2}:\d{2}.*` +
		// Constants: MAX_VALUE, API_KEY
		`|[A-Z_]+` +
		// Template vars: ${foo}, ${incomplete, {id}, {incomplete
		`|\$\{[^}]*\}?` +
		`|\{[a-zA-Z][a-zA-Z0-9_]*\}?` +
		// At-rules/decorators: @media, @import, @keyframes
		`|@.+` +
		// Versions: v1.0, 2.3.4, v1.2.3
		`|v?\d+(?:\.\d+)+` +
		// MIME types: text/html, application/json
		`|(?:text|application|image|audio|video)/.+` +
		// Font families
		`|(?:sans-serif|serif|monospace|cursive|fantasy)` +
		// Display/position values
		`|(?:block|inline|flex|grid|absolute|relative|fixed|static)` +
		// Alignment values
		`|(?:top|bottom|left|right|center|middle)` +
		// Border styles
		`|(?:solid|dashed|dotted|double|groove|ridge|inset|outset)` +
		`)$`)

	// Extension regex
	reGetExtName = regexp.MustCompile(`\.([0-9a-zA-Z]+)(\?|#|$)`)

	// Non-printable regex
	nonPrintableRegex = regexp.MustCompile(`[\t\r\n]+`)

	// Regex metacharacter patterns in path segments (invalid paths)
	// Detects: +((, .*, +*, ++, ?+, (?:, (?=, (?!, (?<, [^
	regexMetaPattern = regexp.MustCompile(`^[+*?]+\(|^\.\*|^[+*?]{2,}|\(\?[=!:<]|\[\^`)

	// Comma-prefixed parameter patterns (malformed paths like ,fn=)
	commaStartPattern = regexp.MustCompile(`^,\w+=`)

	// Dangerous URL-encoded characters pattern (reject entire URL)
	// %00 = null, %22/%27 = quotes, %3C/%3E = angle brackets, %5B/%5D = brackets, %7C = pipe
	dangerousEncodedPattern = regexp.MustCompile(`(?i)%(?:00|22|27|3[cCeE]|5[bBdD]|7[cC])`)
)

// blacklistWordlist contains patterns to filter out spam/noise from extracted links.
var blacklistWordlist = []string{
	".replace(",
	"/,",
	")]",
	")}",
	"if(",
	"for(",
	".concat",
	"url(",
	"},",
	"&&",
	"==",
	"===",
	"!=",
	"!==",
	",regex:",
	"{top:",
	".padding",
	".length",
	".split(",
	".join(",
	".slice(",
	".substr(",
	".substring(",
	".trim(",
	".map(",
	".shadow(",
	".filter(",
	".find(",
	".findIndex(",
	".findLast(",
	".findLastIndex(",
	".includes(",
	".indexOf(",
	"Math.round",
	"Math.floor",
	"Math.ceil",
	"Math.random",
	"Math.max",
	"Math.min",
	"Math.abs",
	"Math.sin",
	"Math.cos",
	"Math.tan",
	"Math.asin",
	"Math.acos",
	"Math.atan",
	"Math.atan2",
	"Math.pow",
	".attr(",
	";if(",
	".if(",
	";while(",
	";switch(",
	";case",
	";default",
	";break",
	";continue",
	"[0-9",
	"],[",
	"!1",
	"!0",
	"\").",
	".test(",
	".replaceAll(",
	"]}(",
	"),{",
	".href",
	"]+",
	"file://",
	"),",
	";;AAAA",
	",/",
	".join",
	",this.",
	"/]]",
	"/d{",
	"officeopenxml.com",
	"w3.org",
	"xl/workbook.bin",
	"schemas.microsoft.com",
	"openxmlformats.org",
	"].xml",
	"git+ssh://",
	"https://github.com/",
	"https://gist.github.com",
	"/_rels",
	"encodeURIComponent",
	"/xl/workbook.bin",
	"/xl/workbook.xml",
	"/xl/workbook.xml.rels",
	"/xl/worksheets/sheet1.xml",
	"/xl/worksheets/sheet1.xml.rels",
	"/xl/worksheets/sheet2.xml",
	"/xl/worksheets/sheet2.xml.rels",
	"/xl/worksheets/sheet3.xml",
	"jsdelivr.net",
	"unpkg.com",
	"openoffice.org",
	"/;;",
	"PDF.js",
	"\",",
	"):[",
	"/:/",
	"www.apache.org",
	"cdnjs.cloudflare.com",
	".exec(",
	"function(",
	".offsetLeft",
	"momentjs.com",
	"npms.io",
	"cookielaw.org",
	"transcend-cdn.com",
	"[...",
	"...]",
	"[.",
	".]",
	"}return",
	"M/D/YYYY",
	"MM/dd/yyyy",
	"Pacific/Niue",
	"Pacific/Pago_Pago",
	"Pacific/Honolulu",
	"Pacific/Rarotonga",
	"Pacific/Tahiti",
	"Pacific/Marquesas",
	"America/Anchorage",
	"Pacific/Gambier",
	"America/Los_Angeles",
	"America/Tijuana",
	"America/Vancouver",
	"America/Whitehorse",
	"Pacific/Pitcairn",
	"America/Denver",
	"America/Phoenix",
	"America/Mazatlan",
	"America/Dawson_Creek",
	"America/Edmonton",
	"America/Hermosillo",
	"America/Yellowknife",
	"America/Belize",
	"America/Chicago",
	"America/Mexico_City",
	"America/Regina",
	"America/Tegucigalpa",
	"America/Winnipeg",
	"America/Costa_Rica",
	"America/El_Salvador",
	"Pacific/Galapagos",
	"America/Guatemala",
	"America/Managua",
	"America/Cancun",
	"America/Bogota",
	"Pacific/Easter",
	"America/New_York",
	"America/Iqaluit",
	"America/Toronto",
	"America/Guayaquil",
	"America/Havana",
	"America/Jamaica",
	"America/Lima",
	"America/Nassau",
	"America/Panama",
	"America/Port-au-Prince",
	"America/Rio_Branco",
	"America/Halifax",
	"America/Barbados",
	"Atlantic/Bermuda",
	"America/Boa_Vista",
	"America/Caracas",
	"America/Curacao",
	"America/Grand_Turk",
	"America/Guyana",
	"America/La_Paz",
	"America/Manaus",
	"America/Martinique",
	"America/Port_of_Spain",
	"America/Porto_Velho",
	"America/Puerto_Rico",
	"America/Santo_Domingo",
	"America/Thule",
	"America/St_Johns",
	"America/Araguaina",
	"America/Asuncion",
	"America/Belem",
	"America/Argentina/Buenos_Aires",
	"America/Campo_Grande",
	"America/Cayenne",
	"America/Cuiaba",
	"America/Fortaleza",
	"America/Godthab",
	"America/Maceio",
	"America/Miquelon",
	"America/Montevideo",
	"Antarctica/Palmer",
	"America/Paramaribo",
	"America/Punta_Arenas",
	"America/Recife",
	"Antarctica/Rothera",
	"America/Bahia",
	"America/Santiago",
	"Atlantic/Stanley",
	"America/Noronha",
	"America/Sao_Paulo",
	"Atlantic/South_Georgia",
	"Atlantic/Azores",
	"Atlantic/Cape_Verde",
	"America/Scoresbysund",
	"Africa/Abidjan",
	"Africa/Accra",
	"Africa/Bissau",
	"Atlantic/Canary",
	"Africa/Casablanca",
	"America/Danmarkshavn",
	"Europe/Dublin",
	"Africa/El_Aaiun",
	"Atlantic/Faroe",
	"Etc/UTC",
	"Europe/Lisbon",
	"Europe/London",
	"Africa/Monrovia",
	"Atlantic/Reykjavik",
	"Africa/Algiers",
	"Europe/Amsterdam",
	"Europe/Andorra",
	"Europe/Berlin",
	"Europe/Brussels",
	"Europe/Budapest",
	"Europe/Belgrade",
	"Europe/Prague",
	"Africa/Ceuta",
	"Europe/Copenhagen",
	"Europe/Gibraltar",
	"Africa/Lagos",
	"Europe/Luxembourg",
	"Europe/Madrid",
	"Europe/Malta",
	"Europe/Monaco",
	"Africa/Ndjamena",
	"Europe/Oslo",
	"Europe/Paris",
	"Europe/Rome",
	"Europe/Stockholm",
	"Europe/Tirane",
	"Africa/Tunis",
	"Europe/Vienna",
	"Europe/Warsaw",
	"Europe/Zurich",
	"Asia/Amman",
	"Europe/Athens",
	"Asia/Beirut",
	"Europe/Bucharest",
	"Africa/Cairo",
	"Europe/Chisinau",
	"Asia/Damascus",
	"Asia/Gaza",
	"Europe/Helsinki",
	"Asia/Jerusalem",
	"Africa/Johannesburg",
	"Africa/Khartoum",
	"Europe/Kiev",
	"Africa/Maputo",
	"Europe/Kaliningrad",
	"Asia/Nicosia",
	"Europe/Riga",
	"Europe/Sofia",
	"Europe/Tallinn",
	"Africa/Tripoli",
	"Europe/Vilnius",
	"Africa/Windhoek",
	"Asia/Baghdad",
	"Europe/Istanbul",
	"Europe/Minsk",
	"Europe/Moscow",
	"Africa/Nairobi",
	"Asia/Qatar",
	"Asia/Riyadh",
	"Antarctica/Syowa",
	"Asia/Tehran",
	"Asia/Baku",
	"Asia/Dubai",
	"Indian/Mahe",
	"Indian/Mauritius",
	"Europe/Samara",
	"Indian/Reunion",
	"Asia/Tbilisi",
	"Asia/Yerevan",
	"Asia/Kabul",
	"Asia/Aqtau",
	"Asia/Aqtobe",
	"Asia/Ashgabat",
	"Asia/Dushanbe",
	"Asia/Karachi",
	"Indian/Kerguelen",
	"Indian/Maldives",
	"Antarctica/Mawson",
	"Asia/Yekaterinburg",
	"Asia/Tashkent",
	"Asia/Colombo",
	"Asia/Kolkata",
	"Asia/Katmandu",
	"Asia/Almaty",
	"Asia/Bishkek",
	"Indian/Chagos",
	"Asia/Dhaka",
	"Asia/Omsk",
	"Asia/Thimphu",
	"Antarctica/Vostok",
	"Indian/Cocos",
	"Asia/Yangon",
	"Asia/Bangkok",
	"Indian/Christmas",
	"Antarctica/Davis",
	"Asia/Saigon",
	"Asia/Hovd",
	"Asia/Jakarta",
	"Asia/Krasnoyarsk",
	"Asia/Brunei",
	"Asia/Shanghai",
	"Asia/Choibalsan",
	"Asia/Hong_Kong",
	"Asia/Kuala_Lumpur",
	"Asia/Macau",
	"Asia/Makassar",
	"Asia/Manila",
	"Asia/Irkutsk",
	"Asia/Singapore",
	"Asia/Taipei",
	"Asia/Ulaanbaatar",
	"Australia/Perth",
	"Asia/Pyongyang",
	"Asia/Dili",
	"Asia/Jayapura",
	"Asia/Yakutsk",
	"Pacific/Palau",
	"Asia/Seoul",
	"Asia/Tokyo",
	"Australia/Darwin",
	"Antarctica/DumontDUrville",
	"Australia/Brisbane",
	"Pacific/Guam",
	"Asia/Vladivostok",
	"Pacific/Port_Moresby",
	"Australia/Adelaide",
	"Antarctica/Casey",
	"Australia/Hobart",
	"Australia/Sydney",
	"Pacific/Efate",
	"Pacific/Guadalcanal",
	"Pacific/Kosrae",
	"Asia/Magadan",
	"Pacific/Noumea",
	"Pacific/Pohnpei",
	"Pacific/Funafuti",
	"Pacific/Kwajalein",
	"Pacific/Majuro",
	"Asia/Kamchatka",
	"Pacific/Tarawa",
	"Pacific/Wake",
	"Pacific/Wallis",
	"Pacific/Auckland",
	"Pacific/Enderbury",
	"Pacific/Fakaofo",
	"Pacific/Fiji",
	"Pacific/Tongatapu",
	"Pacific/Apia",
	"Pacific/Kiritimati",
	"purl.org",
	"sharedStrings.xml",
	"application/xml",
	"application/pdf",
	"application/zip",
	"text/csv",
	"xl/workbook.xml",
	"xl/worksheets/sheet",
	"xl/media/image",
	"xl/drawings/drawing",
	"image/png",
	"xl/sharedStrings.xml",
	"xl/styles.xml",
	"docProps/app.xml",
	"N/A",
	"M/d/y",
	"M/d",
	"M/y",
	"application/json",
	"DD/M/YYYY",
	"D/M/YYYY",
	"multipart/form-data",
	"application/octet-stream",
	"image/x-icon",
	"npmcdn.com",
	"text/javascript",
	"YYYY/M/D",
	"yyyy/m/d",
	"MM/DD/YYYY",
	"mm/dd/yy",
	"mm/dd/yyyy",
	"YYYY/MM/DD",
	"yyyy/mm/dd",
	"D/JM",
	"DD/MM/YYYY",
	"dd/mm/yyyy",
	"M/d/yy",
	"m/d/yy",
	"MM/D/YYYY",
	"mm/d/yy",
	"this.route.",
	"wss://",
	"ws://",
	".endIndex",
	".startIndex",
	"text/xml",
	"text/html",
	"./]",
	".subCommand",
	"this.getAction",
	"this.createElement",
	".getAttribute",
	"this.element.id",
	".appendChild",
	".removeChild",
	".replaceChild",
	".insertBefore",
	".insertAdjacentHTML",
	".insertAdjacentText",
	".insertAdjacentElement",
	"application/x-www-form-urlencoded",
	",<>",
	"{}[]",
	"<>",
	".lastIndexOf",
	"angular.io",
	".item.url",
	"this.onActionComplete.",
	"this.actionCompleteHandler.",
	"this.actionComplete.bind",
	"this.actionBegin.bind",
	"g.co/ng/",
	"(d*)",
	"/^(",
	"s[n.",
	"multipart/mixed",
	"text/x-scriptlet",
	"/docProps/core.xml",
	"/worksheets/sheet",
	".componentRef",
	"application/x-shockwave-flash",
	"text/plain",
	"/signalr/js",
	"://aka.ms/",
	"www.cdc.gov",
	"fb.me/",
	"</style",
	"<script",
	"<style",
	"<link",
	"<meta",
	"<title",
	"<body",
	"<html",
	"<head",
	"</textarea",
	".createElement",
	"this.props.",
	"this.schedule",
	"openid.net",
	"petstore.swagger.io",
	"validator.swagger.io", "twitter.com/hashtag/", "facebook.com/hashtag", "instagram.com/explore/tags", "i18n/lang",
	"ngInjectableDef.js", "ngModuleDef.js", "ngInjectorDef.js",
	"facebook.github.io",
	"bit.ly/",
	"nist.gov",
	":{{",
	"CDATA[[",
	"/marked.js.org",
	"^http.",
	"^https.",
	"http(s)",
	"[hH]",
	"ng://", "ng:///",
}

// unwantedExts contains file extensions to filter from extraction.
var unwantedExts = map[string]bool{
	// Frontend frameworks/templates
	"vue": true,
	// Stylesheets
	"css": true, "scss": true, "sass": true, "less": true,
	// Scripts (static assets)
	"ts": true, "tsx": true, "jsx": true, "mjs": true, "map": true,
	// Images
	"jpg": true, "jpeg": true, "png": true, "gif": true, "svg": true,
	"bmp": true, "webp": true, "ico": true, "tiff": true, "tif": true,
	// Fonts
	"woff": true, "woff2": true, "ttf": true, "eot": true, "otf": true,
	// Audio
	"mp3": true, "wav": true, "ogg": true, "flac": true, "aac": true, "m3u8": true,
	// Video
	"mp4": true, "webm": true, "mkv": true, "flv": true, "avi": true, "mov": true, "wmv": true,
	// Documents
	"pdf": true,
	// Archives
	"zip": true, "tar": true, "gz": true, "rar": true, "7z": true, "bz2": true,
}
