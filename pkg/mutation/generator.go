package mutation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Generate produces mutations for the given value and detected type.
// Options control which intents are included and how many variants per intent.
func Generate(value string, vtype ValueType, opts *GenerateOptions) MutationSet {
	if opts == nil {
		opts = DefaultGenerateOptions()
	}
	if opts.MaxPerIntent <= 0 {
		opts.MaxPerIntent = 5
	}

	ms := MutationSet{
		OriginalValue: value,
		DetectedType:  vtype,
	}

	var generators []func(string, *GenerateOptions) []Mutation

	switch vtype {
	case TypeInteger:
		generators = append(generators, generateInteger)
	case TypeFloat:
		generators = append(generators, generateFloat)
	case TypeBoolean:
		generators = append(generators, generateBoolean)
	case TypeUUID:
		generators = append(generators, generateUUID)
	case TypeEmail:
		generators = append(generators, generateEmail)
	case TypeTimestamp:
		generators = append(generators, generateTimestamp)
	case TypeDate:
		generators = append(generators, generateDate)
	case TypeIPv4:
		generators = append(generators, generateIPv4)
	case TypeIPv6:
		generators = append(generators, generateIPv6)
	case TypePath:
		generators = append(generators, generatePath)
	case TypeEnum:
		generators = append(generators, generateEnum)
	case TypeSequentialID:
		generators = append(generators, generateSequentialID)
	case TypeStructuredCode:
		generators = append(generators, generateStructuredCode)
	case TypeJWT:
		generators = append(generators, generateJWT)
	case TypeBase64:
		generators = append(generators, generateBase64)
	case TypeHexEncoded:
		generators = append(generators, generateHexEncoded)
	case TypeURL:
		generators = append(generators, generateURL)
	case TypePhoneNumber:
		generators = append(generators, generatePhoneNumber)
	case TypeCreditCard:
		generators = append(generators, generateCreditCard)
	case TypeSlug:
		generators = append(generators, generateSlug)
	case TypeJSON:
		generators = append(generators, generateJSON)
	case TypeEmpty, TypeUnknown:
		generators = append(generators, generateEmptyUnknown)
	}

	for _, gen := range generators {
		mutations := gen(value, opts)
		ms.Mutations = append(ms.Mutations, mutations...)
	}

	// Deduplicate and remove mutations that equal the original value
	ms.Mutations = dedup(ms.Mutations, value, opts.MaxPerIntent)

	return ms
}

// dedup removes duplicate mutations and those matching the original value,
// enforcing MaxPerIntent limits.
func dedup(mutations []Mutation, original string, maxPerIntent int) []Mutation {
	seen := make(map[string]bool)
	intentCounts := make(map[MutationIntent]int)
	var result []Mutation

	for _, m := range mutations {
		if m.Value == original {
			continue
		}
		key := fmt.Sprintf("%d:%s", m.Intent, m.Value)
		if seen[key] {
			continue
		}
		if intentCounts[m.Intent] >= maxPerIntent {
			continue
		}
		seen[key] = true
		intentCounts[m.Intent]++
		result = append(result, m)
	}
	return result
}

// --- Integer mutations ---

func generateInteger(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return mutations
	}

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: strconv.FormatInt(n+1, 10), Intent: IntentNeighbor, Label: "increment by 1"},
			Mutation{Value: strconv.FormatInt(n-1, 10), Intent: IntentNeighbor, Label: "decrement by 1"},
			Mutation{Value: strconv.FormatInt(n+10, 10), Intent: IntentNeighbor, Label: "increment by 10"},
			Mutation{Value: strconv.FormatInt(n-10, 10), Intent: IntentNeighbor, Label: "decrement by 10"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "0", Intent: IntentBoundary, Label: "zero"},
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "negative one"},
			Mutation{Value: "2147483647", Intent: IntentBoundary, Label: "MAX_INT32"},
			Mutation{Value: "-2147483648", Intent: IntentBoundary, Label: "MIN_INT32"},
		)
		// Schema-aware boundary
		if opts.SchemaHint != nil {
			if opts.SchemaHint.Maximum != nil {
				max := int64(*opts.SchemaHint.Maximum)
				mutations = append(mutations,
					Mutation{Value: strconv.FormatInt(max+1, 10), Intent: IntentBoundary, Label: "above schema max"},
				)
			}
			if opts.SchemaHint.Minimum != nil {
				min := int64(*opts.SchemaHint.Minimum)
				mutations = append(mutations,
					Mutation{Value: strconv.FormatInt(min-1, 10), Intent: IntentBoundary, Label: "below schema min"},
				)
			}
		}
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: strconv.FormatInt(-n, 10), Intent: IntentFormat, Label: "negative flip"},
			Mutation{Value: "0", Intent: IntentFormat, Label: "zeroed"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
			Mutation{Value: "NaN", Intent: IntentEmpty, Label: "NaN"},
		)
	}

	return mutations
}

// --- Float mutations ---

func generateFloat(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return mutations
	}

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: formatFloat(f + 0.01), Intent: IntentNeighbor, Label: "increment by 0.01"},
			Mutation{Value: formatFloat(f - 0.01), Intent: IntentNeighbor, Label: "decrement by 0.01"},
			Mutation{Value: formatFloat(f + 1.0), Intent: IntentNeighbor, Label: "increment by 1.0"},
			Mutation{Value: formatFloat(f - 1.0), Intent: IntentNeighbor, Label: "decrement by 1.0"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "0.0", Intent: IntentBoundary, Label: "zero"},
			Mutation{Value: "-0.01", Intent: IntentBoundary, Label: "small negative"},
			Mutation{Value: "99999.99", Intent: IntentBoundary, Label: "large value"},
			Mutation{Value: "Infinity", Intent: IntentBoundary, Label: "infinity"},
			Mutation{Value: "-Infinity", Intent: IntentBoundary, Label: "negative infinity"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Integer cast
		intVal := int64(f)
		mutations = append(mutations,
			Mutation{Value: strconv.FormatInt(intVal, 10), Intent: IntentFormat, Label: "integer cast"},
			Mutation{Value: strconv.FormatInt(intVal+1, 10), Intent: IntentFormat, Label: "integer cast rounded up"},
			Mutation{Value: fmt.Sprintf("%e", f), Intent: IntentFormat, Label: "scientific notation"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
			Mutation{Value: "NaN", Intent: IntentEmpty, Label: "NaN"},
		)
	}

	return mutations
}

func formatFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// --- Boolean mutations ---

func generateBoolean(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation
	lower := strings.ToLower(value)
	isTruthy := lower == "true" || lower == "yes" || lower == "on" || lower == "1"

	if opts.hasIntent(IntentNeighbor) {
		if isTruthy {
			mutations = append(mutations, Mutation{Value: oppositeBoolean(value), Intent: IntentNeighbor, Label: "opposite value"})
		} else {
			mutations = append(mutations, Mutation{Value: oppositeBoolean(value), Intent: IntentNeighbor, Label: "opposite value"})
		}
	}

	if opts.hasIntent(IntentFormat) {
		if isTruthy {
			mutations = append(mutations,
				Mutation{Value: "0", Intent: IntentFormat, Label: "numeric false"},
				Mutation{Value: "no", Intent: IntentFormat, Label: "no"},
				Mutation{Value: "off", Intent: IntentFormat, Label: "off"},
				Mutation{Value: "FALSE", Intent: IntentFormat, Label: "uppercase FALSE"},
			)
		} else {
			mutations = append(mutations,
				Mutation{Value: "1", Intent: IntentFormat, Label: "numeric true"},
				Mutation{Value: "yes", Intent: IntentFormat, Label: "yes"},
				Mutation{Value: "on", Intent: IntentFormat, Label: "on"},
				Mutation{Value: "TRUE", Intent: IntentFormat, Label: "uppercase TRUE"},
			)
		}
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "2", Intent: IntentBoundary, Label: "non-boolean truthy"},
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "negative truthy"},
			Mutation{Value: "null", Intent: IntentBoundary, Label: "null"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

func oppositeBoolean(value string) string {
	switch strings.ToLower(value) {
	case "true":
		return "false"
	case "false":
		return "true"
	case "yes":
		return "no"
	case "no":
		return "yes"
	case "on":
		return "off"
	case "off":
		return "on"
	case "1":
		return "0"
	case "0":
		return "1"
	default:
		return "false"
	}
}

// --- UUID mutations ---

func generateUUID(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Flip last byte
		if len(value) >= 36 {
			lastChar := value[len(value)-1]
			var flipped byte
			if lastChar == '0' {
				flipped = '1'
			} else {
				flipped = '0'
			}
			mutations = append(mutations,
				Mutation{Value: value[:len(value)-1] + string(flipped), Intent: IntentNeighbor, Label: "last byte flipped"},
			)
		}
		// Random UUID
		newUUID := uuid.New().String()
		mutations = append(mutations,
			Mutation{Value: newUUID, Intent: IntentNeighbor, Label: "random UUID v4"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "00000000-0000-0000-0000-000000000000", Intent: IntentBoundary, Label: "nil UUID"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Without dashes
		noDashes := strings.ReplaceAll(value, "-", "")
		mutations = append(mutations,
			Mutation{Value: noDashes, Intent: IntentFormat, Label: "without dashes"},
			Mutation{Value: strings.ToUpper(value), Intent: IntentFormat, Label: "uppercase"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Email mutations ---

func generateEmail(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return mutations
	}
	local, domain := parts[0], parts[1]

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: local + "+1@" + domain, Intent: IntentNeighbor, Label: "plus addressing +1"},
			Mutation{Value: local + "+test@" + domain, Intent: IntentNeighbor, Label: "plus addressing +test"},
		)
	}

	if opts.hasIntent(IntentEscalation) {
		mutations = append(mutations,
			Mutation{Value: "admin@" + domain, Intent: IntentEscalation, Label: "admin email"},
			Mutation{Value: "root@" + domain, Intent: IntentEscalation, Label: "root email"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: strings.ToUpper(local) + "@" + domain, Intent: IntentFormat, Label: "uppercase local part"},
			Mutation{Value: local + "@sub." + domain, Intent: IntentFormat, Label: "subdomain added"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Timestamp mutations ---

func generateTimestamp(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Attempt to adjust dates. Use simple string manipulation for robustness.
		mutations = append(mutations,
			Mutation{Value: adjustDay(value, -1), Intent: IntentNeighbor, Label: "minus 1 day"},
			Mutation{Value: adjustDay(value, 1), Intent: IntentNeighbor, Label: "plus 1 day"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "1970-01-01T00:00:00Z", Intent: IntentBoundary, Label: "epoch"},
			Mutation{Value: "2099-12-31T23:59:59Z", Intent: IntentBoundary, Label: "far future"},
			Mutation{Value: "2025-12-31T23:59:59Z", Intent: IntentBoundary, Label: "year boundary end"},
			Mutation{Value: "2026-01-01T00:00:00Z", Intent: IntentBoundary, Label: "year boundary start"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: "0", Intent: IntentFormat, Label: "unix epoch zero"},
			Mutation{Value: strings.ReplaceAll(strings.TrimSuffix(value, "Z"), "T", " "), Intent: IntentFormat, Label: "space-separated no TZ"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Date mutations ---

func generateDate(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: adjustDay(value, -1), Intent: IntentNeighbor, Label: "minus 1 day"},
			Mutation{Value: adjustDay(value, 1), Intent: IntentNeighbor, Label: "plus 1 day"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "1970-01-01", Intent: IntentBoundary, Label: "epoch date"},
			Mutation{Value: "2099-12-31", Intent: IntentBoundary, Label: "far future"},
			Mutation{Value: "2025-12-31", Intent: IntentBoundary, Label: "year boundary end"},
			Mutation{Value: "2026-01-01", Intent: IntentBoundary, Label: "year boundary start"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Different date format
		parts := strings.Split(value, "-")
		if len(parts) == 3 {
			mutations = append(mutations,
				Mutation{Value: parts[1] + "/" + parts[2] + "/" + parts[0], Intent: IntentFormat, Label: "MM/DD/YYYY format"},
				Mutation{Value: parts[2] + "." + parts[1] + "." + parts[0], Intent: IntentFormat, Label: "DD.MM.YYYY format"},
			)
		}
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// adjustDay does a simple day adjustment on ISO date strings.
func adjustDay(value string, delta int) string {
	// Parse YYYY-MM-DD from start of value
	if len(value) < 10 {
		return value
	}
	datePart := value[:10]
	rest := value[10:]

	parts := strings.Split(datePart, "-")
	if len(parts) != 3 {
		return value
	}
	year, _ := strconv.Atoi(parts[0])
	month, _ := strconv.Atoi(parts[1])
	day, _ := strconv.Atoi(parts[2])

	day += delta
	if day < 1 {
		month--
		if month < 1 {
			month = 12
			year--
		}
		day = daysInMonth(year, month)
	} else if day > daysInMonth(year, month) {
		day = 1
		month++
		if month > 12 {
			month = 1
			year++
		}
	}
	return fmt.Sprintf("%04d-%02d-%02d%s", year, month, day, rest)
}

func daysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
			return 31
	case 4, 6, 9, 11:
		// What hapends if the number of days of these months is 31?
		// We set the ratio to 20% for the above case
		if rand.Float32() > 0.2 {
			return 30
		} else {
			return 31
		}
	case 2:
		// The same as the case of the months 4, 6, 9, 11
		// We still set the ratio is 20%
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			if rand.Float32() > 0.2 {
				return 29
			} else {
				return 30
			}
		} else if rand.Float32() > 0.2 {
			return 28
		} else {
			return 29
		}
	}
	return 30
}

// --- IPv4 mutations ---

func generateIPv4(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return mutations
	}
	lastOctet, _ := strconv.Atoi(parts[3])

	if opts.hasIntent(IntentNeighbor) {
		if lastOctet < 255 {
			mutations = append(mutations,
				Mutation{Value: parts[0] + "." + parts[1] + "." + parts[2] + "." + strconv.Itoa(lastOctet+1), Intent: IntentNeighbor, Label: "last octet +1"},
			)
		}
		if lastOctet > 0 {
			mutations = append(mutations,
				Mutation{Value: parts[0] + "." + parts[1] + "." + parts[2] + "." + strconv.Itoa(lastOctet-1), Intent: IntentNeighbor, Label: "last octet -1"},
			)
		}
	}

	if opts.hasIntent(IntentEscalation) {
		mutations = append(mutations,
			Mutation{Value: "127.0.0.1", Intent: IntentEscalation, Label: "localhost"},
			Mutation{Value: "10.0.0.1", Intent: IntentEscalation, Label: "internal 10.x"},
			Mutation{Value: "0.0.0.0", Intent: IntentEscalation, Label: "all interfaces"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "255.255.255.255", Intent: IntentBoundary, Label: "broadcast"},
			Mutation{Value: parts[0] + "." + parts[1] + "." + parts[2] + ".255", Intent: IntentBoundary, Label: "subnet broadcast"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Decimal encoding
		octets := make([]int, 4)
		for i, p := range parts {
			octets[i], _ = strconv.Atoi(p)
		}
		decimal := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
		mutations = append(mutations,
			Mutation{Value: strconv.FormatUint(uint64(decimal), 10), Intent: IntentFormat, Label: "decimal encoding"},
			Mutation{Value: fmt.Sprintf("0x%08X", decimal), Intent: IntentFormat, Label: "hex encoding"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- IPv6 mutations ---

func generateIPv6(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: "::2", Intent: IntentNeighbor, Label: "::2"},
		)
	}

	if opts.hasIntent(IntentEscalation) {
		mutations = append(mutations,
			Mutation{Value: "::1", Intent: IntentEscalation, Label: "IPv6 localhost"},
			Mutation{Value: "::", Intent: IntentEscalation, Label: "IPv6 unspecified"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Intent: IntentBoundary, Label: "max IPv6"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: "::ffff:" + value, Intent: IntentFormat, Label: "IPv4-mapped IPv6"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Path mutations ---

func generatePath(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Version increment
		for _, old := range []string{"/v1/", "/v2/", "/v3/"} {
			if strings.Contains(value, old) {
				newVer := strings.Replace(old, old[2:3], nextChar(old[2]), 1)
				mutations = append(mutations,
					Mutation{Value: strings.Replace(value, old, newVer, 1), Intent: IntentNeighbor, Label: "version increment"},
				)
				break
			}
		}
	}

	if opts.hasIntent(IntentEscalation) {
		// Replace common resource names
		for _, resource := range []string{"users", "accounts", "items", "orders"} {
			if strings.Contains(value, "/"+resource) {
				mutations = append(mutations,
					Mutation{Value: strings.Replace(value, "/"+resource, "/admins", 1), Intent: IntentEscalation, Label: "admin resource swap"},
				)
				break
			}
		}
		mutations = append(mutations,
			Mutation{Value: "/admin" + value, Intent: IntentEscalation, Label: "admin prefix"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: value + "/", Intent: IntentFormat, Label: "trailing slash"},
			Mutation{Value: value + ".json", Intent: IntentFormat, Label: "JSON extension"},
			Mutation{Value: value + ".xml", Intent: IntentFormat, Label: "XML extension"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: value + "/..", Intent: IntentBoundary, Label: "path traversal"},
			Mutation{Value: value + "/%2e%2e", Intent: IntentBoundary, Label: "encoded path traversal"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "/", Intent: IntentEmpty, Label: "root path"},
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
		)
	}

	return mutations
}

func nextChar(b byte) string {
	if b >= '1' && b <= '8' {
		return string(b + 1)
	}
	return string(b)
}

// --- Sequential ID mutations ---

func generateSequentialID(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return mutations
	}

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: strconv.FormatInt(n+1, 10), Intent: IntentNeighbor, Label: "increment by 1"},
			Mutation{Value: strconv.FormatInt(n-1, 10), Intent: IntentNeighbor, Label: "decrement by 1"},
			Mutation{Value: strconv.FormatInt(n+10, 10), Intent: IntentNeighbor, Label: "increment by 10"},
			Mutation{Value: strconv.FormatInt(n-10, 10), Intent: IntentNeighbor, Label: "decrement by 10"},
		)
	}

	if opts.hasIntent(IntentEscalation) {
		mutations = append(mutations,
			Mutation{Value: "1", Intent: IntentEscalation, Label: "ID=1 (often admin)"},
			Mutation{Value: "0", Intent: IntentEscalation, Label: "ID=0"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "999999", Intent: IntentBoundary, Label: "very large ID"},
			Mutation{Value: "2147483647", Intent: IntentBoundary, Label: "MAX_INT32"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: fmt.Sprintf("0x%X", n), Intent: IntentFormat, Label: "hex format"},
			Mutation{Value: fmt.Sprintf("%06d", n), Intent: IntentFormat, Label: "zero-padded"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
			Mutation{Value: "-1", Intent: IntentEmpty, Label: "negative one"},
		)
	}

	return mutations
}

// --- Structured code mutations ---

func generateStructuredCode(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	// Parse prefix and numeric parts
	dashIdx := strings.Index(value, "-")
	if dashIdx < 0 {
		return mutations
	}
	prefix := value[:dashIdx]
	numPart := value[dashIdx+1:]

	// Handle multi-segment codes like INV-2024-001
	segments := strings.Split(numPart, "-")
	lastSegment := segments[len(segments)-1]

	n, err := strconv.ParseInt(lastSegment, 10, 64)
	if err != nil {
		return mutations
	}
	width := len(lastSegment)

	if opts.hasIntent(IntentNeighbor) {
		mutations = append(mutations,
			Mutation{Value: rebuildCode(prefix, segments, n-1, width), Intent: IntentNeighbor, Label: "decrement numeric part"},
			Mutation{Value: rebuildCode(prefix, segments, n+1, width), Intent: IntentNeighbor, Label: "increment numeric part"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: rebuildCode(prefix, segments, 0, width), Intent: IntentBoundary, Label: "numeric part zeroed"},
			Mutation{Value: rebuildCode(prefix, segments, int64(math.Pow10(width))-1, width), Intent: IntentBoundary, Label: "numeric part maxed"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Different prefix
		altPrefixes := []string{"ADM", "INV", "USR", "SYS"}
		for _, alt := range altPrefixes {
			if alt != prefix {
				mutations = append(mutations,
					Mutation{Value: alt + value[dashIdx:], Intent: IntentFormat, Label: "prefix swap to " + alt},
				)
				break
			}
		}
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

func rebuildCode(prefix string, segments []string, newNum int64, width int) string {
	var b strings.Builder
	b.WriteString(prefix)
	for i, seg := range segments {
		b.WriteByte('-')
		if i == len(segments)-1 {
			fmt.Fprintf(&b, "%0*d", width, newNum)
		} else {
			b.WriteString(seg)
		}
	}
	return b.String()
}

// --- Enum mutations ---

// commonEnumEscalation maps known enum-like values to their escalation counterparts.
var commonEnumEscalation = map[string][]string{
	"enabled":  {"disabled"},
	"disabled": {"enabled"},
	"active":   {"inactive", "suspended", "deleted"},
	"inactive": {"active"},
	"public":   {"private", "internal"},
	"private":  {"public"},
	"user":     {"admin", "superadmin", "root"},
	"viewer":   {"editor", "owner", "admin"},
	"editor":   {"admin", "owner"},
	"read":     {"write", "admin", "execute"},
	"write":    {"admin", "execute"},
	"draft":    {"published", "approved"},
	"pending":  {"approved", "completed"},
	"allow":    {"deny", "block"},
	"deny":     {"allow"},
	"standard": {"premium", "enterprise"},
	"basic":    {"premium", "enterprise", "admin"},
	"free":     {"premium", "enterprise", "pro"},
	"low":      {"high", "critical"},
	"medium":   {"high", "critical"},
	"high":     {"critical"},
}

func generateEnum(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) && opts.SchemaHint != nil && len(opts.SchemaHint.Enum) > 0 {
		// Find adjacent enum values
		enumVals := opts.SchemaHint.Enum
		for i, e := range enumVals {
			if e == value {
				if i+1 < len(enumVals) {
					mutations = append(mutations, Mutation{Value: enumVals[i+1], Intent: IntentNeighbor, Label: "next enum value"})
				}
				if i > 0 {
					mutations = append(mutations, Mutation{Value: enumVals[i-1], Intent: IntentNeighbor, Label: "previous enum value"})
				}
				break
			}
		}
	}

	if opts.hasIntent(IntentBoundary) && opts.SchemaHint != nil && len(opts.SchemaHint.Enum) > 0 {
		enumVals := opts.SchemaHint.Enum
		if len(enumVals) > 0 {
			mutations = append(mutations,
				Mutation{Value: enumVals[0], Intent: IntentBoundary, Label: "first enum value"},
				Mutation{Value: enumVals[len(enumVals)-1], Intent: IntentBoundary, Label: "last enum value"},
			)
		}
	}

	if opts.hasIntent(IntentEscalation) {
		lower := strings.ToLower(value)
		if escalations, ok := commonEnumEscalation[lower]; ok {
			for _, esc := range escalations {
				mutations = append(mutations,
					Mutation{Value: esc, Intent: IntentEscalation, Label: "escalation: " + esc},
				)
			}
		}
	}

	if opts.hasIntent(IntentFormat) {
		upper := strings.ToUpper(value)
		title := strings.ToUpper(value[:1]) + strings.ToLower(value[1:])
		mutations = append(mutations,
			Mutation{Value: upper, Intent: IntentFormat, Label: "uppercase"},
			Mutation{Value: title, Intent: IntentFormat, Label: "title case"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- URL mutations ---

func generateURL(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentEscalation) {
		mutations = append(mutations,
			Mutation{Value: "http://127.0.0.1/", Intent: IntentEscalation, Label: "localhost"},
			Mutation{Value: "http://localhost/", Intent: IntentEscalation, Label: "localhost hostname"},
			Mutation{Value: "http://169.254.169.254/", Intent: IntentEscalation, Label: "cloud metadata"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		if strings.HasPrefix(value, "https://") {
			mutations = append(mutations,
				Mutation{Value: "http://" + value[8:], Intent: IntentFormat, Label: "protocol downgrade"},
			)
		} else if strings.HasPrefix(value, "http://") {
			mutations = append(mutations,
				Mutation{Value: "https://" + value[7:], Intent: IntentFormat, Label: "protocol upgrade"},
			)
		}
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- JWT mutations ---

func generateJWT(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentFormat) {
		// alg:none token
		algNoneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		parts := strings.Split(value, ".")
		if len(parts) == 3 {
			mutations = append(mutations,
				Mutation{Value: algNoneHeader + "." + parts[1] + ".", Intent: IntentFormat, Label: "alg:none attack"},
			)
		}
	}

	if opts.hasIntent(IntentBoundary) {
		// Empty payload
		emptyPayload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		algNone := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		mutations = append(mutations,
			Mutation{Value: algNone + "." + emptyPayload + ".", Intent: IntentBoundary, Label: "empty payload"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Base64 mutations ---

func generateBase64(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Decode → classify inner → mutate → re-encode
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(value)
		}
		if err == nil && len(decoded) > 0 {
			inner := string(decoded)
			innerType := Classify(inner, nil)
			if innerType != TypeUnknown && innerType != TypeEmpty {
				innerMutations := Generate(inner, innerType, &GenerateOptions{
					Intents:      []MutationIntent{IntentNeighbor},
					MaxPerIntent: 2,
				})
				for _, m := range innerMutations.Mutations {
					encoded := base64.StdEncoding.EncodeToString([]byte(m.Value))
					mutations = append(mutations,
						Mutation{Value: encoded, Intent: IntentNeighbor, Label: "inner " + m.Label + " re-encoded"},
					)
				}
			}
		}
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentBoundary, Label: "empty"},
			Mutation{Value: "AA==", Intent: IntentBoundary, Label: "minimal base64"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Hex-encoded mutations ---

func generateHexEncoded(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Flip last byte
		if len(value) >= 2 {
			lastByte := value[len(value)-2:]
			n, err := strconv.ParseUint(lastByte, 16, 8)
			if err == nil {
				flipped := fmt.Sprintf("%02x", (n+1)&0xFF)
				mutations = append(mutations,
					Mutation{Value: value[:len(value)-2] + flipped, Intent: IntentNeighbor, Label: "last byte +1"},
				)
			}
		}
	}

	if opts.hasIntent(IntentFormat) {
		mutations = append(mutations,
			Mutation{Value: strings.ToUpper(value), Intent: IntentFormat, Label: "uppercase hex"},
		)
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: strings.Repeat("00", len(value)/2), Intent: IntentBoundary, Label: "all zeros"},
			Mutation{Value: strings.Repeat("ff", len(value)/2), Intent: IntentBoundary, Label: "all ff"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Phone number mutations ---

func generatePhoneNumber(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Increment last digit
		runes := []rune(value)
		for i := len(runes) - 1; i >= 0; i-- {
			if runes[i] >= '0' && runes[i] <= '8' {
				modified := make([]rune, len(runes))
				copy(modified, runes)
				modified[i]++
				mutations = append(mutations,
					Mutation{Value: string(modified), Intent: IntentNeighbor, Label: "last digit +1"},
				)
				break
			}
		}
	}

	if opts.hasIntent(IntentFormat) {
		// Strip formatting
		stripped := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' || r == '+' {
				return r
			}
			return -1
		}, value)
		mutations = append(mutations,
			Mutation{Value: stripped, Intent: IntentFormat, Label: "stripped formatting"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Credit card mutations ---

func generateCreditCard(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: strings.Repeat("0", len(value)), Intent: IntentBoundary, Label: "all zeros"},
			Mutation{Value: "4111111111111111", Intent: IntentBoundary, Label: "test Visa number"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Add dashes
		if len(value) == 16 {
			mutations = append(mutations,
				Mutation{Value: value[:4] + "-" + value[4:8] + "-" + value[8:12] + "-" + value[12:], Intent: IntentFormat, Label: "dash-separated"},
			)
		}
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Slug mutations ---

func generateSlug(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentNeighbor) {
		// Append number
		mutations = append(mutations,
			Mutation{Value: value + "-2", Intent: IntentNeighbor, Label: "appended -2"},
		)
	}

	if opts.hasIntent(IntentEscalation) {
		mutations = append(mutations,
			Mutation{Value: "admin", Intent: IntentEscalation, Label: "admin slug"},
			Mutation{Value: "admin-panel", Intent: IntentEscalation, Label: "admin-panel slug"},
		)
	}

	if opts.hasIntent(IntentFormat) {
		// Swap separator
		if strings.Contains(value, "-") {
			mutations = append(mutations,
				Mutation{Value: strings.ReplaceAll(value, "-", "_"), Intent: IntentFormat, Label: "underscore separator"},
			)
		} else if strings.Contains(value, "_") {
			mutations = append(mutations,
				Mutation{Value: strings.ReplaceAll(value, "_", "-"), Intent: IntentFormat, Label: "dash separator"},
			)
		}
		mutations = append(mutations,
			Mutation{Value: strings.ToUpper(value), Intent: IntentFormat, Label: "uppercase"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- JSON mutations ---

func generateJSON(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentFormat) {
		// Try to add admin:true to objects
		var obj map[string]any
		if json.Unmarshal([]byte(value), &obj) == nil {
			obj["admin"] = true
			if injected, err := json.Marshal(obj); err == nil {
				mutations = append(mutations,
					Mutation{Value: string(injected), Intent: IntentFormat, Label: "admin:true injected"},
				)
			}
			// Type confusion: convert first string value to bool
			for k, v := range obj {
				if _, ok := v.(string); ok {
					obj[k] = true
					if confused, err := json.Marshal(obj); err == nil {
						mutations = append(mutations,
							Mutation{Value: string(confused), Intent: IntentFormat, Label: "type confusion: string→bool"},
						)
					}
					break
				}
			}
		}
	}

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "{}", Intent: IntentBoundary, Label: "empty object"},
			Mutation{Value: "[]", Intent: IntentBoundary, Label: "empty array"},
		)
	}

	if opts.hasIntent(IntentEmpty) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}

	return mutations
}

// --- Empty/Unknown mutations ---

func generateEmptyUnknown(value string, opts *GenerateOptions) []Mutation {
	var mutations []Mutation

	if opts.hasIntent(IntentBoundary) {
		mutations = append(mutations,
			Mutation{Value: "", Intent: IntentBoundary, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentBoundary, Label: "null"},
			Mutation{Value: "undefined", Intent: IntentBoundary, Label: "undefined"},
			Mutation{Value: "NaN", Intent: IntentBoundary, Label: "NaN"},
			Mutation{Value: "[]", Intent: IntentBoundary, Label: "empty array"},
			Mutation{Value: "{}", Intent: IntentBoundary, Label: "empty object"},
			Mutation{Value: "0", Intent: IntentBoundary, Label: "zero"},
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "negative one"},
			Mutation{Value: "true", Intent: IntentBoundary, Label: "boolean true"},
			Mutation{Value: "false", Intent: IntentBoundary, Label: "boolean false"},
		)
	}

	return mutations
}
