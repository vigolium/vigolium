package utils

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unsafe"

	"github.com/samber/lo"
)

// Truthy reports whether s reads as a positive boolean flag — case-insensitive
// "1", "true", "yes", "on". Used for env-var and CLI-token parsing where the
// no/false form is conventionally absence.
func Truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// EnvTruthy reads os.Getenv(name) through Truthy. Empty / unset / unrecognized
// returns false.
func EnvTruthy(name string) bool {
	return Truthy(os.Getenv(name))
}

//go:embed assets/*
var assetsFS embed.FS

// GetFileByName retrieves the content of a file from the embedded assets by its name.
func GetFileByName(filename string) (string, error) {
	data, err := fs.ReadFile(assetsFS, "assets/"+filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// RandomFromChoices 从choices里面随机获取
func RandomFromChoices(n int, choices string) string {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, r.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = r.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(choices) {
			b[i] = choices[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func UnwrapError(err error) error {
	for { // get the last wrapped error
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			break
		}
		err = unwrapped
	}
	return err
}

// IsURL tests a string to determine if it is a well-structured url or not.
func IsURL(input string) bool {
	u, err := url.Parse(input)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// StringSliceContains checks if a string slice contains a string.
func StringSliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}

const (
	NUMBER_CHARSET = "123456789" // remove 0 to make sure it is not confused with O
	START_CHARSET  = "ghijklmnopqrstuvwxyz"
	CHARSET        = "0123456789abcdefghijklmnopqrstuvwxyz"
	HEX_CHARSET    = "0123456789abcdef"
)

// RandomNumber returns a random number with the specified length
func RandomNumber(length int) string {
	if length == 0 {
		length = 1
	}
	result := make([]byte, length)
	for i := range result {
		result[i] = NUMBER_CHARSET[rand.Intn(len(NUMBER_CHARSET))]
	}
	return string(result)
}
func RandomNumberInRange(from, to int) string {
	if from == to {
		return strconv.Itoa(from)
	}
	if from > to {
		from, to = to, from
	}
	return strconv.Itoa(rand.Intn(to-from+1) + from)
}

func RandomString(length int) string {
	if length == 0 {
		length = 1
	}
	result := make([]byte, length)
	result[0] = START_CHARSET[rand.Intn(len(START_CHARSET))]
	for i := 1; i < length; i++ {
		result[i] = CHARSET[rand.Intn(len(CHARSET))]
	}
	return string(result)
}

func RandomUpper(s string) string {
	r := []rune(s)
	for {
		pos := rand.Intn(len(r))
		if unicode.IsLower(r[pos]) {
			r[pos] = unicode.ToUpper(r[pos])
			break
		} else if unicode.IsUpper(r[pos]) {
			r[pos] = unicode.ToLower(r[pos])
			break
		}
	}

	for i := 0; i < len(r); i++ {
		if !unicode.IsLetter(r[i]) {
			continue
		}
		if rand.Intn(2) == 0 {
			r[i] = unicode.ToLower(r[i])
		} else {
			r[i] = unicode.ToUpper(r[i])
		}
	}
	return string(r)
}

var reGetExtName = regexp.MustCompile(`\.([0-9a-zA-Z]+)(\?|#|$)`)
var mediaRegex = regexp.MustCompile(
	`^(woff|woff2|ttf|eot|otf|svg|mp4|webm|ogg|mkv|flv|avi|mov|wmv|css|jpg|jpeg|png|gif|bmp|webp|js|ico|pdf|mp3|m3u8)$`,
)
var mediaAndJSRegex = regexp.MustCompile(
	`^(woff|woff2|ttf|eot|otf|svg|mp4|webm|ogg|mkv|flv|avi|mov|wmv|css|jpg|jpeg|png|gif|bmp|webp|js|ico|pdf|mp3|m3u8|js|json|zip|tar.gz|exe|gz|rar)$`,
)

// IsMediaAndJSURL checks if a URL is a media or JS file
// return true if it is a media or JS file
func IsMediaAndJSURL(url string) bool {
	ext := GetExtensionOfPath(url)
	return mediaAndJSRegex.MatchString(ext)
}

func IsMediaURL(url string) bool {
	ext := GetExtensionOfPath(url)
	return mediaRegex.MatchString(ext)
}

func GetExtensionOfPath(url string) string {
	matches := reGetExtName.FindStringSubmatch(url)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}
	return ""
}

func BasicEncodeParam(payload string) string {
	replacer := strings.NewReplacer(
		"%", "%25",
		"\u0000", "%00",
		"&", "%26",
		"#", "%23",
		"\u0020", "%20",
		";", "%3b",
		"+", "%2b",
		"\n", "%0A",
		"\r", "%0d",
	)
	return replacer.Replace(payload)
}
func GenerateCanary() string {
	return RandomString(4+rand.Intn(7)) + RandomNumber(1)
}

// GetPathFromRequest returns the path from a request INCLUDE QUERY ALSO
func GetPathFromRequest(request []byte) string {
	// i := 0
	recording := false
	builder := strings.Builder{}
	for _, currentChar := range request {
		if recording {
			if currentChar == ' ' {
				break
			}
			builder.WriteByte(currentChar)
		} else if currentChar == ' ' {
			recording = true
		}
	}
	return builder.String()
}
func b2s(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func ReplaceFirst(request []byte, find []byte, replace []byte) []byte {
	return bytes.Replace(request, find, replace, 1)
}

func Replace(request []byte, find []byte, replace []byte) []byte {
	return bytes.ReplaceAll(request, find, replace)
}

func AppendToQuery(request []byte, suffix string) []byte {
	path := GetPathFromRequest(request)
	if strings.Contains(path, "?") {
		if strings.Index(path, "?") == len(path)-1 {

		} else {
			suffix = "&" + suffix
		}
	} else {
		suffix = "?" + suffix
	}
	return ReplaceFirst(request, s2b(path), s2b(path+suffix))
}

func SetHeader(request []byte, header string, value string) []byte {
	offsets := GetHeaderOffsets(request, header)
	if offsets == nil {
		return request
	}
	buffer := bytes.Buffer{}
	buffer.Write(request[:offsets[1]])
	buffer.WriteString(value)
	buffer.Write(request[offsets[2]:])
	return buffer.Bytes()
}

func AddOrReplaceHeader(request []byte, header string, value string) []byte {
	offsets := GetHeaderOffsets(request, header)
	if offsets != nil {
		return SetHeader(request, header, value)
	}
	return ReplaceFirst(request, s2b("\r\n\r\n"), s2b("\r\n"+header+": "+value+"\r\n\r\n"))
}

func AppendToHeader(request []byte, header, value string) []byte {
	baseValue := GetHeader(request, header)
	if baseValue == "" {
		return request
	}
	return AddOrReplaceHeader(request, header, baseValue+value)
}

func GetBodyStart(response []byte) int {
	if len(response) == 0 {
		return 0
	}
	i := 0
	newLineSeen := 0

	for i < len(response) {
		currentChar := response[i]
		if currentChar == '\n' {
			newLineSeen++
		} else if currentChar != '\r' {
			newLineSeen = 0
		}

		if newLineSeen == 2 {
			i += 1
			break
		}
		i += 1
	}
	return i
}

// GetHeaderOffsets return the offsets of the headers in the request/response
//
// the header name is case-insensitive
func GetHeaderOffsets(request []byte, header string) []int {
	if len(request) == 0 {
		return nil
	}
	i := 0
	end := GetBodyStart(request)

	for i < end {
		lineStart := i
		i += 1 // allow headers starting with whitespace

		for ; i < end && request[i] != ' '; i++ {
		}

		nameStart := lineStart + 1
		nameEnd := i - 1
		if nameStart > nameEnd {
			nameStart = nameEnd
		}
		headerName := request[nameStart:nameEnd]

		headerValueStart := i + 1
		for i < end && request[i] != ' ' {
			i++
		}

		if i == end {
			break
		}

		headerNameStr := b2s(headerName)
		headerValueEnd := i - 1
		if headerValueStart > headerValueEnd {
			headerValueStart = headerValueEnd
		}

		if strings.EqualFold(headerNameStr, header) {
			return []int{lineStart, headerValueStart, headerValueEnd}
		}

		if i+2 < end && request[i] == '\r' && request[i+1] == '\n' {
			break
		}
	}
	return nil
}

func GetHeader(request []byte, header string) string {
	if len(request) == 0 {
		return ""
	}
	offsets := GetHeaderOffsets(request, header)
	if offsets == nil {
		return ""
	}
	return b2s(request[offsets[1]:offsets[2]])
}

func AddCacheBuster(request []byte, cacheBuster string) []byte {
	if cacheBuster != "" {
		request = AppendToQuery(request, cacheBuster+"=1")
	} else {
		cacheBuster = GenerateCanary()
	}
	request = AppendToHeader(request, "Accept", ", text/"+cacheBuster)
	request = AppendToHeader(request, "Accept-Encoding", ", "+cacheBuster)
	request = AppendToHeader(request, "User-Agent", " "+cacheBuster)
	return request
}

func SplitPathRecursive(input string) []string {
	if input == "" {
		return []string{}
	}
	basePath := path.Dir(input)

	var finalParts []string
	var seen []string
	for _, part := range strings.Split(basePath, "/") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		seen = append(seen, part)
		finalParts = append(finalParts, strings.Join(seen, "/"))
	}
	return finalParts
}

func EscapeJSONString(input string) string {
	var buf bytes.Buffer
	for _, char := range input {
		switch char {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if char < 32 {
				buf.WriteString(`\u00`)
				buf.WriteByte(HEX_CHARSET[char>>4])
				buf.WriteByte(HEX_CHARSET[char&0xF])
			} else {
				buf.WriteRune(char)
			}
		}
	}
	return buf.String()
}
func MD5Enc(input string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(input)))
}

func Sha1(input string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(input)))
}

// StructToJsonString 将结构体输出位 json 字符
func StructToJsonString(item interface{}) string {
	jsonBytes, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		panic(err)
	}

	return string(jsonBytes)
}

func IsNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}

// MightBeOrderBy checks if the given name or value suggests an 'order by' or 'sort' operation
func MightBeOrderBy(name, value string) bool {
	nameLower := strings.ToLower(name)
	valueLower := strings.ToLower(value)

	return strings.Contains(nameLower, "order") ||
		strings.Contains(nameLower, "sort") ||
		valueLower == "asc" ||
		valueLower == "desc" ||
		(IsNumeric(value) && toFloat(value) <= 1000) ||
		(len(value) < 20 && isAlpha(value))
}

// toFloat converts a string to a float64
func toFloat(value string) float64 {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return f
}

// isAlpha checks if the string contains only alphabetic characters
func isAlpha(value string) bool {
	for _, r := range value {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// MightBeIdentifier checks if the string is a possible identifier based on specific allowed characters
func MightBeIdentifier(value string) bool {
	for _, x := range value {
		if !unicode.IsLetter(x) && !unicode.IsDigit(x) && x != '.' && x != '-' && x != '_' && x != ':' && x != '$' {
			return false
		}
	}
	return true
}

var phpFunctions []string

func MightBeFunction(value string) bool {
	if phpFunctions == nil {
		rawData, err := GetFileByName("php_functions.txt")
		if err != nil {
			return false
		}
		scanner := bufio.NewScanner(strings.NewReader(rawData))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			phpFunctions = append(phpFunctions, line)
		}
	}
	return lo.Contains(phpFunctions, value)
}

func GetCertificateFromHostname(host string) []string {
	if host == "" {
		return []string{}
	}
	hostname, port, _ := net.SplitHostPort(host)
	if hostname == "" {
		hostname = host
	}
	if port == "" {
		port = "443"
	}

	conn, err := tls.Dial("tcp", hostname+":"+port, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return []string{}
	}
	defer func() { _ = conn.Close() }()

	certs, _, err := serverCert(hostname, port)
	if err != nil {
		return []string{}
	}
	if len(certs) == 0 {
		return []string{}
	}
	cert := certs[0]

	return cert.DNSNames
}

var serverCert = func(host, port string) ([]*x509.Certificate, string, error) {
	d := &net.Dialer{
		Timeout: time.Duration(5) * time.Second,
	}

	conn, err := tls.DialWithDialer(d, "tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       nil,
		MaxVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return []*x509.Certificate{{}}, "", err
	}
	defer func() { _ = conn.Close() }()

	addr := conn.RemoteAddr()
	ip, _, _ := net.SplitHostPort(addr.String())
	cert := conn.ConnectionState().PeerCertificates

	return cert, ip, nil
}
