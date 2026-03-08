package anomaly

import (
	"net/http"
	"net/url"
	"sync"
)

type FingerprintList struct {
	filters []*Fingerprint
	lock    sync.RWMutex
}

func NewFingerprintList() *FingerprintList {
	return &FingerprintList{
		filters: make([]*Fingerprint, 0),
	}
}

func (fl *FingerprintList) IsUnique(toCompare *Fingerprint, autoAddToFilterList bool) bool {
	fl.lock.Lock()
	defer fl.lock.Unlock()
	similarFingerprintFound := false
	for _, filter := range fl.filters {
		// stop if have at least one similar fingerprint
		if filter.IsSimilar(toCompare) {
			similarFingerprintFound = true
			break
		}
	}

	if autoAddToFilterList && !similarFingerprintFound {
		// fmt.Printf("adding new fingerprint to filter list\n%s\n", toCompare.String())
		fl.filters = append(fl.filters, toCompare)
	}

	return !similarFingerprintFound
}

func (fl *FingerprintList) IsUniqueNoAdd(toCompare *Fingerprint) bool {
	fl.lock.RLock()
	for _, filter := range fl.filters {
		if filter.IsSimilar(toCompare) {
			fl.lock.RUnlock()
			return true
		}
	}
	fl.lock.RUnlock()
	return false
}

func (fl *FingerprintList) AddFingerprint(toAdd *Fingerprint) {
	fl.lock.Lock()
	fl.filters = append(fl.filters, toAdd)
	fl.lock.Unlock()
}

type URLGroup struct {
	data map[int]*FingerprintList
	lock sync.RWMutex
}

func (ug *URLGroup) getOrCreateFingerprintList(statusCode int) *FingerprintList {
	ug.lock.RLock()
	filter, ok := ug.data[statusCode]
	ug.lock.RUnlock()

	if !ok {
		ug.lock.Lock()
		filter, ok = ug.data[statusCode]
		if !ok {
			filter = NewFingerprintList()
			ug.data[statusCode] = filter
		}
		ug.lock.Unlock()
	}
	return filter
}

type URLGroupFilterManager struct {
	data             map[string]*URLGroup // map[rootURL]*URLGroup
	fingerprintTypes []Type
	lock             sync.RWMutex
}

var DefaultFingerprintTypes = []Type{
	STATUS_CODE,
	LINE_COUNT,
	WORD_COUNT,
	CONTENT_TYPE,
	SERVER_HEADER,
	STATUS_CODE_TEXT,
	PAGE_TITLE,
	CSS_CLASSES,
	FIRST_HEADER_TAG,
	HEADER_TAGS,
	DIV_IDS,
	TAG_IDS,
	TAG_NAMES,
	// VISIBLE_TEXT,
	// VISIBLE_WORD_COUNT,
	OUTBOUND_EDGE_TAG_NAMES,
	OUTBOUND_EDGE_COUNT,
	ANCHOR_LABELS,
	INPUT_IMAGE_LABELS,
	INPUT_SUBMIT_LABELS,
	BUTTON_SUBMIT_LABELS,
	NON_HIDDEN_FORM_INPUT_TYPES,
}

func NewURLGroupFilterManager() *URLGroupFilterManager {
	return &URLGroupFilterManager{
		data:             make(map[string]*URLGroup),
		fingerprintTypes: DefaultFingerprintTypes,
	}
}

func NewURLGroupFilterManagerWithFingerprintTypes(fingerprintTypes []Type) *URLGroupFilterManager {
	return &URLGroupFilterManager{
		data:             make(map[string]*URLGroup),
		fingerprintTypes: fingerprintTypes,
	}
}

func (fm *URLGroupFilterManager) getOrCreateURLGroup(rootURL string) *URLGroup {
	fm.lock.RLock()
	urlGroup, ok := fm.data[rootURL]
	fm.lock.RUnlock()

	if !ok {
		fm.lock.Lock()
		urlGroup, ok = fm.data[rootURL]
		if !ok {
			urlGroup = &URLGroup{
				data: make(map[int]*FingerprintList),
			}
			fm.data[rootURL] = urlGroup
		}
		fm.lock.Unlock()
	}
	return urlGroup
}

func (fm *URLGroupFilterManager) IsUnique(resp *http.Response) bool {
	rootURL := getRootURL(resp.Request.URL.String())
	fingerprint := NewFingerprint4(resp, fm.fingerprintTypes)
	urlGroup := fm.getOrCreateURLGroup(rootURL)
	filters := urlGroup.getOrCreateFingerprintList(resp.StatusCode)

	isUnique := filters.IsUnique(fingerprint, true)
	return isUnique
}

func (fm *URLGroupFilterManager) IsUnique2(rawURL string, statusCode int, responseBody string, headers map[string][]string) bool {
	rootURL := getRootURL(rawURL)
	fingerprint := NewFingerprint2(statusCode, responseBody, headers, fm.fingerprintTypes)
	urlGroup := fm.getOrCreateURLGroup(rootURL)
	filters := urlGroup.getOrCreateFingerprintList(statusCode)
	isUnique := filters.IsUnique(fingerprint, true)

	return isUnique
}

func (fm *URLGroupFilterManager) IsUnique3(rawURL string, statusCode int, responseBody string, headers map[string]string) bool {
	rootURL := getRootURL(rawURL)
	fingerprint := NewFingerprint3(statusCode, responseBody, headers, fm.fingerprintTypes)
	urlGroup := fm.getOrCreateURLGroup(rootURL)
	filters := urlGroup.getOrCreateFingerprintList(statusCode)

	isUnique := filters.IsUnique(fingerprint, true)
	return isUnique
}

func getRootURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	return parsedURL.Scheme + "://" + parsedURL.Host
}
