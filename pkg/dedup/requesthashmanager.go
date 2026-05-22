package dedup

import (
	"hash/fnv"
	"strconv"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Option configures which request components are included in the hash.
type Option struct {
	Method                 bool
	Host                   bool
	Path                   bool
	InjectingParamName     bool
	InjectingParamValue    bool
	InjectingParamPosition bool
	Body                   bool
	AllParamKeys           bool
	AllParamKV             bool
}

// DefaultOption provides sensible defaults for request hashing.
var DefaultOption = Option{
	Method:                 true,
	Host:                   true,
	Path:                   true,
	InjectingParamName:     true,
	InjectingParamPosition: true,
	AllParamKeys:           true,

	InjectingParamValue: false,
	AllParamKV:          false,
	Body:                false,
}

// RequestHashManager provides deduplication for HTTP requests.
type RequestHashManager struct {
	diskSet *DiskSet
	option  Option
}

func newRequestHashManager(option Option) (*RequestHashManager, error) {
	ds, err := NewDiskSet(DefaultDiskSetOptions)
	if err != nil {
		return nil, err
	}
	return &RequestHashManager{diskSet: ds, option: option}, nil
}

// GetNotCheckedParams filters parameters to only include those not yet checked.
func (m *RequestHashManager) GetNotCheckedParams(
	urlx *urlutil.URL,
	request *httpmsg.HttpRequest,
	params []*httpmsg.Param,
) []*httpmsg.Param {
	var notCheckedParams []*httpmsg.Param
	if len(params) == 0 {
		return notCheckedParams
	}
	for _, param := range params {
		if m.ShouldCheck(urlx, request, param) {
			notCheckedParams = append(notCheckedParams, param)
		}
	}
	return notCheckedParams
}

// ShouldCheck returns true if the request does not exist in the data (should check).
func (m *RequestHashManager) ShouldCheck(
	urlx *urlutil.URL,
	request *httpmsg.HttpRequest,
	param *httpmsg.Param,
) bool {
	return !m.hasOrAdd(urlx, request, param, "")
}

// ShouldCheck2 returns true if the request should be checked with method override.
func (m *RequestHashManager) ShouldCheck2(
	urlx *urlutil.URL,
	request *httpmsg.HttpRequest,
	param *httpmsg.Param,
	overwriteMethod string,
) bool {
	return !m.hasOrAdd(urlx, request, param, overwriteMethod)
}

// ShouldCheck3 returns true if the request should be checked with direct parameters.
func (m *RequestHashManager) ShouldCheck3(
	urlx *urlutil.URL,
	method, body, paramName, paramValue, paramPosition string,
) bool {
	rHash := m.hash(urlx, method, body, paramName, paramValue, paramPosition)
	return !m.diskSet.IsSeen(rHash)
}

// GetNotCheckedInsertionPoints filters insertion points to only include those not yet checked.
func (m *RequestHashManager) GetNotCheckedInsertionPoints(
	urlx *urlutil.URL,
	request *httpmsg.HttpRequest,
	points []httpmsg.InsertionPoint,
) []httpmsg.InsertionPoint {
	var notChecked []httpmsg.InsertionPoint
	if len(points) == 0 {
		return notChecked
	}
	for _, ip := range points {
		paramType := strconv.Itoa(int(ip.Type()))
		if m.ShouldCheckInsertionPoint(urlx, request, ip.Name(), ip.BaseValue(), paramType) {
			notChecked = append(notChecked, ip)
		}
	}
	return notChecked
}

// ShouldCheckInsertionPoint returns true if the insertion point should be checked.
func (m *RequestHashManager) ShouldCheckInsertionPoint(
	urlx *urlutil.URL,
	request *httpmsg.HttpRequest,
	paramName, paramValue, paramType string,
) bool {
	rHash := m.hash(urlx, request.Method(), string(request.Body()), paramName, paramValue, paramType)
	return !m.diskSet.IsSeen(rHash)
}

// hasOrAdd returns true if the request exists in the data.
func (m *RequestHashManager) hasOrAdd(
	urlx *urlutil.URL,
	request *httpmsg.HttpRequest,
	param *httpmsg.Param,
	overwriteMethod string,
) bool {
	method := request.Method()
	if overwriteMethod != "" {
		method = overwriteMethod
	}
	var paramName, paramValue, paramPosition string
	if param != nil {
		paramName = param.Name()
		paramValue = param.Value()
		paramPosition = param.Type().String()
	}
	rHash := m.hash(urlx, method, string(request.Body()), paramName, paramValue, paramPosition)
	return m.diskSet.IsSeen(rHash)
}

// Close releases resources.
func (m *RequestHashManager) Close() {
	_ = m.diskSet.Close()
}

func (m *RequestHashManager) hash(
	urlx *urlutil.URL,
	method string,
	body string,
	paramName, paramValue, paramPosition string,
) string {
	h := fnv.New64a()
	if m.option.Method {
		h.Write([]byte(method))
	}
	if m.option.Host {
		h.Write([]byte(urlx.Host))
	}
	if m.option.Path {
		h.Write([]byte(urlx.Path))
	}
	if m.option.InjectingParamName {
		h.Write([]byte(paramName))
	}
	if m.option.InjectingParamValue {
		h.Write([]byte(paramValue))
	}
	if m.option.InjectingParamPosition {
		h.Write([]byte(paramPosition))
	}
	if !m.option.AllParamKV && m.option.AllParamKeys {
		urlx.Params.Iterate(func(key string, value []string) bool {
			h.Write([]byte(key))
			return true
		})
	}
	if m.option.AllParamKV && m.option.AllParamKeys {
		urlx.Params.Iterate(func(key string, value []string) bool {
			h.Write([]byte(key))
			h.Write([]byte("="))
			for _, v := range value {
				h.Write([]byte(v))
			}
			return true
		})
	}
	if m.option.Body {
		h.Write([]byte(body))
	}
	return strconv.FormatUint(h.Sum64(), 16)
}
