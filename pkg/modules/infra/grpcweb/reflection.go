package grpcweb

import (
	"encoding/binary"
	"errors"
	"sort"
)

// Server reflection (grpc.reflection.v1 / v1alpha ServerReflectionInfo) over
// gRPC-Web, decoded with a hand-written protobuf wire reader. The messages are
// fixed by the reflection protocol and descriptor.proto, and only a handful of
// fields are read, so a wire reader of a few dozen lines replaces linking
// google.golang.org/protobuf (which this package keeps out). Field numbers:
//
//	ServerReflectionRequest   host=1, file_containing_symbol=4, list_services=7
//	ServerReflectionResponse  file_descriptor_response=4, list_services_response=6,
//	                          error_response=7
//	FileDescriptorResponse    file_descriptor_proto=1 (repeated bytes)
//	ListServiceResponse       service=1 (repeated ServiceResponse{name=1})
//	ErrorResponse             error_code=1, error_message=2
//	FileDescriptorProto       name=1, package=2, service=6
//	ServiceDescriptorProto    name=1, method=2
//	MethodDescriptorProto     name=1, input_type=2, output_type=3,
//	                          client_streaming=5, server_streaming=6

// ReflectionPaths are the server-reflection RPC paths, newest first: v1 is the
// stable service, v1alpha the one older servers register.
var ReflectionPaths = []string{
	"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
}

// ReflectionService is one service a reflection catalog names, with the
// methods its file descriptor declares (empty when the descriptor was not
// returned).
type ReflectionService struct {
	Name    string             `json:"name"`
	Methods []ReflectionMethod `json:"methods,omitempty"`
}

// ReflectionMethod is one RPC method from a service descriptor.
type ReflectionMethod struct {
	Name            string `json:"name"`
	Path            string `json:"path"` // "/package.Service/Method"
	InputType       string `json:"input_type,omitempty"`
	OutputType      string `json:"output_type,omitempty"`
	ClientStreaming bool   `json:"client_streaming,omitempty"`
	ServerStreaming bool   `json:"server_streaming,omitempty"`
}

// ReflectionResponse is a decoded ServerReflectionResponse: the services a
// list_services answer names, the file descriptors a file_* answer carries, or
// the server's error.
type ReflectionResponse struct {
	Services        []string
	FileDescriptors [][]byte
	ErrorCode       int
	ErrorMessage    string
}

// EncodeListServicesRequest is a ServerReflectionRequest asking for the
// service list (list_services = "").
func EncodeListServicesRequest() []byte {
	return appendBytesField(nil, 7, nil)
}

// EncodeFileContainingSymbolRequest asks for the file descriptor that declares
// symbol (a fully-qualified service name).
func EncodeFileContainingSymbolRequest(symbol string) []byte {
	return appendBytesField(nil, 4, []byte(symbol))
}

// DecodeReflectionResponse decodes one ServerReflectionResponse message.
func DecodeReflectionResponse(msg []byte) (ReflectionResponse, error) {
	var out ReflectionResponse
	err := walkFields(msg, func(num int, wt byte, v []byte, _ uint64) error {
		if wt != wireBytes {
			return nil
		}
		switch num {
		case 6: // list_services_response
			return walkFields(v, func(n int, w byte, sv []byte, _ uint64) error {
				if n != 1 || w != wireBytes {
					return nil
				}
				name, err := stringField(sv, 1)
				if err != nil {
					return err
				}
				if name != "" {
					out.Services = append(out.Services, name)
				}
				return nil
			})
		case 4: // file_descriptor_response
			return walkFields(v, func(n int, w byte, fd []byte, _ uint64) error {
				if n == 1 && w == wireBytes {
					out.FileDescriptors = append(out.FileDescriptors, append([]byte(nil), fd...))
				}
				return nil
			})
		case 7: // error_response
			return walkFields(v, func(n int, w byte, ev []byte, iv uint64) error {
				switch {
				case n == 1 && w == wireVarint:
					out.ErrorCode = int(int32(iv))
				case n == 2 && w == wireBytes:
					out.ErrorMessage = string(ev)
				}
				return nil
			})
		}
		return nil
	})
	return out, err
}

// DecodeFileDescriptorServices returns the services (with their methods) a
// serialized FileDescriptorProto declares, names fully qualified by the
// file's package.
func DecodeFileDescriptorServices(fd []byte) ([]ReflectionService, error) {
	pkg, err := stringField(fd, 2)
	if err != nil {
		return nil, err
	}
	var services []ReflectionService
	err = walkFields(fd, func(num int, wt byte, sv []byte, _ uint64) error {
		if num != 6 || wt != wireBytes {
			return nil
		}
		name, err := stringField(sv, 1)
		if err != nil || name == "" {
			return err
		}
		full := name
		if pkg != "" {
			full = pkg + "." + name
		}
		svc := ReflectionService{Name: full}
		err = walkFields(sv, func(n int, w byte, mv []byte, _ uint64) error {
			if n != 2 || w != wireBytes {
				return nil
			}
			m, err := decodeMethod(mv)
			if err != nil || m.Name == "" {
				return err
			}
			m.Path = "/" + full + "/" + m.Name
			svc.Methods = append(svc.Methods, m)
			return nil
		})
		if err != nil {
			return err
		}
		services = append(services, svc)
		return nil
	})
	return services, err
}

func decodeMethod(mv []byte) (ReflectionMethod, error) {
	var m ReflectionMethod
	err := walkFields(mv, func(n int, w byte, v []byte, iv uint64) error {
		switch {
		case n == 1 && w == wireBytes:
			m.Name = string(v)
		case n == 2 && w == wireBytes:
			m.InputType = trimLeadingDot(string(v))
		case n == 3 && w == wireBytes:
			m.OutputType = trimLeadingDot(string(v))
		case n == 5 && w == wireVarint:
			m.ClientStreaming = iv != 0
		case n == 6 && w == wireVarint:
			m.ServerStreaming = iv != 0
		}
		return nil
	})
	return m, err
}

// MergeServices folds per-file service lists into one catalog keyed by service
// name: names from list_services with no descriptor keep an empty method list,
// and a service a descriptor declares is filled in. Sorted by name.
func MergeServices(names []string, described []ReflectionService) []ReflectionService {
	byName := make(map[string]*ReflectionService)
	for _, n := range names {
		if _, ok := byName[n]; !ok {
			byName[n] = &ReflectionService{Name: n}
		}
	}
	for _, s := range described {
		cur, ok := byName[s.Name]
		if !ok {
			cp := s
			byName[s.Name] = &cp
			continue
		}
		if len(cur.Methods) == 0 {
			cur.Methods = s.Methods
		}
	}
	out := make([]ReflectionService, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func trimLeadingDot(s string) string {
	if len(s) > 0 && s[0] == '.' {
		return s[1:]
	}
	return s
}

// Protobuf wire types this reader handles; fixed32/fixed64 are skipped.
const (
	wireVarint  byte = 0
	wireFixed64 byte = 1
	wireBytes   byte = 2
	wireFixed32 byte = 5
)

// errBadWire is a malformed protobuf message.
var errBadWire = errors.New("grpcweb: malformed protobuf message")

// walkFields calls fn for every field of msg: the field number, wire type and
// either the length-delimited bytes (v) or the varint value (iv).
func walkFields(msg []byte, fn func(num int, wt byte, v []byte, iv uint64) error) error {
	for i := 0; i < len(msg); {
		key, n := binary.Uvarint(msg[i:])
		if n <= 0 {
			return errBadWire
		}
		i += n
		num, wt := int(key>>3), byte(key&7)
		if num <= 0 {
			return errBadWire
		}
		switch wt {
		case wireVarint:
			iv, n := binary.Uvarint(msg[i:])
			if n <= 0 {
				return errBadWire
			}
			i += n
			if err := fn(num, wt, nil, iv); err != nil {
				return err
			}
		case wireBytes:
			l, n := binary.Uvarint(msg[i:])
			if n <= 0 || l > uint64(len(msg)-i-n) {
				return errBadWire
			}
			i += n
			if err := fn(num, wt, msg[i:i+int(l)], 0); err != nil {
				return err
			}
			i += int(l)
		case wireFixed64:
			if i+8 > len(msg) {
				return errBadWire
			}
			i += 8
		case wireFixed32:
			if i+4 > len(msg) {
				return errBadWire
			}
			i += 4
		default:
			return errBadWire
		}
	}
	return nil
}

// stringField is the last occurrence of length-delimited field num in msg.
func stringField(msg []byte, num int) (string, error) {
	var s string
	err := walkFields(msg, func(n int, w byte, v []byte, _ uint64) error {
		if n == num && w == wireBytes {
			s = string(v)
		}
		return nil
	})
	return s, err
}

// appendBytesField appends a length-delimited field.
func appendBytesField(b []byte, num int, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3|uint64(wireBytes))
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}
