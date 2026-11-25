package grpcweb

import (
	"encoding/binary"
	"testing"
)

// Fixture encoders: the descriptor.proto / reflection.proto shapes a server
// sends, built field by field.
func pbBytes(b []byte, num int, v []byte) []byte { return appendBytesField(b, num, v) }
func pbStr(b []byte, num int, s string) []byte   { return appendBytesField(b, num, []byte(s)) }
func pbBool(b []byte, num int, v bool) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3|uint64(wireVarint))
	if v {
		return binary.AppendUvarint(b, 1)
	}
	return binary.AppendUvarint(b, 0)
}

func methodProto(name, in, out string, cs, ss bool) []byte {
	m := pbStr(nil, 1, name)
	m = pbStr(m, 2, in)
	m = pbStr(m, 3, out)
	if cs {
		m = pbBool(m, 5, true)
	}
	if ss {
		m = pbBool(m, 6, true)
	}
	return m
}

// FixtureFileDescriptor is a FileDescriptorProto for package acme.v1 with one
// service and two methods, plus an unrelated message_type field to skip.
func fixtureFileDescriptor() []byte {
	svc := pbStr(nil, 1, "Users")
	svc = pbBytes(svc, 2, methodProto("GetUser", ".acme.v1.GetUserRequest", ".acme.v1.User", false, false))
	svc = pbBytes(svc, 2, methodProto("WatchUsers", ".acme.v1.WatchRequest", ".acme.v1.User", false, true))
	fd := pbStr(nil, 1, "acme/v1/users.proto")
	fd = pbStr(fd, 2, "acme.v1")
	fd = pbBytes(fd, 4, pbStr(nil, 1, "User")) // message_type, ignored
	fd = pbBytes(fd, 6, svc)
	return fd
}

func TestReflection_RequestEncoding(t *testing.T) {
	if got := EncodeListServicesRequest(); string(got) != "\x3a\x00" {
		t.Fatalf("list_services request = %x, want 3a00", got)
	}
	if got := EncodeFileContainingSymbolRequest("acme.v1.Users"); string(got) != "\x22\x0dacme.v1.Users" {
		t.Fatalf("file_containing_symbol request = %q", got)
	}
}

func TestReflection_DecodeListServices(t *testing.T) {
	list := pbBytes(nil, 1, pbStr(nil, 1, "acme.v1.Users"))
	list = pbBytes(list, 1, pbStr(nil, 1, "grpc.reflection.v1.ServerReflection"))
	msg := pbStr(nil, 1, "host") // valid_host
	msg = pbBytes(msg, 2, EncodeListServicesRequest())
	msg = pbBytes(msg, 6, list)
	resp, err := DecodeReflectionResponse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Services) != 2 || resp.Services[0] != "acme.v1.Users" {
		t.Fatalf("services = %v", resp.Services)
	}
}

func TestReflection_DecodeFileDescriptorServices(t *testing.T) {
	msg := pbBytes(nil, 4, pbBytes(nil, 1, fixtureFileDescriptor()))
	resp, err := DecodeReflectionResponse(msg)
	if err != nil || len(resp.FileDescriptors) != 1 {
		t.Fatalf("file descriptors = %d, %v", len(resp.FileDescriptors), err)
	}
	svcs, err := DecodeFileDescriptorServices(resp.FileDescriptors[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "acme.v1.Users" || len(svcs[0].Methods) != 2 {
		t.Fatalf("services = %+v", svcs)
	}
	get, watch := svcs[0].Methods[0], svcs[0].Methods[1]
	if get.Path != "/acme.v1.Users/GetUser" || get.InputType != "acme.v1.GetUserRequest" || get.OutputType != "acme.v1.User" || get.ServerStreaming {
		t.Fatalf("GetUser = %+v", get)
	}
	if !watch.ServerStreaming || watch.ClientStreaming {
		t.Fatalf("WatchUsers = %+v", watch)
	}
}

func TestReflection_DecodeError(t *testing.T) {
	errMsg := binary.AppendUvarint(nil, 1<<3|uint64(wireVarint))
	errMsg = binary.AppendUvarint(errMsg, 5) // NOT_FOUND
	errMsg = pbStr(errMsg, 2, "symbol not found")
	resp, err := DecodeReflectionResponse(pbBytes(nil, 7, errMsg))
	if err != nil || resp.ErrorCode != 5 || resp.ErrorMessage != "symbol not found" {
		t.Fatalf("error response = %+v, %v", resp, err)
	}
}

// Truncated and garbage input is an error, never a panic.
func TestReflection_Malformed(t *testing.T) {
	good := pbBytes(nil, 4, pbBytes(nil, 1, fixtureFileDescriptor()))
	for i := 1; i < len(good); i++ {
		_, _ = DecodeReflectionResponse(good[:i])
		_, _ = DecodeFileDescriptorServices(fixtureFileDescriptor()[:min(i, len(fixtureFileDescriptor()))])
	}
	if _, err := DecodeReflectionResponse([]byte{0x22, 0xff}); err == nil {
		t.Fatal("a length past the end must be an error")
	}
	if _, err := DecodeReflectionResponse([]byte{0x07}); err == nil {
		t.Fatal("field number 0 must be an error")
	}
}

func TestMergeServices(t *testing.T) {
	described := []ReflectionService{{Name: "acme.v1.Users", Methods: []ReflectionMethod{{Name: "GetUser"}}}}
	got := MergeServices([]string{"grpc.health.v1.Health", "acme.v1.Users"}, described)
	if len(got) != 2 || got[0].Name != "acme.v1.Users" || len(got[0].Methods) != 1 || got[1].Methods != nil {
		t.Fatalf("merged = %+v", got)
	}
}
