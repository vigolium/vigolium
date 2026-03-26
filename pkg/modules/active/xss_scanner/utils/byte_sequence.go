package utils

import (
	"bytes"
	"fmt"
	"io"
)

// ByteSequence represents a byte array container with indexed access and subsequence operations.
type ByteSequence struct {
	data []byte
}

// NewByteSequenceWithCapacity creates a new ByteSequence with a given capacity
func NewByteSequenceWithCapacity(capacity int) *ByteSequence {
	return &ByteSequence{
		data: make([]byte, capacity),
	}
}

// NewByteSequence creates a new ByteSequence with the given data
func NewByteSequence(data []byte) *ByteSequence {
	return &ByteSequence{
		data: data,
	}
}

// ByteSequenceFromBytes creates an ByteSequenceByteData from a byte array
func ByteSequenceFromBytes(data []byte) *ByteSequence {
	if data == nil {
		return nil
	}
	return NewByteSequence(data)
}

// ByteSequenceFromString creates an ByteSequenceByteData from a string
func ByteSequenceFromString(s string) *ByteSequence {
	if s == "" {
		return nil
	}
	return NewByteSequence(StringToBytes(s))
}

// EmptyByteSequence creates an empty ByteSequence
func EmptyByteSequence() *ByteSequence {
	return NewByteSequence(make([]byte, 0))
}

// GetData returns the byte array data
func (a *ByteSequence) GetData() []byte {
	return a.data
}

// GetString returns a string representation of the data
func (a *ByteSequence) GetString() string {
	return BytesToString(a.data)
}

// SetData sets the byte array data
func (a *ByteSequence) SetData(data []byte) (*ByteSequence, error) {
	if len(data) != len(a.data) {
		return nil, fmt.Errorf("illegal argument: data length must match")
	}
	copy(a.data, data)
	return a, nil
}

// GetByte returns the byte at the given index
func (a *ByteSequence) GetByte(index int) byte {
	return a.data[index]
}

// SetByte sets the byte at the given index
func (a *ByteSequence) SetByte(index int, value byte) {
	a.data[index] = value
}

// SubSequence returns a subsequence of the byte data
func (a *ByteSequence) SubSequence(startIndex, endIndex int) (*ByteSequence, error) {
	if startIndex < 0 || endIndex < startIndex || endIndex > len(a.data) {
		return nil, fmt.Errorf("array index out of bounds")
	}
	subArray := CopyOfRange(a.data, startIndex, endIndex)
	if subArray == nil && (endIndex-startIndex > 0) {
		return nil, fmt.Errorf(
			"CopyOfRange returned nil for range [%d:%d] on data of len %d",
			startIndex,
			endIndex,
			len(a.data),
		)
	}
	return ByteSequenceFromBytes(subArray), nil
}

// WriteTo writes data to the given writer
func (a *ByteSequence) WriteTo(writer io.Writer, offset, length int) error {
	if offset < 0 || length < 0 || offset+length > a.Length() {
		return fmt.Errorf("array index out of bounds")
	}
	_, err := writer.Write(a.data[offset : offset+length])
	return err
}

// Length returns the length of the byte data
func (a *ByteSequence) Length() int {
	return len(a.data)
}

func (a *ByteSequence) NewReader() io.Reader {
	return bytes.NewReader(a.data)
}

// ReadFromWithLength reads data from the given reader into the byte sequence
func (a *ByteSequence) ReadFromWithLength(reader io.Reader, length int) (*ByteSequence, error) {
	if length != len(a.data) {
		return nil, fmt.Errorf("illegal argument: length must match data length")
	}

	remaining := length
	offset := 0

	for remaining > 0 {
		n, err := reader.Read(a.data[offset : offset+remaining])
		if err != nil && err != io.EOF {
			return nil, err
		}
		remaining -= n
		offset += n
		if err == io.EOF {
			break
		}
	}

	return a, nil
}

// Equals checks if this ByteSequenceByteData equals the given object
func (a *ByteSequence) Equals(other interface{}) bool {
	if a == other {
		return true
	}

	if otherData, ok := other.(*ByteSequence); ok {
		return bytes.Equal(a.data, otherData.data)
	}

	return false
}

// HashCode returns a hash code for this ByteSequenceByteData
func (a *ByteSequence) HashCode() int {
	result := 1
	for _, b := range a.data {
		result = 31*result + int(b)
	}
	return result
}
