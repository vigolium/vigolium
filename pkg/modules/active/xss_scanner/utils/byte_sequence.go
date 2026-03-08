package utils

import (
	"bytes"
	"fmt"
	"io"
)

// Ac0 represents a byte array container equivalent to ac0.java
// This is a Go implementation of the Java ac0 class which extends ah7 and implements bi9
type Ac0 struct {
	data []byte // Equivalent to private final byte[] c; in ac0.java
}

// NewAc0ByteDataWithCapacity creates a new Ac0ByteData with a given capacity
// Equivalent to ac0(int var1) constructor in Java
func NewAc0ByteDataWithCapacity(capacity int) *Ac0 {
	return &Ac0{
		data: make([]byte, capacity),
	}
}

// NewAc0ByteData creates a new Ac0ByteData with the given data
// Equivalent to private ac0(byte[] var1) constructor in Java
func NewAc0ByteData(data []byte) *Ac0 {
	return &Ac0{
		data: data,
	}
}

// Ac0FromBytes creates an Ac0ByteData from a byte array
// Equivalent to static ac0 a(byte[] var0) in Java
func Ac0FromBytes(data []byte) *Ac0 {
	if data == nil {
		return nil
	}
	return NewAc0ByteData(data)
}

// Ac0FromString creates an Ac0ByteData from a string
// Equivalent to static ac0 a(String var0) in Java
func Ac0FromString(s string) *Ac0 {
	if s == "" {
		return nil
	}
	return NewAc0ByteData(StringToBytes(s))
}

// Ac0Empty creates an empty Ac0ByteData
// Equivalent to static ac0 aJ() in Java
func Ac0Empty() *Ac0 {
	return NewAc0ByteData(make([]byte, 0))
}

// GetData returns the byte array data
// Equivalent to byte[] z() in Java
func (a *Ac0) GetData() []byte {
	return a.data
}

// GetString returns a string representation of the data
// Equivalent to String x() in Java
func (a *Ac0) GetString() string {
	return BytesToString(a.data)
}

// SetData sets the byte array data
// Equivalent to bi9 a(byte[] var1) in Java
func (a *Ac0) SetData(data []byte) (*Ac0, error) {
	if len(data) != len(a.data) {
		return nil, fmt.Errorf("illegal argument: data length must match")
	}
	copy(a.data, data)
	return a, nil
}

// GetByte returns the byte at the given index
// Equivalent to byte a(int var1) in Java
func (a *Ac0) GetByte(index int) byte {
	return a.data[index]
}

// SetByte sets the byte at the given index
// Equivalent to void a(int var1, byte var2) in Java
func (a *Ac0) SetByte(index int, value byte) {
	a.data[index] = value
}

// SubSequence returns a subsequence of the byte data
// Equivalent to bi9 a(int var1, int var2) in Java
func (a *Ac0) SubSequence(startIndex, endIndex int) (*Ac0, error) {
	if startIndex < 0 || endIndex < startIndex || endIndex > len(a.data) {
		return nil, fmt.Errorf("array index out of bounds")
	}
	subArray := NetPortswiggerNkACopyOfRange(a.data, startIndex, endIndex)
	if subArray == nil && (endIndex-startIndex > 0) {
		return nil, fmt.Errorf(
			"NkSubArray/NetPortswiggerNkACopyOfRange returned nil for range [%d:%d] on data of len %d",
			startIndex,
			endIndex,
			len(a.data),
		)
	}
	return Ac0FromBytes(subArray), nil
}

// WriteTo writes data to the given writer
// Equivalent to void a(OutputStream var1, int var2, int var3) in Java
func (a *Ac0) WriteTo(writer io.Writer, offset, length int) error {
	if offset < 0 || length < 0 || offset+length > a.Length() {
		return fmt.Errorf("array index out of bounds")
	}
	_, err := writer.Write(a.data[offset : offset+length])
	return err
}

// Length returns the length of the byte data
// Equivalent to int aF() in Java
func (a *Ac0) Length() int {
	return len(a.data)
}

// NewReader returns a new reader for the byte data
// Equivalent to InputStream y() in Java
func (a *Ac0) NewReader() io.Reader {
	return bytes.NewReader(a.data)
}

// ReadFromWithLength reads data from the given reader into the byte sequence
// Equivalent to bi9 a(InputStream var1, int var2) in Java
func (a *Ac0) ReadFromWithLength(reader io.Reader, length int) (*Ac0, error) {
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

// Equals checks if this Ac0ByteData equals the given object
// Equivalent to boolean equals(Object var1) in Java
func (a *Ac0) Equals(other interface{}) bool {
	if a == other {
		return true
	}

	if otherData, ok := other.(*Ac0); ok {
		return bytes.Equal(a.data, otherData.data)
	}

	return false
}

// HashCode returns a hash code for this Ac0ByteData
// Equivalent to int hashCode() in Java
func (a *Ac0) HashCode() int {
	// Simple hash code implementation equivalent to Java's Arrays.hashCode(byte[])
	result := 1
	for _, b := range a.data {
		result = 31*result + int(b)
	}
	return result
}
