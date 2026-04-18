package ggml

import (
	"bytes"
	"encoding/binary"
	"runtime/debug"
	"strings"
	"testing"
)

// buildAlignmentZeroGGUF crafts a minimal GGUF file with general.alignment = uint32(0)
// and zero tensors, exercising the ggufPadding(offset, 0) path.
func buildAlignmentZeroGGUF() []byte {
	var b bytes.Buffer
	// magic (GGUF LE)
	binary.Write(&b, binary.LittleEndian, uint32(FILE_MAGIC_GGUF_LE))
	// version 3
	binary.Write(&b, binary.LittleEndian, uint32(3))
	// V3: NumTensor=0, NumKV=1
	binary.Write(&b, binary.LittleEndian, uint64(0)) // numTensor
	binary.Write(&b, binary.LittleEndian, uint64(1)) // numKV

	// Write KV: "general.alignment" (string) = uint32(0)
	key := "general.alignment"
	binary.Write(&b, binary.LittleEndian, uint64(len(key)))
	b.WriteString(key)
	// value type: ggufTypeUint32 == 4
	binary.Write(&b, binary.LittleEndian, uint32(4))
	// value: 0
	binary.Write(&b, binary.LittleEndian, uint32(0))

	return b.Bytes()
}

func TestAlignmentZeroPanic(t *testing.T) {
	blob := buildAlignmentZeroGGUF()
	t.Logf("blob size: %d bytes", len(blob))

	defer func() {
		if r := recover(); r != nil {
			msg := ""
			switch v := r.(type) {
			case error:
				msg = v.Error()
			case string:
				msg = v
			default:
				msg = "non-standard panic"
			}
			t.Logf("PANIC caught: %v", r)
			t.Logf("stack:\n%s", debug.Stack())
			if strings.Contains(msg, "integer divide by zero") {
				t.Logf("CONFIRMED: integer divide by zero panic reached")
				return
			}
			t.Logf("panic message: %s", msg)
		}
	}()

	rs := bytes.NewReader(blob)
	_, err := Decode(rs, -1)
	t.Logf("Decode returned err=%v (no panic)", err)
}
