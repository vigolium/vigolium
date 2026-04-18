package ggml

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// buildMaliciousGGUF crafts a GGUF file that declares numTensor tensor records
// with minimum-size metadata (empty name, 0 dims, kind=0, offset=0). Each record is 24 bytes.
func buildMaliciousGGUF(numTensor uint64) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(FILE_MAGIC_GGUF_LE))
	binary.Write(&b, binary.LittleEndian, uint32(3))
	binary.Write(&b, binary.LittleEndian, numTensor)
	binary.Write(&b, binary.LittleEndian, uint64(0))

	for i := uint64(0); i < numTensor; i++ {
		binary.Write(&b, binary.LittleEndian, uint64(0))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint64(0))
	}
	return b.Bytes()
}

type peakSampler struct {
	mu   sync.Mutex
	peak uint64
	stop chan struct{}
}

func startSampler() *peakSampler {
	s := &peakSampler{stop: make(chan struct{})}
	go func() {
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				s.mu.Lock()
				if m.HeapAlloc > s.peak {
					s.peak = m.HeapAlloc
				}
				s.mu.Unlock()
			}
		}
	}()
	return s
}

func (s *peakSampler) Stop() uint64 {
	close(s.stop)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func runAdvCase(t *testing.T, n uint64) {
	debug.SetGCPercent(-1) // disable GC during decode to measure true peak
	defer debug.SetGCPercent(100)

	blob := buildMaliciousGGUF(n)
	t.Logf("numTensor=%d blob size: %.2f MB", n, float64(len(blob))/1024/1024)

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	sampler := startSampler()
	start := time.Now()
	rs := bytes.NewReader(blob)
	_, err := Decode(rs, -1)
	elapsed := time.Since(start)
	peak := sampler.Stop()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	t.Logf("numTensor=%d err=%v elapsed=%v peak_heap=%.2f MB delta_heap=%.2f MB total_allocs=%d",
		n, err, elapsed,
		float64(peak)/1024/1024,
		float64(int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/1024/1024,
		m1.Mallocs-m0.Mallocs)
}

func TestAdvMaliciousGGUF_Baseline(t *testing.T) { runAdvCase(t, 100) }
func TestAdvMaliciousGGUF_1M(t *testing.T)       { runAdvCase(t, 1_000_000) }
func TestAdvMaliciousGGUF_10M(t *testing.T)      { runAdvCase(t, 10_000_000) }

func TestAdvMaliciousGGUF_30M(t *testing.T) {
	if testing.Short() {
		t.Skip("slow large test")
	}
	runAdvCase(t, 30_000_000)
}
