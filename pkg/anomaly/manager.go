package anomaly

import "sync"

type FingerprintManager struct {
	Mutex sync.Mutex
	Data  map[string]*Fingerprint
}

func NewFingerprintManager() *FingerprintManager {
	f := new(FingerprintManager)
	f.Data = make(map[string]*Fingerprint)
	return f
}

func (f *FingerprintManager) AddFingerprint(name string, add *Fingerprint) {
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	f.Data[name] = add
}

func (f *FingerprintManager) GetFingerprint(name string) *Fingerprint {
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	if _, ok := f.Data[name]; ok {
		return f.Data[name]
	}
	return nil
}

func (f *FingerprintManager) Clean() {
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	f.Data = make(map[string]*Fingerprint)
}
