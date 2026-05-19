package harness

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// OASTProbe records details about an OAST probe generated during scanning.
type OASTProbe struct {
	TargetURL     string
	ParamName     string
	InjectionType string
	ModuleID      string
	RequestHash   string
	CallbackURL   string
}

// MockOASTProvider implements modkit.OASTProvider for benchmark testing.
// It records probe details for assertion without requiring a real callback server.
type MockOASTProvider struct {
	mu     sync.Mutex
	probes []OASTProbe
	count  atomic.Int64
}

// Compile-time interface check.
var _ modkit.OASTProvider = (*MockOASTProvider)(nil)

// NewMockOASTProvider creates a new MockOASTProvider.
func NewMockOASTProvider() *MockOASTProvider {
	return &MockOASTProvider{}
}

// GenerateURL records the probe and returns a deterministic mock callback URL.
func (m *MockOASTProvider) GenerateURL(targetURL, paramName, injectionType, moduleID, requestHash string) string {
	n := m.count.Add(1)
	callbackURL := fmt.Sprintf("http://oast.mock.local/cb/%d", n)

	m.mu.Lock()
	m.probes = append(m.probes, OASTProbe{
		TargetURL:     targetURL,
		ParamName:     paramName,
		InjectionType: injectionType,
		ModuleID:      moduleID,
		RequestHash:   requestHash,
		CallbackURL:   callbackURL,
	})
	m.mu.Unlock()

	return callbackURL
}

// Enabled returns true — the mock provider is always enabled.
func (m *MockOASTProvider) Enabled() bool {
	return true
}

// ProbeCount returns the total number of OAST probes generated.
func (m *MockOASTProvider) ProbeCount() int64 {
	return m.count.Load()
}

// Probes returns a copy of all recorded probes.
func (m *MockOASTProvider) Probes() []OASTProbe {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]OASTProbe, len(m.probes))
	copy(out, m.probes)
	return out
}

// SetupTestInfraWithOAST initializes test infrastructure with an OASTProvider
// wired into the ScanContext. Returns the infra and the mock provider for assertions.
func SetupTestInfraWithOAST() (*TestInfra, *MockOASTProvider, error) {
	infra, err := SetupTestInfra()
	if err != nil {
		return nil, nil, err
	}

	mock := NewMockOASTProvider()
	infra.ScanCtx.OASTProvider = mock

	return infra, mock, nil
}
