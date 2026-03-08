package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// SSTIPayloadProvider corresponds to bb6.java. It provides a list of SSTI payloads.
type SSTIPayloadProvider struct {
	randomProvider *utils.RandomGenerator
	payloads       []*PayloadModificationContext
}

// NewSSTIPayloadProvider creates a new provider for SSTI payloads.
func NewSSTIPayloadProvider(randomProvider *utils.RandomGenerator, thoroughScan bool) *SSTIPayloadProvider {
	provider := &SSTIPayloadProvider{
		randomProvider: randomProvider,
		payloads:       make([]*PayloadModificationContext, 0),
	}
	provider.initializePayloads(thoroughScan)
	return provider
}

func (p *SSTIPayloadProvider) initializePayloads(thoroughScan bool) {
	// Payloads from bb6.java for ctx.FAST
	p.payloads = append(p.payloads, NewPayloadModificationContext(utils.StringToBytes("}}"), p.randomProvider))
	p.payloads = append(p.payloads, NewPayloadModificationContext(utils.StringToBytes("%}"), p.randomProvider))
	p.payloads = append(p.payloads, NewPayloadModificationContextWithPrefix(utils.StringToBytes(p.randomProvider.GeneratePrefixedAlphanumeric(5)), utils.StringToBytes("%>"), p.randomProvider))

	if thoroughScan { // Payloads from bb6.java for ctx.THOROUGH
		p.payloads = append(p.payloads, NewPayloadModificationContext(utils.StringToBytes("%]"), p.randomProvider))
		sstiPrefix := utils.StringToBytes(p.randomProvider.GeneratePrefixedAlphanumeric(5))
		sstiPayload := utils.StringToBytes(";//';//\"//%>?>")
		p.payloads = append(p.payloads, NewPayloadModificationContextWithPrefix(sstiPrefix, sstiPayload, p.randomProvider))
	}
}

// Payloads returns the list of configured SSTI payloads.
func (p *SSTIPayloadProvider) Payloads() []*PayloadModificationContext {
	return p.payloads
}
