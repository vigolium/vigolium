package diffscan

import (
	"errors"

	"github.com/samber/lo"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	globalutils "github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

type PayloadInjector struct {
	InsertionPoint httpmsg.InsertionPoint

	baseRequest []byte
	httpService *httpmsg.Service
	httpClient  *http.Requester
	Options     *Option
}

func NewPayloadInjector(
	baseRequest []byte,
	insertionPoint httpmsg.InsertionPoint,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
	options *Option,
) *PayloadInjector {
	return &PayloadInjector{
		InsertionPoint: insertionPoint,
		Options:        options,
		baseRequest:    baseRequest,
		httpService:    httpService,
		httpClient:     httpClient,
	}
}

// MapInsertionPointToPosition maps insertion point type to position string
func MapInsertionPointToPosition(ipType httpmsg.InsertionPointType) string {
	switch ipType {
	case httpmsg.INS_PARAM_URL:
		return "query"
	case httpmsg.INS_PARAM_BODY:
		return "body"
	case httpmsg.INS_PARAM_COOKIE:
		return "cookie"
	case httpmsg.INS_HEADER:
		return "header"
	case httpmsg.INS_URL_PATH_FOLDER, httpmsg.INS_URL_PATH_FILENAME:
		return "path"
	case httpmsg.INS_PARAM_JSON:
		return "json"
	case httpmsg.INS_PARAM_XML, httpmsg.INS_PARAM_XML_ATTR:
		return "xml"
	default:
		return "unknown"
	}
}

// IsCookieInsertionPoint checks if insertion point is for cookies
func IsCookieInsertionPoint(ip httpmsg.InsertionPoint) bool {
	return ip.Type() == httpmsg.INS_PARAM_COOKIE
}

// IsHeaderInsertionPoint checks if insertion point is for headers
func IsHeaderInsertionPoint(ip httpmsg.InsertionPoint) bool {
	return ip.Type() == httpmsg.INS_HEADER
}

// GetPosition returns the position string for this injector's insertion point
func (s *PayloadInjector) GetPosition() string {
	return MapInsertionPointToPosition(s.InsertionPoint.Type())
}

// IsCookie returns true if the insertion point is a cookie parameter
func (s *PayloadInjector) IsCookie() bool {
	return IsCookieInsertionPoint(s.InsertionPoint)
}

// IsHeader returns true if the insertion point is a header
func (s *PayloadInjector) IsHeader() bool {
	return IsHeaderInsertionPoint(s.InsertionPoint)
}

func (s *PayloadInjector) Fuzz(
	baselineAttack *Attack,
	probe *Probe,
) ([]*Attack, error) {
	attacks := make([]*Attack, 0, 2)
	breakAttack, err := s.buildAttackFromProbe(probe, probe.GetNextBreakPayload())
	if err != nil {
		return nil, err
	}

	zap.L().Debug("diffscan.Fuzz: break vs baseline",
		zap.String("probe", probe.Name),
		zap.String("break_payload", breakAttack.Payload),
		zap.Int("baseline_status", baselineAttack.FirstSnapshot.StatusCode),
		zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
		zap.Int("baseline_fp_keys", len(baselineAttack.Fingerprint)),
		zap.Int("break_fp_keys", len(breakAttack.Fingerprint)),
	)

	if Identical(baselineAttack, breakAttack) {
		zap.L().Debug("diffscan.Fuzz: BAIL - break identical to baseline",
			zap.String("probe", probe.Name),
			zap.String("break_payload", breakAttack.Payload),
		)
		return nil, nil
	}

	escapeSet := probe.GetNextEscapePayloadSet()
	for escapeIndex, escapePayload := range escapeSet {
		beginAttack, err := s.buildAttackFromProbe(probe, escapePayload)
		if err != nil {
			return nil, err
		}
		beginAttack.AddAttack(baselineAttack)

		zap.L().Debug("diffscan.Fuzz: escape vs break",
			zap.String("probe", probe.Name),
			zap.Int("escape_index", escapeIndex),
			zap.String("escape_payload", escapePayload),
			zap.Int("escape_status", beginAttack.FirstSnapshot.StatusCode),
			zap.Int("escape_fp_keys", len(beginAttack.Fingerprint)),
			zap.Bool("identical_to_break", Identical(beginAttack, breakAttack)),
		)

		if !Identical(beginAttack, breakAttack) {
			zap.L().Debug("diffscan.Fuzz: escape differs from break, sending to verify",
				zap.String("probe", probe.Name),
				zap.String("escape_payload", escapePayload),
			)
			verifiedAttacks, err := s.verify(beginAttack, breakAttack, probe, escapeIndex)
			if err != nil {
				return nil, err
			}
			if len(verifiedAttacks) > 0 {
				for _, _attack := range verifiedAttacks {
					if _attack.FirstSnapshot != nil && _attack.FirstSnapshot.WafBlocked() {
						zap.L().Debug("Attack is blocked by WAF")
						return nil, errors.New("attack blocked by WAF")
					}
				}
				// Suppress the finding when the confirmed difference cannot be
				// template evaluation: redirect-only, non-rendered (empty/404),
				// or fully explained by verbatim payload reflection.
				if reason := nonEvaluableReason(verifiedAttacks); reason != "" {
					zap.L().Debug("diffscan.Fuzz: BAIL - "+reason,
						zap.String("probe", probe.Name),
					)
					return nil, nil
				}
				return verifiedAttacks, nil
			}
		}
	}

	return attacks, nil
}

func (s *PayloadInjector) verify(
	baselineAttackSeed *Attack,
	breakAttackSeed *Attack,
	probe *Probe,
	chosenEscape int,
) ([]*Attack, error) {
	attacks := make([]*Attack, 0, 2)

	mergedBreakAttack := NewAttack(s.Options.QuantitativeDiffKeys, s.Options.QuantileFactor, s.Options.CustomCanary)
	mergedBreakAttack.AddAttack(breakAttackSeed)

	mergedBaselineAttack := NewAttack(s.Options.QuantitativeDiffKeys, s.Options.QuantileFactor, s.Options.CustomCanary)
	mergedBaselineAttack.AddAttack(baselineAttackSeed)

	tempBaselineAttack := baselineAttackSeed

	confirmations := s.Options.Confirmations
	boostedConfirmations := false
	for i := 0; i < confirmations; i++ {
		tempBreakAttack, err := s.buildAttackFromProbe(probe, probe.GetNextBreakPayload())
		if err != nil {
			return nil, err
		}
		mergedBreakAttack.AddAttack(tempBreakAttack)

		similarCheck1 := Similar(mergedBaselineAttack, tempBreakAttack)
		toleranceCheck1 := probe.RequireConsistentEvidence &&
			SimilarWithTolerance(
				mergedBaselineAttack,
				mergedBreakAttack,
				tempBaselineAttack,
				tempBreakAttack,
			)
		if similarCheck1 || toleranceCheck1 {
			zap.L().Debug(
				"verify rejected (loop)",
				zap.Bool("similarCheck1", similarCheck1),
				zap.Bool("toleranceCheck1", toleranceCheck1),
				zap.String("mergedBaselineAttack_payload", mergedBaselineAttack.Payload),
				zap.String("tempBreakAttack_payload", tempBreakAttack.Payload),
				zap.String("mergedBreakAttack_payload", mergedBreakAttack.Payload),
				zap.String("baselineAttackSeed_payload", baselineAttackSeed.Payload),
			)

			return []*Attack{}, nil
		}

		if boostedConfirmations && mergedBaselineAttack.Size() > mergedBreakAttack.Size()+5 {
			continue
		}

		tempBaselineAttack, err = s.buildAttackFromProbe(
			probe,
			probe.GetNextEscapePayloadSet()[chosenEscape],
		)
		if err != nil {
			return nil, err
		}
		mergedBaselineAttack.AddAttack(tempBaselineAttack)

		similarCheck2 := Similar(mergedBreakAttack, tempBaselineAttack)
		toleranceCheck2 := probe.RequireConsistentEvidence &&
			SimilarWithTolerance(
				mergedBaselineAttack,
				mergedBreakAttack,
				tempBaselineAttack,
				tempBreakAttack,
			)
		if similarCheck2 || toleranceCheck2 {
			zap.L().Debug(
				"verify rejected (loop) after adding tempBaselineAttack",
				zap.Bool("similarCheck2", similarCheck2),
				zap.Bool("toleranceCheck2", toleranceCheck2),
				zap.String("mergedBreakAttack_payload", mergedBreakAttack.Payload),
				zap.String("tempBaselineAttack_payload", tempBaselineAttack.Payload),
				zap.String("mergedBaselineAttack_payload", mergedBaselineAttack.Payload),
				zap.String("tempBreakAttack_payload", tempBreakAttack.Payload),
			)
			return []*Attack{}, nil
		}

		if i == confirmations-1 && !boostedConfirmations {
			keys := GetNonMatchingFingerprints(mergedBaselineAttack, mergedBreakAttack)
			if tempBreakAttack.AllKeysAreQuantitative(lo.Keys(keys)) {
				confirmations = s.Options.QuantitativeConfirmations
				boostedConfirmations = true
			}
		}
	}

	// Final probe pair sent out of order
	tempBaselineAttack, err := s.buildAttackFromProbe(
		probe,
		probe.GetNextEscapePayloadSet()[chosenEscape],
	)
	if err != nil {
		return nil, err
	}
	mergedBaselineAttack.AddAttack(tempBaselineAttack)

	tempBreakAttack, err := s.buildAttackFromProbe(probe, probe.GetNextBreakPayload())
	if err != nil {
		return nil, err
	}
	mergedBreakAttack.AddAttack(tempBreakAttack)

	toleranceCheck3 := SimilarWithTolerance(
		mergedBaselineAttack,
		mergedBreakAttack,
		tempBaselineAttack,
		tempBreakAttack,
	)
	similarCheck3 := probe.RequireConsistentEvidence &&
		Similar(mergedBreakAttack, tempBaselineAttack)
	if toleranceCheck3 || similarCheck3 {
		zap.L().Debug(
			"verify rejected (final) after final probes",
			zap.Bool("toleranceCheck3", toleranceCheck3),
			zap.Bool("similarCheck3", similarCheck3),
			zap.String("mergedBaselineAttack_payload", mergedBaselineAttack.Payload),
			zap.String("mergedBreakAttack_payload", mergedBreakAttack.Payload),
			zap.String("tempBaselineAttack_payload", tempBaselineAttack.Payload),
			zap.String("tempBreakAttack_payload", tempBreakAttack.Payload),
		)
		return []*Attack{}, nil
	}

	if !boostedConfirmations {
		keys := GetNonMatchingFingerprints(mergedBaselineAttack, mergedBreakAttack)
		quantitativeCheck := tempBreakAttack.AllKeysAreQuantitative(lo.Keys(keys))
		if quantitativeCheck {
			zap.L().Debug(
				"verify rejected (final): All keys are quantitative and confirmations not boosted",
				zap.Bool("quantitativeCheck", quantitativeCheck),
				zap.String("tempBreakAttack_payload", tempBreakAttack.Payload),
				zap.String("mergedBaselineAttack_payload", mergedBaselineAttack.Payload),
				zap.String("mergedBreakAttack_payload", mergedBreakAttack.Payload),
			)
			return []*Attack{}, nil
		}
	}

	attacks = append(attacks, mergedBreakAttack, mergedBaselineAttack)

	return attacks, nil
}

func (s *PayloadInjector) buildAttackFromProbe(
	_probe *Probe,
	payload string,
) (*Attack, error) {
	randomAnchor := _probe.RandomAnchor
	prefix := _probe.InjectType
	baseValue := s.InsertionPoint.BaseValue()

	anchor := ""
	if randomAnchor {
		anchor = globalutils.GenerateCanary()
	}

	basePayload := payload
	switch prefix {
	case InjectType_Prepend:
		payload = payload + baseValue
	case InjectType_Append:
		payload = baseValue + anchor + payload
	case InjectType_Replace:
		// payload remains unchanged
	default:
		return nil, errors.New("unknown payload position")
	}

	zap.L().Debug("diffscan: buildAttackFromProbe",
		zap.String("probe", _probe.Name),
		zap.String("raw_payload", basePayload),
		zap.String("final_payload", payload),
		zap.String("inject_type", prefix.String()),
		zap.String("base_value", baseValue),
	)

	needCacheBuster := _probe.UseCacheBuster || s.IsCookie() || s.IsHeader()
	snap, err := s.buildRequest(payload, needCacheBuster)
	if err != nil {
		return nil, err
	}

	return NewAttackFromSnapshot(snap, _probe, basePayload, anchor, s.Options.QuantitativeDiffKeys, s.Options.QuantileFactor, s.Options.CustomCanary), nil
}

func (s *PayloadInjector) buildRequest(
	payload string,
	needCacheBuster bool,
) (*ResponseSnapshot, error) {
	// Use httpmsg InsertionPoint to build the fuzzed request
	fuzzedRaw := s.InsertionPoint.BuildRequest([]byte(payload))

	// Add cache buster if needed
	if needCacheBuster {
		fuzzedRaw = globalutils.AddCacheBuster(fuzzedRaw, globalutils.GenerateCanary())
	}

	// Parse the raw request into a typed request
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(s.httpService)

	// Execute the request
	resp, _, err := s.httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}

	if reqURL, urlErr := fuzzedReq.URL(); urlErr == nil {
		zap.L().Debug("diffscan: HTTP request",
			zap.String("url", reqURL.String()),
			zap.Int("status", resp.Response().StatusCode),
		)
	}

	// Create snapshot and close ResponseChain immediately
	return NewResponseSnapshot(resp), nil
}

func (s *PayloadInjector) ProbeAttack(payload string) (*Attack, error) {
	snap, err := s.buildRequest(payload, true)
	if err != nil {
		return nil, err
	}

	return NewAttackFromSnapshotSimple(snap, "", s.Options.QuantitativeDiffKeys, s.Options.QuantileFactor, s.Options.CustomCanary), nil
}

func (s *PayloadInjector) BuildAttack(payload string, random bool) (*Attack, error) {
	canary := ""
	if random {
		canary = globalutils.GenerateCanary()
	}

	snap, err := s.buildRequest(canary+payload, !random)
	if err != nil {
		return nil, err
	}

	return NewAttackFromSnapshotSimple(snap, canary, s.Options.QuantitativeDiffKeys, s.Options.QuantileFactor, s.Options.CustomCanary), nil
}
