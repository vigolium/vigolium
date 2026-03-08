package nginx_path_escape

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Module implements Nginx Path Escape Detection for path-based vulnerabilities.
type Module struct {
	modkit.BaseActiveModule
	ds      dedup.Lazy[dedup.DiskSet]
	options *Options
}

// New creates a new Nginx Path Escape Detection module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds:      dedup.LazyDiskSet("nginx_path_escape"),
		options: DefaultOptions(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess
// that does not include the base URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true for any URL with a non-root path.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	method := ctx.Request().Method()
	return method != "OPTIONS" && method != "CONNECT"
}

// ScanPerRequest scans the request for Nginx path escape vulnerabilities.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	httpService := ctx.Service()
	if httpService == nil {
		return nil, errors.New("httpService is nil in request")
	}

	rawRequest := ctx.Request().Raw()
	fullPath := urlx.EscapedPath()

	pathLevels := splitPathIntoLevels(fullPath)
	if len(pathLevels) == 0 {
		return nil, nil
	}

	if m.options.MaxPathLevels > 0 && len(pathLevels) > m.options.MaxPathLevels {
		pathLevels = pathLevels[:m.options.MaxPathLevels]
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var allFindings []*finding

	// Per-level probes: create a level insertion point per path level
	for levelIdx, pathLevel := range pathLevels {
		modReq, ip, err := createLevelInsertionPoint(rawRequest, pathLevel)
		if err != nil {
			zap.L().Debug("NginxPathEscape: Failed to create level insertion point",
				zap.String("pathLevel", pathLevel),
				zap.Error(err),
			)
			continue
		}

		if diskSet != nil && diskSet.IsSeen(urlx.Host+pathLevel) {
			continue
		}

		inj := diffscan.NewPayloadInjector(modReq, ip, httpService, httpClient, m.options.DiffScanOptions)

		segment := ip.BaseValue()

		// softBase: replace segment with itself + "/" → path with trailing slash
		// This matches what escape payloads resolve to after server-side normalization
		softBase, err := m.buildStabilizedBaseline(inj, segment+"/")
		if err != nil {
			continue
		}

		// errorBase: replace segment with random nonexistent name
		errorSegment := "NONEXISTENT_" + utils.GenerateCanary()
		errorBase, _ := m.buildStabilizedBaseline(inj, errorSegment)

		// parentBaseline: replace segment with "" → parent path
		parentBaseline, _ := m.buildStabilizedBaseline(inj, "")

		levelFindings := m.testPathLevel(inj, softBase, errorBase, segment, pathLevel, levelIdx, parentBaseline)
		allFindings = append(allFindings, levelFindings...)
	}

	// Full-path probes (N7, N16): use a full-path insertion point
	fullPathIP, err := createFullPathInsertionPoint(rawRequest)
	if err == nil {
		if diskSet == nil || !diskSet.IsSeen(urlx.Host+fullPath) {
			fullInj := diffscan.NewPayloadInjector(rawRequest, fullPathIP, httpService, httpClient, m.options.DiffScanOptions)

			fullSoftBase, err := m.buildStabilizedBaseline(fullInj, fullPath)
			if err == nil {
				errorPath := "/NONEXISTENT_RANDOM_" + utils.GenerateCanary()
				fullErrorBase, _ := m.buildStabilizedBaseline(fullInj, errorPath)

				fullPathFindings := m.testFullPathProbes(fullInj, fullSoftBase, fullErrorBase, fullPath)
				allFindings = append(allFindings, fullPathFindings...)
			}

		}
	}

	if len(allFindings) == 0 {
		return nil, nil
	}

	report := generateReport(allFindings, fullPath)
	if report == "" {
		return nil, nil
	}

	bestSeverity := getBestSeverity(allFindings)

	zap.L().Debug("NginxPathEscape: Found vulnerabilities",
		zap.String("url", urlx.String()),
		zap.Int("count", len(allFindings)))

	vulnPath := allFindings[0].ProbeInfo.Probe.Base
	modifiedRaw, err := httpmsg.SetPath(rawRequest, vulnPath)
	if err != nil {
		modifiedRaw = rawRequest
	}

	return []*output.ResultEvent{{
		URL:              urlx.String(),
		Host:             urlx.Host,
		Request:          string(modifiedRaw),
		FuzzingParameter: "PATH",
		Info: output.Info{
			Severity:    bestSeverity,
			Description: report,
		},
	}}, nil
}

// testPathLevel tests all per-level probes (N1-N6, N8-N15, N17-N18) at a single path level.
func (m *Module) testPathLevel(
	inj *diffscan.PayloadInjector,
	softBase, errorBase *diffscan.Attack,
	segment string,
	pathLevel string,
	levelIndex int,
	parentBaseline *diffscan.Attack,
) []*finding {
	var findings []*finding

	zap.L().Debug("NginxPathEscape: testing path level",
		zap.String("segment", segment),
		zap.String("pathLevel", pathLevel),
		zap.Int("levelIndex", levelIndex),
		zap.Int("softBase_status", softBase.FirstSnapshot.StatusCode),
		zap.Int("softBase_fp_keys", len(softBase.Fingerprint)),
	)

	parentBaselines := map[int]*diffscan.Attack{}
	if parentBaseline != nil {
		parentBaselines[1] = parentBaseline
	}

	// --- Traversal probes ---

	// N1: Off-by-slash alias/proxy_pass traversal
	n1 := diffscan.NewProbe("Off-by-slash traversal", SeverityHigh, segment+"../")
	n1.Base = segment + "../"
	n1.InjectType = diffscan.InjectType_Replace
	n1.SetRandomAnchor(false)
	n1.SetEscapeStrings(segment+"/.", segment+"/./")
	if f := m.runProbeAndValidate("N1", "Off-by-slash traversal", inj, softBase, errorBase, parentBaselines, n1, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N2a: Encoded dot off-by-slash
	n2a := diffscan.NewProbe("Encoded dot off-by-slash", SeverityMedium, segment+"%2e%2e/", segment+"%2e%2e%2f")
	n2a.Base = segment + "%2e%2e/"
	n2a.InjectType = diffscan.InjectType_Replace
	n2a.SetRandomAnchor(false)
	n2a.SetEscapeStrings(segment+"/%2e/", segment+"/%2e")
	if f := m.runProbeAndValidate("N2a", "Encoded dot off-by-slash", inj, softBase, errorBase, parentBaselines, n2a, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N2b: Encoded dot standard
	n2b := diffscan.NewProbe("Encoded dot standard", SeverityMedium, segment+"/%2e%2e/", segment+"/%2e%2e%2f")
	n2b.Base = segment + "/%2e%2e/"
	n2b.InjectType = diffscan.InjectType_Replace
	n2b.SetRandomAnchor(false)
	n2b.SetEscapeStrings(segment+"/%2e/", segment+"/%2e")
	if f := m.runProbeAndValidate("N2b", "Encoded dot standard", inj, softBase, errorBase, parentBaselines, n2b, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N3: merge_slashes off
	n3 := diffscan.NewProbe("merge_slashes off", SeverityMedium, segment+"///../", segment+"////../")
	n3.Base = segment + "///../"
	n3.InjectType = diffscan.InjectType_Replace
	n3.SetRandomAnchor(false)
	n3.SetEscapeStrings(segment+"///.", segment+"///")
	if f := m.runProbeAndValidate("N3", "merge_slashes off", inj, softBase, errorBase, parentBaselines, n3, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N4: Backslash as forward slash
	n4 := diffscan.NewProbe("Backslash as slash", SeverityLow, segment+"..\\../", segment+"..\\..")
	n4.Base = segment + "..\\../"
	n4.InjectType = diffscan.InjectType_Replace
	n4.SetRandomAnchor(false)
	n4.SetEscapeStrings(segment+".\\.", segment+".\\.")
	if f := m.runProbeAndValidate("N4", "Backslash as slash", inj, softBase, errorBase, parentBaselines, n4, 2); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N5: Encoded slash normalization
	n5 := diffscan.NewProbe("Encoded slash normalization", SeverityMedium, segment+"..%2f..%2f", segment+"..%2f../")
	n5.Base = segment + "..%2f..%2f"
	n5.InjectType = diffscan.InjectType_Replace
	n5.SetRandomAnchor(false)
	n5.SetEscapeStrings(segment+".%2f./", segment+"/%2f./")
	if f := m.runProbeAndValidate("N5", "Encoded slash normalization", inj, softBase, errorBase, parentBaselines, n5, 2); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N6: $uri null byte
	n6 := diffscan.NewProbe("$uri null byte", SeverityLow, segment+"%00../", segment+"%00..")
	n6.Base = segment + "%00../"
	n6.InjectType = diffscan.InjectType_Replace
	n6.SetRandomAnchor(false)
	n6.SetEscapeStrings(segment+"%00./", segment+"%00.")
	if f := m.runProbeAndValidate("N6", "$uri null byte", inj, softBase, errorBase, parentBaselines, n6, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N8: Fully encoded path traversal
	n8 := diffscan.NewProbe("Full encoded traversal", SeverityHigh, segment+"/%2e%2e%2f", segment+"/%2e%2e/")
	n8.Base = segment + "/%2e%2e%2f"
	n8.InjectType = diffscan.InjectType_Replace
	n8.SetRandomAnchor(false)
	n8.SetEscapeStrings(segment+"/%2e/", segment+"/%2e%2f")
	if f := m.runProbeAndValidate("N8", "Full encoded traversal", inj, softBase, errorBase, parentBaselines, n8, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N9: URL-encoded fragment stripping
	n9 := diffscan.NewProbe("Fragment stripping", SeverityLow, segment+"%23/../", segment+"%23/..")
	n9.Base = segment + "%23/../"
	n9.InjectType = diffscan.InjectType_Replace
	n9.SetRandomAnchor(false)
	n9.SetEscapeStrings(segment+"%23/./", segment+"%23/")
	if f := m.runProbeAndValidate("N9", "Fragment stripping", inj, softBase, errorBase, parentBaselines, n9, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N10: Double encoding dots
	n10 := diffscan.NewProbe("Double encoding dots", SeverityMedium, segment+"%252e%252e/", segment+"%252e%252e%252f")
	n10.Base = segment + "%252e%252e/"
	n10.InjectType = diffscan.InjectType_Replace
	n10.SetRandomAnchor(false)
	n10.SetEscapeStrings(segment+"/%252e/", segment+"/%252e")
	if f := m.runProbeAndValidate("N10", "Double encoding dots", inj, softBase, errorBase, parentBaselines, n10, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N11: Rewrite double-encode slash
	n11 := diffscan.NewProbe("Rewrite double-encode slash", SeverityMedium, segment+"..%252f../", segment+"..%252f..")
	n11.Base = segment + "..%252f../"
	n11.InjectType = diffscan.InjectType_Replace
	n11.SetRandomAnchor(false)
	n11.SetEscapeStrings(segment+".%252f./", segment+"/%252f./")
	if f := m.runProbeAndValidate("N11", "Rewrite double-encode slash", inj, softBase, errorBase, parentBaselines, n11, 2); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N17: Overlong UTF-8 traversal
	n17 := diffscan.NewProbe("Overlong UTF-8 traversal", SeverityLow, segment+"%c0%ae%c0%ae/", segment+"%c0%ae%c0%ae%c0%af")
	n17.Base = segment + "%c0%ae%c0%ae/"
	n17.InjectType = diffscan.InjectType_Replace
	n17.SetRandomAnchor(false)
	n17.SetEscapeStrings(segment+"%c0%ae/", segment+"%c1%9c/")
	if f := m.runProbeAndValidate("N17", "Overlong UTF-8 traversal", inj, softBase, errorBase, parentBaselines, n17, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// --- Semicolon probes ---

	// N12a: Semicolon off-by-slash
	n12a := diffscan.NewProbe("Semicolon off-by-slash", SeverityHigh, segment+"..;/", segment+"..;foo/", segment+"..;bar/")
	n12a.Base = segment + "..;/"
	n12a.InjectType = diffscan.InjectType_Replace
	n12a.SetRandomAnchor(false)
	n12a.SetEscapeStrings(segment+"../", segment+".;/", segment+"..:")
	if f := m.runProbeAndValidate("N12a", "Semicolon off-by-slash", inj, softBase, errorBase, parentBaselines, n12a, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N12b: Semicolon standard
	n12b := diffscan.NewProbe("Semicolon standard", SeverityHigh, segment+"/..;/", segment+"/..;foo/", segment+"/..;bar/")
	n12b.Base = segment + "/..;/"
	n12b.InjectType = diffscan.InjectType_Replace
	n12b.SetRandomAnchor(false)
	n12b.SetEscapeStrings(segment+"/../", segment+"/.;/", segment+"/..:")
	if f := m.runProbeAndValidate("N12b", "Semicolon standard", inj, softBase, errorBase, parentBaselines, n12b, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N13a: Encoded semicolon off-by-slash
	n13a := diffscan.NewProbe("Encoded semicolon off-by-slash", SeverityMedium, segment+"..%3b/", segment+"..%3bfoo/")
	n13a.Base = segment + "..%3b/"
	n13a.InjectType = diffscan.InjectType_Replace
	n13a.SetRandomAnchor(false)
	n13a.SetEscapeStrings(segment+"..%3a/", segment+".%3b/")
	if f := m.runProbeAndValidate("N13a", "Encoded semicolon off-by-slash", inj, softBase, errorBase, parentBaselines, n13a, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N13b: Encoded semicolon standard
	n13b := diffscan.NewProbe("Encoded semicolon standard", SeverityMedium, segment+"/..%3b/", segment+"/..%3bfoo/")
	n13b.Base = segment + "/..%3b/"
	n13b.InjectType = diffscan.InjectType_Replace
	n13b.SetRandomAnchor(false)
	n13b.SetEscapeStrings(segment+"/..%3a/", segment+"/.%3b/")
	if f := m.runProbeAndValidate("N13b", "Encoded semicolon standard", inj, softBase, errorBase, parentBaselines, n13b, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N14: Semicolon nested
	n14 := diffscan.NewProbe("Semicolon nested", SeverityHigh, segment+";/..;/", segment+"..;/..;/")
	n14.Base = segment + ";/..;/"
	n14.InjectType = diffscan.InjectType_Replace
	n14.SetRandomAnchor(false)
	n14.SetEscapeStrings(segment+":/..:/", segment+";/../")
	if f := m.runProbeAndValidate("N14", "Semicolon nested", inj, softBase, errorBase, parentBaselines, n14, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// N15: Matrix parameter
	n15 := diffscan.NewProbe("Matrix parameter traversal", SeverityMedium, segment+"..;x=1/", segment+"/..;x=1/")
	n15.Base = segment + "..;x=1/"
	n15.InjectType = diffscan.InjectType_Replace
	n15.SetRandomAnchor(false)
	n15.SetEscapeStrings(segment+"..:x=1/", segment+"..#x=1/")
	if f := m.runProbeAndValidate("N15", "Matrix parameter traversal", inj, softBase, errorBase, parentBaselines, n15, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	// --- Other probes ---

	// N18: Regex newline bypass
	n18 := diffscan.NewProbe("Regex newline bypass", SeverityMedium, segment+"%0a/../", segment+"%0a/..")
	n18.Base = segment + "%0a/../"
	n18.InjectType = diffscan.InjectType_Replace
	n18.SetRandomAnchor(false)
	n18.SetEscapeStrings(segment+"%0a/./", segment+"%0b/../")
	if f := m.runProbeAndValidate("N18", "Regex newline bypass", inj, softBase, errorBase, parentBaselines, n18, 1); f != nil {
		f.SegmentPath = pathLevel
		f.SegmentIndex = levelIndex
		findings = append(findings, f)
	}

	return findings
}

// testFullPathProbes runs N7 and N16 probes on the full-path insertion point.
func (m *Module) testFullPathProbes(
	inj *diffscan.PayloadInjector,
	softBase, errorBase *diffscan.Attack,
	fullPath string,
) []*finding {
	var findings []*finding

	// N7: Double slash ACL bypass
	n7 := diffscan.NewProbe("Double slash ACL bypass", SeverityMedium, "/"+fullPath, "/"+fullPath+"/")
	n7.Base = "/" + fullPath
	n7.InjectType = diffscan.InjectType_Replace
	n7.SetRandomAnchor(false)
	n7.SetEscapeStrings(fullPath, fullPath+"/")
	if f := m.runProbeAndValidate("N7", "Double slash ACL bypass", inj, softBase, errorBase, nil, n7, 0); f != nil {
		f.ProbeInfo.RedirectMeansSafe = true
		f.ProbeInfo.IsACLBypass = true
		f.SegmentPath = fullPath
		f.SegmentIndex = 0
		findings = append(findings, f)
	}

	// N16: Case sensitivity ACL bypass
	upperPath := toUpperFirstAlpha(fullPath)
	if upperPath != fullPath {
		mixedPath := mixCase(fullPath)
		n16 := diffscan.NewProbe("Case sensitivity ACL bypass", SeverityMedium, upperPath, mixedPath)
		n16.Base = upperPath
		n16.InjectType = diffscan.InjectType_Replace
		n16.SetRandomAnchor(false)
		n16.SetEscapeStrings(fullPath, fullPath+"/")
		if f := m.runProbeAndValidate("N16", "Case sensitivity ACL bypass", inj, softBase, errorBase, nil, n16, 0); f != nil {
			f.ProbeInfo.IsACLBypass = true
			f.SegmentPath = fullPath
			f.SegmentIndex = 0
			findings = append(findings, f)
		}
	}

	return findings
}

// runProbeAndValidate runs a probe and validates the result using the unified validation logic.
func (m *Module) runProbeAndValidate(
	id, name string,
	inj *diffscan.PayloadInjector,
	softBase, errorBase *diffscan.Attack,
	parentBaselines map[int]*diffscan.Attack,
	probe *diffscan.Probe,
	traversalLevels int,
) *finding {
	zap.L().Debug("NginxPathEscape: runProbeAndValidate",
		zap.String("id", id),
		zap.String("probe", name),
		zap.Strings("breaks", probe.GetBreakStrings()),
		zap.String("escapes", fmt.Sprintf("%v", probe.GetAllEscapeSets())),
	)
	attacks, err := inj.Fuzz(softBase, probe)
	if err != nil {
		zap.L().Debug("NginxPathEscape: probe fuzz failed",
			zap.String("id", id), zap.String("probe", name), zap.Error(err))
		return nil
	}
	zap.L().Debug("NginxPathEscape: probe fuzz result",
		zap.String("id", id),
		zap.String("probe", name),
		zap.Int("attack_count", len(attacks)),
	)

	return m.validateAttacks(id, name, attacks, softBase, errorBase, parentBaselines, probe, traversalLevels)
}

// validateAttacks applies multi-layer validation to filter false positives.
func (m *Module) validateAttacks(
	id, name string,
	attacks []*diffscan.Attack,
	softBase, errorBase *diffscan.Attack,
	parentBaselines map[int]*diffscan.Attack,
	probe *diffscan.Probe,
	traversalLevels int,
) *finding {
	if len(attacks) < 2 {
		return nil
	}
	breakAttack := attacks[0]
	escapeAttack := attacks[1]

	zap.L().Debug("NginxPathEscape: validateAttacks",
		zap.String("id", id),
		zap.String("probe", name),
		zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
		zap.Int("escape_status", escapeAttack.FirstSnapshot.StatusCode),
		zap.Int("softBase_fp_keys", len(softBase.Fingerprint)),
		zap.Int("break_fp_keys", len(breakAttack.Fingerprint)),
		zap.Int("escape_fp_keys", len(escapeAttack.Fingerprint)),
	)

	// Layer 0: SoftBase must NOT match errorBase
	if errorBase != nil && diffscan.Similar(errorBase, softBase) {
		zap.L().Debug("NginxPathEscape: Layer0 REJECT - SoftBase matches errorBase",
			zap.String("id", id), zap.String("probe", name),
			zap.Int("softBase_status", softBase.FirstSnapshot.StatusCode),
		)
		return nil
	}

	// Layer 1: Break must differ from softBase
	if diffscan.Similar(softBase, breakAttack) {
		zap.L().Debug("NginxPathEscape: Layer1 REJECT - Break similar to softBase",
			zap.String("id", id), zap.String("probe", name),
			zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
			zap.Int("softBase_status", softBase.FirstSnapshot.StatusCode),
			zap.String("break_url", breakAttack.FirstSnapshot.URL),
			zap.String("softBase_url", softBase.FirstSnapshot.URL),
		)
		return nil
	}

	// Layer 2: CRITICAL - Escape MUST match softBase
	if !diffscan.Similar(softBase, escapeAttack) {
		if errorBase != nil && diffscan.Similar(errorBase, escapeAttack) {
			zap.L().Debug("NginxPathEscape: Layer2 REJECT - Escape matches errorBase",
				zap.String("id", id), zap.String("probe", name),
				zap.Int("escape_status", escapeAttack.FirstSnapshot.StatusCode),
				zap.String("escape_url", escapeAttack.FirstSnapshot.URL),
			)
			return nil
		}
		zap.L().Debug("NginxPathEscape: Layer2 REJECT - Escape differs from softBase",
			zap.String("id", id), zap.String("probe", name),
			zap.Int("escape_status", escapeAttack.FirstSnapshot.StatusCode),
			zap.Int("softBase_status", softBase.FirstSnapshot.StatusCode),
			zap.String("escape_url", escapeAttack.FirstSnapshot.URL),
			zap.String("softBase_url", softBase.FirstSnapshot.URL),
			zap.String("fp_diff", fingerprintDiff(softBase.Fingerprint, escapeAttack.Fingerprint)),
		)
		return nil
	}

	// Layer 3: Break must not match errorBase
	if errorBase != nil && diffscan.Similar(errorBase, breakAttack) {
		zap.L().Debug("NginxPathEscape: Layer3 REJECT - Break matches errorBase",
			zap.String("id", id), zap.String("probe", name),
			zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
		)
		return nil
	}

	// Layer 3.8: Filter path-normalization false positives
	if traversalLevels > 0 && parentBaselines != nil {
		expectedBaseline := parentBaselines[traversalLevels]
		if expectedBaseline != nil && diffscan.Similar(expectedBaseline, breakAttack) {
			zap.L().Debug("NginxPathEscape: Layer3.8 REJECT - Break matches expected normalized path",
				zap.String("id", id), zap.String("probe", name),
				zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
			)
			return nil
		}
	}

	// Layer 4: Break and escape must differ
	if diffscan.Similar(breakAttack, escapeAttack) {
		zap.L().Debug("NginxPathEscape: Layer4 REJECT - Break and escape too similar",
			zap.String("id", id), zap.String("probe", name),
			zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
			zap.Int("escape_status", escapeAttack.FirstSnapshot.StatusCode),
		)
		return nil
	}

	zap.L().Debug("NginxPathEscape: probe PASSED all layers",
		zap.String("id", id),
		zap.String("probe", name),
		zap.Int("break_status", breakAttack.FirstSnapshot.StatusCode),
		zap.Int("escape_status", escapeAttack.FirstSnapshot.StatusCode),
	)

	return &finding{
		ProbeInfo: &ProbeInfo{
			ID:              id,
			Name:            name,
			Probe:           probe,
			TraversalLevels: traversalLevels,
		},
		BreakAttack:  breakAttack,
		EscapeAttack: escapeAttack,
	}
}

// buildStabilizedBaseline sends request multiple times and merges fingerprints.
func (m *Module) buildStabilizedBaseline(
	payloadInjector *diffscan.PayloadInjector,
	payload string,
) (*diffscan.Attack, error) {
	base, err := payloadInjector.BuildAttack(payload, false)
	if err != nil {
		return nil, err
	}

	for i := 1; i < m.options.BaselineRequests; i++ {
		additionalBase, err := payloadInjector.BuildAttack(payload, false)
		if err != nil {
			continue
		}
		base.AddAttack(additionalBase)
	}

	zap.L().Debug("NginxPathEscape: baseline built",
		zap.String("payload", payload),
		zap.Int("status", base.FirstSnapshot.StatusCode),
		zap.Int("content_length", base.FirstSnapshot.ContentLength),
		zap.String("url", base.FirstSnapshot.URL),
		zap.Int("fp_keys", len(base.Fingerprint)),
	)

	return base, nil
}

// createLevelInsertionPoint creates a modified raw request (with query removed) and an
// insertion point at the last path segment for a given path level.
func createLevelInsertionPoint(rawRequest []byte, pathLevel string) ([]byte, httpmsg.InsertionPoint, error) {
	// Set raw request path to pathLevel — removes query string entirely
	modifiedReq, err := httpmsg.SetPath(rawRequest, pathLevel)
	if err != nil {
		return nil, nil, err
	}

	// Find path boundaries in modified request line
	newlineIdx := bytes.IndexByte(modifiedReq, '\n')
	if newlineIdx == -1 {
		return nil, nil, errors.New("invalid HTTP request: no newline found")
	}

	requestLine := modifiedReq[:newlineIdx]
	spaceIdx := bytes.IndexByte(requestLine, ' ')
	if spaceIdx == -1 {
		return nil, nil, errors.New("invalid HTTP request line: no space after method")
	}

	pathStart := spaceIdx + 1

	// Since SetPath removes query, path ends at the space before HTTP version
	pathEnd := bytes.LastIndexByte(requestLine, ' ')
	if pathEnd <= pathStart {
		return nil, nil, errors.New("invalid HTTP request line: no HTTP version")
	}

	// Find last "/" in path
	pathBytes := modifiedReq[pathStart:pathEnd]
	lastSlash := bytes.LastIndexByte(pathBytes, '/')
	if lastSlash == -1 {
		return nil, nil, errors.New("no slash in path")
	}

	// segmentStart = after the last "/"
	segmentStart := pathStart + lastSlash + 1
	segmentEnd := pathEnd

	// Handle trailing slash: /api/v1/ → segment is empty, back up one level
	if segmentStart == segmentEnd && lastSlash > 0 {
		prevSlash := bytes.LastIndexByte(pathBytes[:lastSlash], '/')
		if prevSlash == -1 {
			return nil, nil, errors.New("cannot find segment in path")
		}
		segmentStart = pathStart + prevSlash + 1
		segmentEnd = pathStart + lastSlash
	}

	// Create EncodedInsertionPoint
	segmentName := string(modifiedReq[segmentStart:segmentEnd])
	ip := httpmsg.NewEncodedInsertionPoint(
		segmentName,
		modifiedReq,
		segmentStart,
		segmentEnd,
		&httpmsg.NoopEncoder{},
		nil,
		httpmsg.INS_URL_PATH_FILENAME,
	)

	return modifiedReq, ip, nil
}

// createFullPathInsertionPoint creates an insertion point covering the entire URL path.
// Used for N7/N16 full-path ACL bypass probes.
func createFullPathInsertionPoint(rawRequest []byte) (httpmsg.InsertionPoint, error) {
	newlineIdx := bytes.IndexByte(rawRequest, '\n')
	if newlineIdx == -1 {
		return nil, errors.New("invalid HTTP request: no newline found")
	}

	requestLine := rawRequest[:newlineIdx]

	spaceIdx := bytes.IndexByte(requestLine, ' ')
	if spaceIdx == -1 {
		return nil, errors.New("invalid HTTP request line: no space after method")
	}

	pathStart := spaceIdx + 1
	remaining := requestLine[pathStart:]
	pathEnd := pathStart

	for i, b := range remaining {
		if b == ' ' || b == '?' {
			pathEnd = pathStart + i
			break
		}
	}

	if pathEnd == pathStart {
		lastSpaceIdx := bytes.LastIndexByte(remaining, ' ')
		if lastSpaceIdx == -1 {
			return nil, errors.New("invalid HTTP request line: no HTTP version")
		}
		pathEnd = pathStart + lastSpaceIdx
	}

	insertionPoint := httpmsg.NewEncodedInsertionPoint(
		"fullpath",
		rawRequest,
		pathStart,
		pathEnd,
		&httpmsg.NoopEncoder{},
		nil,
		httpmsg.INS_URL_PATH_FOLDER,
	)

	return insertionPoint, nil
}

// splitPathIntoLevels returns path levels from full path to root.
func splitPathIntoLevels(urlPath string) []string {
	if urlPath == "/" || urlPath == "" {
		return nil
	}

	cleanPath := strings.TrimSuffix(urlPath, "/")
	if cleanPath == "" {
		return nil
	}

	var levels []string
	currentPath := cleanPath

	for {
		levels = append(levels, currentPath)

		lastSlash := strings.LastIndex(currentPath, "/")
		if lastSlash <= 0 {
			break
		}
		currentPath = currentPath[:lastSlash]
	}

	return levels
}

// getParentPath returns the parent path of the given URL path.
func getParentPath(urlPath string) string {
	if urlPath == "/" || urlPath == "." || urlPath == "./" || urlPath == "" {
		return urlPath
	}

	trimmedPath := strings.TrimSuffix(urlPath, "/")

	if trimmedPath == "" {
		return "/"
	}

	lastSlashIndex := strings.LastIndex(trimmedPath, "/")

	switch lastSlashIndex {
	case -1:
		return "./"
	case 0:
		return "/"
	default:
		return trimmedPath[:lastSlashIndex+1]
	}
}

// toUpperFirstAlpha uppercases the first alphabetic character after the initial slash.
func toUpperFirstAlpha(p string) string {
	if len(p) < 2 {
		return p
	}
	for i := 1; i < len(p); i++ {
		c := rune(p[i])
		if unicode.IsLetter(c) && unicode.IsLower(c) {
			return p[:i] + string(unicode.ToUpper(c)) + p[i+1:]
		}
	}
	return p
}

// mixCase alternates case of alphabetic characters in the path (after initial slash).
func mixCase(p string) string {
	if len(p) < 2 {
		return p
	}
	result := []byte(p)
	toggle := true
	for i := 1; i < len(result); i++ {
		c := rune(result[i])
		if unicode.IsLetter(c) {
			if toggle {
				result[i] = byte(unicode.ToUpper(c))
			} else {
				result[i] = byte(unicode.ToLower(c))
			}
			toggle = !toggle
		}
	}
	return string(result)
}

// fingerprintDiff returns a string describing keys that differ between two fingerprint maps.
func fingerprintDiff(base, other map[string]any) string {
	var diffs []string
	for key, val := range base {
		otherVal, exists := other[key]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("%s: %v vs <missing>", key, val))
		} else if fmt.Sprintf("%v", val) != fmt.Sprintf("%v", otherVal) {
			diffs = append(diffs, fmt.Sprintf("%s: %v vs %v", key, val, otherVal))
		}
	}
	for key, val := range other {
		if _, exists := base[key]; !exists {
			diffs = append(diffs, fmt.Sprintf("%s: <missing> vs %v", key, val))
		}
	}
	if len(diffs) == 0 {
		return "<identical>"
	}
	return strings.Join(diffs, "; ")
}
