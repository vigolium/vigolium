package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"go.uber.org/zap"
)

// runSecretScanBatch scans all response bodies in the database for secrets using
// the native in-process detector (pkg/secretscan). Detection runs inline per
// record — no external binary, no temp files.
func (r *Runner) runSecretScanBatch(ctx context.Context, infra *phaseInfra, onResult func(*output.ResultEvent), inScopeHosts []database.HostTarget) error {
	if r.repository == nil {
		return fmt.Errorf("secret scan: database repository required")
	}

	det, err := secretscan.Default()
	if err != nil {
		return fmt.Errorf("secret scan: detector unavailable: %w", err)
	}

	zap.L().Info("KnownIssueScan: native secret scan — scanning response bodies for secrets")

	var cursor string
	var totalFindings, skippedCovered int
	defer func() {
		if skippedCovered > 0 {
			zap.L().Debug("KnownIssueScan: secret scan skipped records already covered by dynamic assessment",
				zap.Int("skipped", skippedCovered))
		}
	}()
	// Collapse the same secret re-observed on the same URL across records (the
	// same page can survive record-dedup under different paths/sources): emit one
	// finding per (host, url, rule, snippet) so near-identical request/response
	// copies don't pile up as redundant Additional Evidence. Run-scoped across
	// batches; bounded by the number of distinct secrets, which is small.
	seenSecret := make(map[string]struct{})
	for {
		// Break promptly when the phase/scan budget elapses. Returning ctx.Err()
		// lets the caller log the secret-scan curtailment notice rather than
		// treating it as a failure.
		if err := ctx.Err(); err != nil {
			return err
		}

		records, err := r.repository.GetRecordsWithResponseBody(ctx, r.options.ProjectUUID, cursor, secretScanBatchSize, inScopeHosts...)
		if err != nil {
			return fmt.Errorf("secret scan: failed to fetch records: %w", err)
		}
		if len(records) == 0 {
			break
		}

		for _, record := range records {
			cursor = record.UUID

			if err := ctx.Err(); err != nil {
				return err
			}
			// Dynamic assessment's secret_detect already analysed this record's
			// response; scanning it again yields the same findings.
			if r.secretCoverage.has(record.UUID) {
				skippedCovered++
				continue
			}

			// Parse the raw response once so we can both scan the body and inspect
			// the status/headers for the severity decision below.
			resp := record.ParsedResponse()
			if resp == nil {
				continue
			}
			// A WAF/CDN edge block is the edge talking, not the application, so its
			// challenge/error page's random tokens must never be scanned as app
			// secrets — same guard the passive path applies.
			if modkit.IsEdgeBlockedResponse(resp) {
				continue
			}
			body := resp.Body()
			// Shared eligibility policy (size cap + media + text MIME) — the batch
			// previously filtered on MIME alone, letting oversized or mislabeled
			// binary bodies reach the detector.
			if !secret_detect.ShouldScanBody(record.ResponseContentType, record.URL, len(body)) {
				continue
			}

			matches := det.Detect(body)
			if len(matches) == 0 {
				continue
			}

			ev := secret_detect.EvidenceContext{
				Body:         body,
				Host:         record.Hostname,
				URL:          record.URL,
				Request:      string(record.RawRequest),
				RespHead:     string(resp.Head()),
				StatusCode:   resp.StatusCode(),
				ContentType:  record.ResponseContentType,
				HeaderValues: secret_detect.JoinHeaderValues(resp.Headers()),
			}

			totalFindings += r.emitSecretFindings(ctx, infra, matches, ev, seenSecret, onResult, secretEmitOptions{
				RecordUUIDs: []string{record.UUID},
				ModuleShort: "Leaked secret detected in HTTP response body",
			})
		}

		if len(records) < secretScanBatchSize {
			break
		}
	}

	recovered, err := r.scanRecoveredSourcesForSecrets(ctx, infra, det, seenSecret, onResult, inScopeHosts)
	if err != nil {
		return err
	}
	totalFindings += recovered

	zap.L().Info("KnownIssueScan: native secret scan completed", zap.Int("findings", totalFindings))
	return nil
}

// secretEmitOptions varies the parts of a secret finding that differ by corpus.
type secretEmitOptions struct {
	// RecordUUIDs anchors the finding to the traffic it came from. May be empty.
	RecordUUIDs []string
	// ModuleShort is the one-line label shown in reports.
	ModuleShort string
	// ExtraTags are appended after the shared known-issue-scan tag.
	ExtraTags []string
	// DescriptionSuffix appends provenance the shared grading cannot know.
	DescriptionSuffix string
}

// emitSecretFindings turns graded detector matches into saved findings.
//
// Both secret-scan corpora — stored response bodies and source-map-recovered
// originals — funnel through here so the rule for what becomes a finding has one
// home. The two were written separately at first and had already drifted on which
// guards they applied, the same way the size cap and media filtering drifted
// before ShouldScanBodyForSecrets centralized them.
func (r *Runner) emitSecretFindings(
	ctx context.Context,
	infra *phaseInfra,
	matches []secretscan.Match,
	ev secret_detect.EvidenceContext,
	seenSecret map[string]struct{},
	onResult func(*output.ResultEvent),
	opts secretEmitOptions,
) int {
	emitted := 0
	for _, mt := range matches {
		// Skip a secret already reported on this URL. Marked seen only after
		// GradeMatch's body-dependent guards pass, so a blob/JS-escape drop never
		// suppresses a genuine match of the same value elsewhere. The map is shared
		// across corpora: the same credential usually appears both in the shipped
		// bundle and in the original source it was compiled from, and that is one
		// finding.
		dedupKey := secret_detect.SecretDedupKey(ev.Host, ev.URL, mt.RuleID, mt.Secret)
		if _, dup := seenSecret[dedupKey]; dup {
			continue
		}

		// Grade the match — structural false-positive guard, severity downgrades
		// (redirect/header/request reflections, docs-demo samples, public
		// reCAPTCHA/OAuth identifiers, low-value JWTs, Google API keys), and evidence
		// reconstruction — via the same helper the passive module uses.
		event, ok := secret_detect.GradeMatch(mt, ev)
		if !ok {
			continue
		}
		seenSecret[dedupKey] = struct{}{}

		// Tag with the secret-detect module ID (same as the passive path) so the
		// URL-keyed finding dedup excludes these too — distinct secrets on one URL
		// are not duplicates. Without it KIS findings carry an empty module_id and
		// would merge with each other (and other empty-id findings) by URL+severity.
		event.ModuleID = secret_detect.ModuleID
		event.Info.Tags = append(event.Info.Tags, "known-issue-scan")
		event.Info.Tags = append(event.Info.Tags, opts.ExtraTags...)
		event.Info.Description += opts.DescriptionSuffix
		// secret-detect is a passive module; label it "passive" like its
		// dynamic-assessment path does (where the executor sets that automatically).
		// FindingSource still records that this one came from known-issue-scan.
		event.ModuleType = database.ModuleTypePassive
		event.FindingSource = database.FindingSourceKnownIssueScan
		event.ModuleShort = opts.ModuleShort

		if saveErr := r.repository.SaveFinding(ctx, event, opts.RecordUUIDs, infra.scanUUID, r.options.ProjectUUID); saveErr != nil {
			zap.L().Debug("Failed to save secret finding", zap.Error(saveErr))
		}
		if onResult != nil {
			onResult(event)
		}
		emitted++
	}
	return emitted
}

// scanRecoveredSourcesForSecrets scans original source files recovered from
// source maps, which are stored as analysis artifacts beside the bundle record
// rather than as response bodies of their own — so the record loop above never
// reaches them.
//
// This is where the yield is. A minified bundle mangles local identifiers, so the
// name-anchored rules ("apiKey", "secret", "password" near a literal) that catch
// most hardcoded credentials fire far less often on the shipped bundle than on
// the original TypeScript the map hands back verbatim.
//
// Findings are attributed to the generated bundle's URL and record, because that
// is the URL an operator can actually re-fetch; the source path travels in the
// evidence and the finding name.
func (r *Runner) scanRecoveredSourcesForSecrets(
	ctx context.Context,
	infra *phaseInfra,
	det *secretscan.Detector,
	seenSecret map[string]struct{},
	onResult func(*output.ResultEvent),
	inScopeHosts []database.HostTarget,
) (int, error) {
	// Same host scope as the record loop above. Artifacts are project-scoped in the
	// database, so without this the corpus would silently differ between the two
	// halves of one secret scan — and include hosts this scan was told to skip.
	hostInScope := func(hostname string) bool {
		if len(inScopeHosts) == 0 {
			return true
		}
		for _, target := range inScopeHosts {
			if strings.EqualFold(target.Hostname, hostname) {
				return true
			}
			if port := fmt.Sprintf("%s:%d", target.Hostname, target.Port); strings.EqualFold(port, hostname) {
				return true
			}
		}
		return false
	}

	found := 0
	var lastGeneratedURL, lastHostname string
	err := r.repository.StreamAnalysisArtifactsByKind(
		ctx, r.options.ProjectUUID, database.AnalysisArtifactKindSourceMapOriginal, secretScanBatchSize,
		func(artifact *database.AnalysisArtifact) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !secret_detect.ShouldScanBody(artifact.MediaType, artifact.Filename, len(artifact.Content)) {
				return nil
			}

			generatedURL, sourcePath := sourceMapArtifactOrigin(artifact)
			// One map contributes up to 512 artifacts, and the stream is in id order,
			// so they arrive consecutively with identical origins. Memo the parse.
			if generatedURL != lastGeneratedURL {
				lastGeneratedURL = generatedURL
				lastHostname = ""
				if parsed, parseErr := url.Parse(generatedURL); parseErr == nil {
					lastHostname = parsed.Host
				}
			}
			hostname := lastHostname
			if !hostInScope(hostname) {
				return nil
			}

			matches := det.Detect(artifact.Content)
			if len(matches) == 0 {
				return nil
			}

			ev := secret_detect.EvidenceContext{
				Body: artifact.Content,
				Host: hostname,
				URL:  generatedURL,
			}
			var recordUUIDs []string
			if artifact.HTTPRecordUUID != "" {
				recordUUIDs = []string{artifact.HTTPRecordUUID}
			}

			found += r.emitSecretFindings(ctx, infra, matches, ev, seenSecret, onResult, secretEmitOptions{
				RecordUUIDs: recordUUIDs,
				ModuleShort: "Leaked secret detected in source-map-recovered source",
				ExtraTags:   []string{"source-map", "recovered-source"},
				DescriptionSuffix: fmt.Sprintf(
					"\n\nRecovered from the source map of %s, in original source %s.",
					generatedURL, sourcePath),
			})
			return nil
		})
	if err != nil {
		return found, err
	}
	if found > 0 {
		zap.L().Info("KnownIssueScan: secrets recovered from source-map originals", zap.Int("findings", found))
	}
	return found, nil
}

// sourceMapArtifactOrigin reads the generated bundle URL and original source path
// an artifact was recovered from. Both live in the artifact metadata written by
// the discovery source; the filename is the fallback for the source path.
func sourceMapArtifactOrigin(artifact *database.AnalysisArtifact) (generatedURL, sourcePath string) {
	sourcePath = artifact.Filename
	if artifact.Metadata == "" {
		return "", sourcePath
	}
	var meta struct {
		GeneratedURL string `json:"generated_url"`
		SourcePath   string `json:"source_path"`
	}
	// The column is declared jsonb. PostgreSQL stores the object natively; SQLite
	// round-trips the Go string through JSON encoding, so the same value comes back
	// as a quoted string containing JSON. A leading quote says which shape this is,
	// so the common path costs one unmarshal on either driver rather than failing
	// into a retry.
	raw := []byte(strings.TrimSpace(artifact.Metadata))
	if len(raw) > 0 && raw[0] == '"' {
		var nested string
		if err := json.Unmarshal(raw, &nested); err != nil {
			return "", sourcePath
		}
		raw = []byte(nested)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", sourcePath
	}
	if meta.SourcePath != "" {
		sourcePath = meta.SourcePath
	}
	return meta.GeneratedURL, sourcePath
}
