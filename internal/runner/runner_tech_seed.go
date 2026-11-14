package runner

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"go.uber.org/zap"
)

// techByHostFromStoredFacts reads the stack the fingerprint phase (this scan's
// or an earlier one in the same project) stored in host_observations, newest
// observation per endpoint, and returns it keyed by modkit.RegistryHostKey
// (hostname, plus ":port" off the default ports). Only detections at medium
// confidence or better are kept: the tech gate EXCLUDES modules on a positive
// identification, so a low-confidence guess must not be one.
//
// Without it the dynamic-assessment tech registry would start empty and the
// gate fail open on every host until a passive fingerprint module happened to
// re-detect the stack mid-phase.
func (r *Runner) techByHostFromStoredFacts(ctx context.Context) map[string][]string {
	if r.repository == nil {
		return nil
	}
	project := r.options.ProjectUUID
	if project == "" {
		project = database.DefaultProjectUUID
	}
	reports, err := r.storedFingerprints(ctx, project, "")
	if err != nil {
		zap.L().Debug("tech seed: reading stored host facts failed", zap.Error(err))
		return nil
	}
	out := make(map[string][]string)
	for ep, report := range reports {
		key := registryKeyForEndpoint(ep.host, ep.port)
		if key == "" {
			continue
		}
		seen := make(map[string]struct{}, len(out[key]))
		for _, t := range out[key] {
			seen[t] = struct{}{}
		}
		for _, tag := range stackTagsFromReport(report) {
			if _, dup := seen[tag]; dup {
				continue
			}
			seen[tag] = struct{}{}
			out[key] = append(out[key], tag)
		}
	}
	return out
}

// fingerprintEndpoint keys a stored fingerprint: lowercased hostname and port.
type fingerprintEndpoint struct {
	host string
	port int
}

// storedFingerprints returns the latest fingerprint report host_observations
// holds per endpoint in projectUUID ("" reads every project), limited to
// scanUUID's observations when set. The one reader of stored fingerprints for
// the tech-registry seed and the known-issue scan's tech selection.
func (r *Runner) storedFingerprints(ctx context.Context, projectUUID, scanUUID string) (map[fingerprintEndpoint]*recon.TechStackReport, error) {
	rows, _, err := r.repository.ListHostObservationsWithCount(ctx, database.HostObservationQuery{
		ProjectUUID: projectUUID, ScanUUID: scanUUID, Has: "fingerprint",
	})
	if err != nil {
		return nil, err
	}
	out := make(map[fingerprintEndpoint]*recon.TechStackReport, len(rows))
	for _, row := range rows {
		if row.Fingerprint != nil {
			out[fingerprintEndpoint{host: strings.ToLower(row.Hostname), port: row.Port}] = row.Fingerprint
		}
	}
	return out, nil
}

// stackTagsFromReport returns the gating stack tags of report's detections at
// medium confidence or better: the detection's module Tag, else its Name when
// that is itself a stack tag.
func stackTagsFromReport(report *recon.TechStackReport) []string {
	var tags []string
	for _, d := range report.Stacks {
		if d.Confidence < recon.ConfidenceMedium {
			continue
		}
		for _, cand := range []string{d.Tag, d.Name} {
			cand = strings.ToLower(strings.TrimSpace(cand))
			if cand != "" && modkit.IsStackTag(cand) {
				tags = append(tags, cand)
				break
			}
		}
	}
	return tags
}

// registryKeyForEndpoint renders hostname:port the way RegistryHostKey keys a
// request (URL host): the bare hostname on 80/443, else host:port.
func registryKeyForEndpoint(hostname string, port int) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return ""
	}
	if port == 0 || port == 80 || port == 443 {
		return hostname
	}
	return net.JoinHostPort(hostname, strconv.Itoa(port))
}

// seedTechRegistry marks the stored stack facts on reg before the first round.
func (r *Runner) seedTechRegistry(ctx context.Context, reg *modkit.TechRegistry) int {
	if reg == nil {
		return 0
	}
	n := 0
	for host, tags := range r.techByHostFromStoredFacts(ctx) {
		for _, tag := range tags {
			reg.Mark(host, tag)
			n++
		}
	}
	return n
}
