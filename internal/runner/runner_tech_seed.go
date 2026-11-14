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
// Without it the dynamic-assessment tech registry started empty and the gate
// failed open on every host until a passive fingerprint module happened to
// re-detect the stack mid-phase (MISS-21).
func (r *Runner) techByHostFromStoredFacts(ctx context.Context) map[string][]string {
	if r.repository == nil {
		return nil
	}
	project := r.options.ProjectUUID
	if project == "" {
		project = database.DefaultProjectUUID
	}
	rows, _, err := r.repository.ListHostObservationsWithCount(ctx, database.HostObservationQuery{
		ProjectUUID: project,
		Has:         "fingerprint",
	})
	if err != nil {
		zap.L().Debug("tech seed: reading stored host facts failed", zap.Error(err))
		return nil
	}
	out := make(map[string][]string)
	for _, row := range rows {
		if row.Fingerprint == nil {
			continue
		}
		key := registryKeyForEndpoint(row.Hostname, row.Port)
		if key == "" {
			continue
		}
		seen := make(map[string]struct{}, len(out[key]))
		for _, t := range out[key] {
			seen[t] = struct{}{}
		}
		for _, tag := range stackTagsFromReport(row.Fingerprint) {
			if _, dup := seen[tag]; dup {
				continue
			}
			seen[tag] = struct{}{}
			out[key] = append(out[key], tag)
		}
	}
	return out
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
