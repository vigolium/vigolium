package cli

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/types"
)

// Caller tags are opaque key=value labels a driver attaches to one
// invocation (`--caller-tag engagement=e1 --caller-tag leg=sweep`, or
// VIGOLIUM_CALLER_TAG=engagement=e1,leg=sweep), so every row the invocation
// writes can be attributed back to it without matching by time window:
//
//   - the scans row of a scan, and the scans row a hand-sent save, an ingest
//     or a bridge import creates, carries them in scans.tags (as sorted
//     "k=v" strings);
//   - every record such a command stores carries that row's scan_uuid;
//   - scan.started carries them as the caller_tags object.
//
// vigolium never interprets them. A flag wins over the variable for the same
// key; a malformed tag is a usage error (exit 2) before anything runs.

// callerTagEnvVar holds comma-separated key=value caller tags.
const callerTagEnvVar = "VIGOLIUM_CALLER_TAG"

// globalCallerTags backs the repeatable --caller-tag flag.
var globalCallerTags []string

// callerTags is the invocation's resolved tag set ("k=v", sorted by key),
// set once by the root PersistentPreRunE (applyCallerTags).
var callerTags []string

// callerTagKey is what a key may contain: a driver's identifiers, and nothing
// that would need quoting in the "k=v" form or the env list.
var callerTagKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// maxCallerTagValue bounds one value; a tag is a label, not a payload.
const maxCallerTagValue = 256

func init() {
	rootCmd.PersistentFlags().StringArrayVar(&globalCallerTags, "caller-tag", nil,
		"Label this invocation key=value (repeatable): stored on the scan row it writes (scans.tags), on every record it stores (via that row's scan_uuid) and on scan.started (caller_tags). Also $"+callerTagEnvVar+"=k=v,k2=v2; a flag wins for the same key")
}

// applyCallerTags resolves --caller-tag and VIGOLIUM_CALLER_TAG into
// callerTags, refusing a malformed tag.
func applyCallerTags() error {
	tags, err := resolveCallerTags(os.Getenv(callerTagEnvVar), globalCallerTags)
	if err != nil {
		return asUsageError(err)
	}
	callerTags = tags
	if scanOpts != nil {
		// The scan pipeline's options are scanOpts itself; the other runner
		// paths copy callerTags when they build theirs.
		scanOpts.CallerTags = tags
	}
	return nil
}

// resolveCallerTags merges the env list and the flag values (flags win per
// key) into sorted "k=v" strings; nil when there are none.
func resolveCallerTags(env string, flags []string) ([]string, error) {
	merged := map[string]string{}
	add := func(origin, raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		key, value, ok := strings.Cut(raw, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case !ok:
			return fmt.Errorf("%s %q: want key=value", origin, raw)
		case !callerTagKey.MatchString(key):
			return fmt.Errorf("%s %q: the key must be 1-64 letters, digits, '_', '.', ':' or '-', starting with a letter or digit", origin, raw)
		case len(value) > maxCallerTagValue:
			return fmt.Errorf("%s %q: the value is longer than %d bytes", origin, key, maxCallerTagValue)
		case strings.ContainsAny(value, "\r\n\x00"):
			return fmt.Errorf("%s %q: the value may not contain a newline or NUL", origin, key)
		}
		merged[key] = value
		return nil
	}
	for _, part := range strings.Split(env, ",") {
		if err := add(callerTagEnvVar, part); err != nil {
			return nil, err
		}
	}
	for _, f := range flags {
		if err := add("--caller-tag", f); err != nil {
			return nil, err
		}
	}
	if len(merged) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(merged))
	for k, v := range merged {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

// callerTagMap is tags ("k=v") as the caller_tags object of scan.started;
// nil when there are none.
func callerTagMap(tags []string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		k, v, _ := strings.Cut(t, "=")
		out[k] = v
	}
	return out
}

// callerTagsOf is opts' caller tags, falling back to the invocation's when a
// path built its options without them.
func callerTagsOf(opts *types.Options) []string {
	if opts != nil && len(opts.CallerTags) > 0 {
		return opts.CallerTags
	}
	return callerTags
}
