package cli

import (
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/database"
)

// trafficTags backs `traffic --tag k=v`: records carrying every label
// (record_tags, written by `import --tag`).
var trafficTags []string

func registerTrafficTagFlag(flags *pflag.FlagSet) {
	flags.StringArrayVar(&trafficTags, "tag", nil,
		"Only records carrying this key=value label (written by 'import --tag'); repeatable, AND-combined. -j rows carry their labels under tags")
}

// parseTagFilterFlag parses a repeatable --tag selector (traffic, db clean).
func parseTagFilterFlag(raw []string) ([]database.RecordTag, error) {
	tags, err := database.ParseRecordTags(raw)
	if err != nil {
		return nil, usageErrorf("--tag: %v", err)
	}
	return tags, nil
}
