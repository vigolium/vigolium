package cli

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/contract"
)

// Every advertised feature still exists: its flag, variable, settings key,
// command, document field or event field. A feature list that names something
// the binary no longer has is worse than none, because a caller gates on it.
func TestVersionFeaturesExist(t *testing.T) {
	settingKeys := map[string]bool{}
	for _, e := range config.SettingEntries(config.DefaultSettings()) {
		settingKeys[e.Key] = true
	}
	envs := map[string]bool{}
	for _, e := range config.EnvRegistry {
		envs[e.Name] = true
	}
	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	seen := map[string]bool{}

	for _, f := range versionFeatures {
		t.Run(f.Name, func(t *testing.T) {
			require.Regexp(t, kebab, f.Name, "feature names are stable kebab-case")
			require.False(t, seen[f.Name], "duplicate feature")
			seen[f.Name] = true
			require.True(t, f.Command != "" || f.Flag != "" || f.Env != "" || f.ConfigKey != "" || f.Event != "",
				"a feature names its evidence")

			cmd := rootCmd
			if f.Command != "" {
				found, _, err := rootCmd.Find(strings.Fields(f.Command))
				require.NoError(t, err)
				require.Equal(t, f.Command, commandPathWithoutRoot(found), "command %q exists", f.Command)
				cmd = found
			}
			if f.Flag != "" {
				fl := cmd.Flags().Lookup(f.Flag)
				if fl == nil {
					fl = cmd.InheritedFlags().Lookup(f.Flag)
				}
				if fl == nil {
					fl = rootCmd.PersistentFlags().Lookup(f.Flag)
				}
				require.NotNil(t, fl, "flag --%s on %q", f.Flag, f.Command)
				if f.FlagValue != "" {
					assert.Contains(t, fl.Usage, f.FlagValue, "--%s accepts %q", f.Flag, f.FlagValue)
				}
			}
			if f.Env != "" {
				assert.True(t, envs[f.Env], "%s is a registered variable", f.Env)
			}
			if f.ConfigKey != "" {
				assert.True(t, settingKeys[f.ConfigKey], "%s is a settings key", f.ConfigKey)
			}
			if f.Field != "" && f.Event == "" {
				vocab := commandTraits[f.Command].Shape.staticVocab(f.Command)
				if !slices.Contains(vocab, f.Field) {
					s, err := contract.CommandSchema(f.Command)
					require.NoError(t, err, "%q has a registered schema", f.Command)
					raw, _ := json.Marshal(s)
					assert.Contains(t, string(raw), `"`+f.Field+`"`, "%q -j carries %s", f.Command, f.Field)
				}
			}
			if f.Event != "" {
				s, err := contract.EventSchema(f.Event)
				require.NoError(t, err, "event %q", f.Event)
				raw, _ := json.Marshal(s)
				assert.Contains(t, string(raw), `"`+f.Field+`"`, "%s carries %s", f.Event, f.Field)
			}
		})
	}

	for _, must := range []string{"no-redact", "redact-env", "offline", "resume-scan", "redirect-in-scope",
		"replay-no-save", "no-auth", "external-lookups-config", "oast-keep-session", "require-scope",
		"claimed-severity", "vuln-class", "schema-traits", "scan-finished-caveats", "kit-cookies"} {
		assert.Contains(t, versionFeatureNames(), must)
	}
}

// version -j carries the list on items[0].
func TestVersionJSONCarriesFeatures(t *testing.T) {
	doc := emitCaptured(t, func() error { return printVersionJSON(versionCmd) })
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	features, ok := items[0].(map[string]any)["features"].([]any)
	require.True(t, ok, "items[0].features is an array")
	got := make([]string, len(features))
	for i, f := range features {
		got[i] = f.(string)
	}
	assert.Equal(t, versionFeatureNames(), got)
	assert.Equal(t, false, doc["redacted"], "version has no raw view to mask")
}
