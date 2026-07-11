package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/vigolium/vigolium/pkg/secretscan/catalog"
)

// kfFile is one kingfisher rules YAML file (data/rules/<provider>.yml).
type kfFile struct {
	Rules []kfRule `yaml:"rules"`
}

type kfRule struct {
	Name       string   `yaml:"name"`
	ID         string   `yaml:"id"`
	Pattern    string   `yaml:"pattern"`
	MinEntropy float64  `yaml:"min_entropy"`
	Confidence string   `yaml:"confidence"`
	Visible    *bool    `yaml:"visible"`
	Reqs       kfReqs   `yaml:"pattern_requirements"`
	Examples   []string `yaml:"examples"`
}

type kfReqs struct {
	MinDigits  int `yaml:"min_digits"`
	MinLower   int `yaml:"min_lowercase"`
	MinUpper   int `yaml:"min_uppercase"`
	MinSpecial int `yaml:"min_special_chars"`
}

// loadKingfisher parses every *.yml under dir and returns normalized catalog
// rules plus a per-rule example corpus (id -> positive examples) for tests.
// Patterns that fail to compile under RE2 after normalization are skipped and
// reported via the returned dropped slice.
func loadKingfisher(dir string) (rules []catalog.Rule, examples map[string][]string, dropped []droppedRule, err error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(files) == 0 {
		return nil, nil, nil, fmt.Errorf("no kingfisher rule files found in %s", dir)
	}
	sort.Strings(files)
	examples = map[string][]string{}

	for _, f := range files {
		raw, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil, nil, nil, rerr
		}
		var kf kfFile
		if uerr := yaml.Unmarshal(raw, &kf); uerr != nil {
			return nil, nil, nil, fmt.Errorf("parse %s: %w", filepath.Base(f), uerr)
		}
		for _, r := range kf.Rules {
			if r.Pattern == "" || r.ID == "" {
				continue
			}
			norm := normalize(r.Pattern)
			if reason, ok := compileCheck(norm); !ok {
				dropped = append(dropped, droppedRule{ID: r.ID, Source: "kingfisher", Reason: reason, Pattern: r.Pattern})
				continue
			}
			visible := true
			if r.Visible != nil {
				visible = *r.Visible
			}
			rule := catalog.Rule{
				ID:          r.ID,
				Name:        r.Name,
				Src:         "kingfisher",
				Re:          norm,
				Kw:          extractKeywords(norm),
				Entropy:     r.MinEntropy,
				MinDigits:   r.Reqs.MinDigits,
				MinLower:    r.Reqs.MinLower,
				MinUpper:    r.Reqs.MinUpper,
				MinSpecial:  r.Reqs.MinSpecial,
				Confidence:  normConfidence(r.Confidence),
				SecretGroup: 0, // kingfisher uses auto capture-selection (TOKEN/named/g1/g0)
				Visible:     visible,
			}
			rules = append(rules, rule)
			if len(r.Examples) > 0 {
				examples[r.ID] = append(examples[r.ID], r.Examples...)
			}
		}
	}
	return rules, examples, dropped, nil
}

func normConfidence(c string) string {
	switch c {
	case "high", "medium", "low":
		return c
	default:
		return "medium"
	}
}
