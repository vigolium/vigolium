package config

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Setting sources, as `config ls --effective` reports them.
const (
	SourceDefault = "default"
	SourceFile    = "file"
	SourceProject = "project"
	SourceProfile = "profile"
	SourceFlag    = "flag"
	// SourceEnvPrefix prefixes the variable that supplied a value: "env:NAME".
	SourceEnvPrefix = "env:"
)

// TraceOptions names the layers TraceSources inspects.
type TraceOptions struct {
	// ConfigPath is the --config value ("" = the discovered config file).
	ConfigPath string
	// ProjectUUID selects the project overlay ("" or the default project's
	// absent overlay = none).
	ProjectUUID string
	// ProfilePath is a scanning profile applied on top ("" = none).
	ProfilePath string
	// FlagKeys are keys a command-line flag set for this run.
	FlagKeys []string
}

// envRefInValue matches ${NAME}, ${NAME:-default} and $NAME references.
var envRefInValue = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// TraceSources reports, for every key a layer set, the layer that decided its
// effective value: the config file (or env:NAME when the file's value is a
// ${NAME} placeholder the environment filled), the project overlay, a
// scanning profile, a variable the binary reads directly (EnvRegistry
// overrides), or a flag. Keys absent from the map come from the defaults.
//
// Later layers win, matching the load order: file → project → profile →
// environment override → flag.
func TraceSources(opts TraceOptions) (map[string]string, error) {
	sources := map[string]string{}
	path, err := resolveConfigFile(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if path != "" {
		if err := traceYAMLFile(path, SourceFile, sources); err != nil {
			return nil, err
		}
	}
	if opts.ProjectUUID != "" {
		if err := traceYAMLFile(ProjectConfigPath(opts.ProjectUUID), SourceProject, sources); err != nil {
			return nil, err
		}
	}
	if opts.ProfilePath != "" {
		if err := traceYAMLFile(ExpandPath(opts.ProfilePath), SourceProfile, sources); err != nil {
			return nil, err
		}
	}
	for _, v := range EnvRegistry {
		if v.OverridesKey == "" {
			continue
		}
		if val, ok := os.LookupEnv(v.Name); ok && val != "" {
			sources[v.OverridesKey] = SourceEnvPrefix + v.Name
		}
	}
	for _, k := range opts.FlagKeys {
		sources[k] = SourceFlag
	}
	return sources, nil
}

// SourceOf is the source TraceSources reports for key, or SourceDefault.
func SourceOf(sources map[string]string, key string) string {
	if s, ok := sources[key]; ok {
		return s
	}
	// A key under a map or list value set as a whole (api_keys set as one
	// mapping) takes its parent's source.
	for k := key; ; {
		i := strings.LastIndexByte(k, '.')
		if i < 0 {
			return SourceDefault
		}
		k = k[:i]
		if s, ok := sources[k]; ok {
			return s
		}
	}
}

// resolveConfigFile is the file LoadSettings reads, or "" when there is none.
func resolveConfigFile(configPath string) (string, error) {
	if configPath != "" {
		return ExpandPath(configPath), nil
	}
	for _, p := range []string{ExpandPath("~/.vigolium/vigolium-configs.yaml"), "./vigolium-configs.yaml"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return "", nil
}

// traceYAMLFile records the leaves of the raw (unexpanded) YAML file at path
// as set by layer, or by env:NAME when the leaf is a placeholder the
// environment filled. A missing file sets nothing.
func traceYAMLFile(path, layer string, sources map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return nil
	}
	traceNode("", doc.Content[0], layer, sources)
	return nil
}

func traceNode(prefix string, n *yaml.Node, layer string, sources map[string]string) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			traceNode(joinKey(prefix, n.Content[i].Value), n.Content[i+1], layer, sources)
		}
		if len(n.Content) == 0 && prefix != "" {
			sources[prefix] = layer
		}
	case yaml.AliasNode:
		if n.Alias != nil {
			traceNode(prefix, n.Alias, layer, sources)
		}
	default:
		if prefix == "" {
			return
		}
		sources[prefix] = layer
		if name := filledEnvRef(n); name != "" {
			sources[prefix] = SourceEnvPrefix + name
		}
	}
}

// filledEnvRef returns the first variable a scalar (or a list's scalars)
// references that is set in the environment, or "".
func filledEnvRef(n *yaml.Node) string {
	values := []string{n.Value}
	if n.Kind == yaml.SequenceNode {
		values = values[:0]
		for _, c := range n.Content {
			values = append(values, c.Value)
		}
	}
	for _, v := range values {
		for _, m := range envRefInValue.FindAllStringSubmatch(v, -1) {
			name := m[1]
			if name == "" {
				name = m[3]
			}
			if os.Getenv(name) != "" {
				return name
			}
		}
	}
	return ""
}
