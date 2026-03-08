package public

import "embed"

//go:embed all:*
var StaticFS embed.FS

//go:embed vigolium-configs.example.yaml
var DefaultConfigYAML []byte
