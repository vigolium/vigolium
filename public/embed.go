package public

import "embed"

//go:embed all:*
var StaticFS embed.FS

//go:embed vigolium-configs.example.yaml
var DefaultConfigYAML []byte

//go:embed default-users.json
var DefaultUsersJSON []byte
