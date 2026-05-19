package wordlists

import "embed"

//go:embed *.txt *.list
var WordlistsFS embed.FS
