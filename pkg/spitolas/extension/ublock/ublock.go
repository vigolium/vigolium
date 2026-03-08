package ublock

import "github.com/vigolium/vigolium/pkg/spitolas/extension"

func init() {
	extension.Register(&uBlockLite{})
}

type uBlockLite struct{}

func (u *uBlockLite) Name() string    { return "ublock" }
func (u *uBlockLite) Version() string { return version }
func (u *uBlockLite) ZipData() []byte { return zipData }
