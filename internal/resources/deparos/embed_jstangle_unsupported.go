// This stub provides an empty JSTangleBinary in two cases:
//   - platforms without a prebuilt jstangle binary, and
//   - any build with `-tags jstangle_stub`, which lets contributors run
//     `go test -tags=jstangle_stub ./...` without first building the large
//     embedded jstangle binaries (see `make ensure-jstangle`). Code paths that
//     actually launch jstangle treat an empty JSTangleBinaryName as "unavailable".
//go:build jstangle_stub || (!(linux && amd64) && !(linux && arm64) && !(darwin && amd64) && !(darwin && arm64) && !(windows && amd64))

package deparos

var JSTangleBinary []byte

const JSTangleBinaryName = ""
