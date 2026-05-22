// This stub provides an empty JSScanBinary in two cases:
//   - platforms without a prebuilt jsscan binary, and
//   - any build with `-tags jsscan_stub`, which lets contributors run
//     `go test -tags=jsscan_stub ./...` without first building the large
//     embedded jsscan binaries (see `make ensure-jsscan`). Code paths that
//     actually launch jsscan treat an empty JSScanBinaryName as "unavailable".
//go:build jsscan_stub || (!(linux && amd64) && !(darwin && arm64) && !(windows && amd64))

package deparos

var JSScanBinary []byte

const JSScanBinaryName = ""
