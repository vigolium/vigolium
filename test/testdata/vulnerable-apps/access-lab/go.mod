// access-lab is a deliberately vulnerable web app used by the durable-autopilot
// e2e demo (make test-e2e-autopilot-access). It has its OWN module so it stays
// out of the parent module's `go build ./...` / `go test ./...` and never ships
// in the vigolium binary. Standard-library only — no external dependencies.
module access-lab

go 1.26
