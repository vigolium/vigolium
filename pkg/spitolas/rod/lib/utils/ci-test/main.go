// Package main A helper to run go test on CI with the right environment variables.
package main

import (
	"os"

	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/utils"
)

func main() {
	for k, v := range utils.TestEnvs {
		err := os.Setenv(k, v)
		utils.E(err)
	}
	utils.Exec("go test", os.Args[1:]...)
}
