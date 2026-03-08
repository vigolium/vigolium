// Package main ...
package main

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/launcher"
	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/utils"
)

func main() {
	p, err := launcher.NewBrowser().Get()
	utils.E(err)

	fmt.Println(p)
}
