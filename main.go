package main

import (
	"github.com/vhqtvn/vhmaskd/cmd"
	_ "github.com/vhqtvn/vhmaskd/cmd/password"
)

func main() {
	cmd.Execute()
}
