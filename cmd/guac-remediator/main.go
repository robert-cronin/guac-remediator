package main

import (
	"github.com/robert-cronin/guac-remediator/cmd/guac-remediator/cli"
)

func main() {
	// delegate to cobra command
	cli.Execute()
}
