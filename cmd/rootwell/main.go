// Command rootwell provides local, security-focused cryptographic tooling.
package main

import (
	"os"

	"github.com/denyfirst/rootwell/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
