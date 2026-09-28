// Command rootwell provides local, security-focused cryptographic tooling.
package main

import (
	"os"

	"github.com/denyfirst/rootwell/internal/cli"
)

func main() {
	os.Exit(cli.RunWithTerminal(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
