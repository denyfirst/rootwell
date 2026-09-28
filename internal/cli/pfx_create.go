package cli

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/pfxcreate"
	"github.com/denyfirst/rootwell/internal/secretfile"
)

type pfxCreateArguments struct {
	certificate string
	key         string
	chain       string
	output      string
}

func parsePFXCreateArguments(args []string) (pfxCreateArguments, bool) {
	if len(args) != 6 && len(args) != 8 {
		return pfxCreateArguments{}, false
	}
	var parsed pfxCreateArguments
	seen := map[string]bool{}
	for index := 0; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if value == "" || seen[flag] {
			return pfxCreateArguments{}, false
		}
		seen[flag] = true
		switch flag {
		case "--cert":
			parsed.certificate = value
		case "--key":
			parsed.key = value
		case "--chain":
			parsed.chain = value
		case "--output":
			parsed.output = value
		default:
			return pfxCreateArguments{}, false
		}
	}
	return parsed, parsed.certificate != "" && parsed.key != "" && parsed.output != ""
}

func runPFXCreate(args pfxCreateArguments, readSecret func(string) (string, error), stderr io.Writer) int {
	if readSecret == nil {
		return writeDiagnostic(stderr, "interactive terminal required for PFX creation\n", ExitFailure)
	}
	if err := secretfile.Preflight(args.output); err != nil {
		if errors.Is(err, secretfile.ErrUnsupported) {
			return writeDiagnostic(stderr, "PFX file creation is supported on Linux only\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "private output directory or destination is unsafe\n", ExitFailure)
	}
	certificate, err := fileinput.Read(args.certificate)
	if err != nil {
		return writeDiagnostic(stderr, "certificate could not be read\n", ExitFailure)
	}
	key, err := fileinput.ReadAtMost(args.key, limits.MaxPrivateKeyBytes)
	if err != nil {
		return writeDiagnostic(stderr, "private key could not be read\n", ExitFailure)
	}
	defer clear(key)
	var chain []byte
	if args.chain != "" {
		chain, err = fileinput.Read(args.chain)
		if err != nil {
			return writeDiagnostic(stderr, "issuer chain could not be read\n", ExitFailure)
		}
	}
	first, err := readSecret("New PFX password (20-128 printable ASCII; use a high-entropy value): ")
	if err != nil {
		return writeDiagnostic(stderr, "PFX password could not be read\n", ExitFailure)
	}
	second, err := readSecret("Confirm new PFX password: ")
	if err != nil {
		return writeDiagnostic(stderr, "PFX password could not be read\n", ExitFailure)
	}
	firstBytes, secondBytes := []byte(first), []byte(second)
	defer clear(firstBytes)
	defer clear(secondBytes)
	if len(firstBytes) != len(secondBytes) || subtle.ConstantTimeCompare(firstBytes, secondBytes) != 1 {
		return writeDiagnostic(stderr, "PFX passwords do not match\n", ExitFailure)
	}
	output, err := pfxcreate.Create(certificate, key, chain, first)
	if err != nil {
		switch {
		case errors.Is(err, pfxcreate.ErrInvalidPassword):
			return writeDiagnostic(stderr, "PFX password does not meet policy\n", ExitFailure)
		case errors.Is(err, keymatch.ErrKeyMismatch):
			return writeDiagnostic(stderr, "certificate and private key do not match\n", ExitFailure)
		case errors.Is(err, pfxcreate.ErrInvalidChain):
			return writeDiagnostic(stderr, "issuer chain is invalid or unordered\n", ExitFailure)
		default:
			return writeDiagnostic(stderr, "PFX input or encoding failed\n", ExitFailure)
		}
	}
	defer clear(output)
	if err := secretfile.WriteNew(args.output, output); err != nil {
		if errors.Is(err, secretfile.ErrUnsupported) {
			return writeDiagnostic(stderr, "PFX file creation is supported on Linux only\n", ExitFailure)
		}
		if errors.Is(err, secretfile.ErrUncertain) {
			return writeDiagnostic(stderr, "PFX output state is uncertain; inspect destination before retry\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "private output directory or destination is unsafe\n", ExitFailure)
	}
	return ExitOK
}
