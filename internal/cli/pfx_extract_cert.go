package cli

import (
	"io"

	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/denyfirst/rootwell/internal/publicconvert"
)

type pfxExtractCertArguments struct {
	input       string
	fingerprint string
	to          string
	output      string
}

func parsePFXExtractCertArguments(args []string) (pfxExtractCertArguments, bool) {
	if len(args) != 8 {
		return pfxExtractCertArguments{}, false
	}
	var parsed pfxExtractCertArguments
	seen := make(map[string]bool)
	for index := 0; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if value == "" || seen[flag] {
			return pfxExtractCertArguments{}, false
		}
		seen[flag] = true
		switch flag {
		case "--input":
			parsed.input = value
		case "--sha256":
			parsed.fingerprint = value
		case "--to":
			parsed.to = value
		case "--output":
			parsed.output = value
		default:
			return pfxExtractCertArguments{}, false
		}
	}
	return parsed, parsed.input != "" && parsed.output != "" && pfxinspect.ValidFingerprint(parsed.fingerprint) && (parsed.to == "pem" || parsed.to == "der")
}

// runPFXExtractCert exports one explicitly selected public certificate only.
// The authenticated PFX is read once, and publication follows a complete
// successful decode; the output is never a private-key or fullchain file.
func runPFXExtractCert(args pfxExtractCertArguments, readSecret func(string) (string, error), stderr io.Writer) int {
	result, code := openPFX(args.input, readSecret, stderr, "extraction")
	if code != ExitOK {
		return code
	}
	der, ok := result.CertificateDER(args.fingerprint)
	if !ok {
		return writeDiagnostic(stderr, "selected public certificate was not found in this PFX\n", ExitFailure)
	}
	defer clear(der)
	output, err := publicconvert.Convert(der, args.to)
	if err != nil {
		return writeDiagnostic(stderr, "selected public certificate could not be encoded\n", ExitFailure)
	}
	defer clear(output)
	if err := writePublicNewFile(args.output, output); err != nil {
		return writeDiagnostic(stderr, "public output could not be created\n", ExitFailure)
	}
	return ExitOK
}
