package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
)

const matchJSONSchema = "rootwell.match.v1"

type matchArguments struct {
	certificatePath string
	privateKeyPath  string
	jsonOutput      bool
}

type matchJSONDocument struct {
	SchemaVersion    string               `json:"schema_version"`
	Match            bool                 `json:"match"`
	Certificate      matchJSONCertificate `json:"certificate"`
	PrivateKey       matchJSONPrivateKey  `json:"private_key"`
	AlgorithmPolicy  string               `json:"algorithm_policy"`
	CertificateTrust string               `json:"certificate_trust"`
	Network          string               `json:"network"`
}

type matchJSONCertificate struct {
	Encoding           string `json:"encoding"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

type matchJSONPrivateKey struct {
	Encoding           string `json:"encoding"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKeyBits      int    `json:"public_key_bits"`
	PublicKeyCurve     string `json:"public_key_curve,omitempty"`
	PublicKeySHA256    string `json:"public_key_sha256"`
}

func parseMatchArguments(args []string) (matchArguments, bool) {
	var parsed matchArguments
	for index := 0; index < len(args); {
		switch args[index] {
		case "--json":
			if parsed.jsonOutput {
				return matchArguments{}, false
			}
			parsed.jsonOutput = true
			index++
		case "--cert", "--key":
			if index+1 >= len(args) || args[index+1] == "" {
				return matchArguments{}, false
			}
			value := args[index+1]
			if args[index] == "--cert" {
				if parsed.certificatePath != "" {
					return matchArguments{}, false
				}
				parsed.certificatePath = value
			} else {
				if parsed.privateKeyPath != "" {
					return matchArguments{}, false
				}
				parsed.privateKeyPath = value
			}
			index += 2
		default:
			return matchArguments{}, false
		}
	}
	return parsed, parsed.certificatePath != "" && parsed.privateKeyPath != ""
}

func runMatch(arguments matchArguments, stdout, stderr io.Writer) int {
	certificateInput, err := readMatchInput(arguments.certificatePath, "certificate", limits.MaxInputBytes, stderr)
	if err != nil {
		return ExitFailure
	}
	defer clear(certificateInput)

	privateKeyInput, err := readMatchInput(arguments.privateKeyPath, "private key", limits.MaxPrivateKeyBytes, stderr)
	if err != nil {
		return ExitFailure
	}
	defer clear(privateKeyInput)

	result, err := keymatch.Match(certificateInput, privateKeyInput)
	if err != nil {
		return writeDiagnostic(stderr, matchDiagnostic(err), ExitFailure)
	}

	var output string
	if arguments.jsonOutput {
		output, err = renderMatchJSON(result)
		if err != nil {
			return writeDiagnostic(stderr, "output encoding failed\n", ExitFailure)
		}
	} else {
		output = renderMatch(result)
	}
	verdictCode := ExitOK
	if !result.Match {
		verdictCode = ExitFailure
	}
	return writeRequestedCode(stdout, stderr, output, verdictCode)
}

func readMatchInput(path, label string, limit int64, stderr io.Writer) ([]byte, error) {
	input, err := fileinput.ReadAtMost(path, limit)
	if err == nil {
		return input, nil
	}
	message := label + " could not be read\n"
	if errors.Is(err, fileinput.ErrEmpty) {
		message = label + " is empty\n"
	} else if errors.Is(err, fileinput.ErrTooLarge) {
		if label == "private key" {
			message = "private key exceeds 64 KiB limit\n"
		} else {
			message = "certificate exceeds 16 MiB limit\n"
		}
	}
	writeDiagnostic(stderr, message, ExitFailure)
	return nil, err
}

func matchDiagnostic(err error) string {
	switch {
	case errors.Is(err, keymatch.ErrInvalidCertificate):
		return "invalid x509 certificate\n"
	case errors.Is(err, keymatch.ErrEmptyPrivateKey):
		return "private key is empty\n"
	case errors.Is(err, keymatch.ErrPrivateKeyTooLarge):
		return "private key exceeds 64 KiB limit\n"
	case errors.Is(err, keymatch.ErrUnsupportedPrivateKeyFormat):
		return "unsupported private key encoding\n"
	case errors.Is(err, keymatch.ErrEncryptedPrivateKey):
		return "encrypted private keys are not supported in this version\n"
	case errors.Is(err, keymatch.ErrUnsupportedPrivateKey):
		return "unsupported private key algorithm\n"
	case errors.Is(err, keymatch.ErrPrivateKeyResourceLimit):
		return "private key exceeds resource limit\n"
	default:
		return "invalid private key\n"
	}
}

func renderMatch(result keymatch.Result) string {
	var output strings.Builder
	fmt.Fprintf(&output, "match: %t\n", result.Match)
	fmt.Fprintf(&output, "certificate-encoding: %s\n", result.CertificateEncoding)
	fmt.Fprintf(&output, "certificate-public-key-algorithm: %s\n", result.CertificateKeyAlgorithm)
	fmt.Fprintf(&output, "private-key-encoding: %s\n", result.PrivateKeyEncoding)
	fmt.Fprintf(&output, "private-key-public-algorithm: %s\n", result.PrivateKeyAlgorithm)
	fmt.Fprintf(&output, "private-key-public-bits: %d\n", result.PublicKeyBits)
	if result.PublicKeyCurve != "" {
		fmt.Fprintf(&output, "private-key-public-curve: %s\n", result.PublicKeyCurve)
	}
	fmt.Fprintf(&output, "private-key-public-sha256: %s\n", result.PublicKeySHA256)
	fmt.Fprintln(&output, "algorithm-policy: not-evaluated")
	fmt.Fprintln(&output, "certificate-trust: not-evaluated")
	fmt.Fprintln(&output, "network: disabled")
	return output.String()
}

func renderMatchJSON(result keymatch.Result) (string, error) {
	document := matchJSONDocument{
		SchemaVersion: matchJSONSchema,
		Match:         result.Match,
		Certificate: matchJSONCertificate{
			Encoding:           string(result.CertificateEncoding),
			PublicKeyAlgorithm: result.CertificateKeyAlgorithm,
		},
		PrivateKey: matchJSONPrivateKey{
			Encoding:           string(result.PrivateKeyEncoding),
			PublicKeyAlgorithm: result.PrivateKeyAlgorithm,
			PublicKeyBits:      result.PublicKeyBits,
			PublicKeyCurve:     result.PublicKeyCurve,
			PublicKeySHA256:    result.PublicKeySHA256,
		},
		AlgorithmPolicy:  "not-evaluated",
		CertificateTrust: "not-evaluated",
		Network:          "disabled",
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded) + "\n", nil
}
