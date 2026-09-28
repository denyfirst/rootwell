package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/publicconvert"
)

type convertArguments struct {
	input  string
	to     string
	output string
}

func parseConvertArguments(args []string) (convertArguments, bool) {
	if len(args) != 6 {
		return convertArguments{}, false
	}
	var parsed convertArguments
	seen := map[string]bool{}
	for index := 0; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if value == "" || seen[flag] {
			return convertArguments{}, false
		}
		seen[flag] = true
		switch flag {
		case "--input":
			parsed.input = value
		case "--to":
			parsed.to = value
		case "--output":
			parsed.output = value
		default:
			return convertArguments{}, false
		}
	}
	return parsed, parsed.input != "" && parsed.output != "" && (parsed.to == "pem" || parsed.to == "der")
}

func runConvert(args convertArguments, stderr io.Writer) int {
	input, err := fileinput.Read(args.input)
	if err != nil {
		return writeDiagnostic(stderr, "public input could not be read\n", ExitFailure)
	}
	output, err := publicconvert.Convert(input, args.to)
	if err != nil {
		return writeDiagnostic(stderr, "invalid public certificate\n", ExitFailure)
	}
	defer clear(output)
	if err := writePublicNewFile(args.output, output); err != nil {
		return writeDiagnostic(stderr, "public output could not be created\n", ExitFailure)
	}
	return ExitOK
}

// writePublicNewFile stages public bytes next to the destination and links the
// completed file into place without replacing an existing path. This is not a
// secret-output primitive and does not promise crash durability.
func writePublicNewFile(path string, data []byte) error {
	if path == "" || len(data) == 0 {
		return os.ErrInvalid
	}
	directory := filepath.Dir(path)
	staging, err := os.CreateTemp(directory, ".rootwell-public-*")
	if err != nil {
		return err
	}
	stagingPath := staging.Name()
	defer func() { _ = os.Remove(stagingPath) }()
	written, writeErr := staging.Write(data)
	if writeErr != nil || written != len(data) {
		_ = staging.Close()
		return os.ErrInvalid
	}
	if err := staging.Sync(); err != nil {
		_ = staging.Close()
		return err
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		_ = staging.Close()
		return err
	}
	readback := make([]byte, len(data))
	_, err = io.ReadFull(staging, readback)
	if err != nil || !bytes.Equal(readback, data) {
		_ = staging.Close()
		return os.ErrInvalid
	}
	if err := staging.Close(); err != nil {
		return err
	}
	return os.Link(stagingPath, path)
}
