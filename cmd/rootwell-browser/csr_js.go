//go:build js && wasm

package main

import (
	"encoding/json"
	"io"
	"strings"
	"syscall/js"

	"github.com/denyfirst/rootwell/internal/csrworkbench"
)

func csrFailure() js.Value {
	return js.ValueOf(map[string]any{"schema_version": csrworkbench.SchemaVersion, "ok": false, "result": nil, "error": "csr-operation-failed"})
}

func csrOptions(value string) (string, csrworkbench.Params, string, bool) {
	var options struct {
		Algorithm string              `json:"algorithm"`
		Params    csrworkbench.Params `json:"params"`
		Format    string              `json:"format"`
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&options); err != nil {
		return "", csrworkbench.Params{}, "", false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || len(options.Algorithm) > 32 {
		return "", csrworkbench.Params{}, "", false
	}
	return options.Algorithm, options.Params, options.Format, true
}

// csrOperation returns public JSON for inspection/comparison; byte output
// exists only for an explicit request download (new private key is encrypted).
func csrOperation(_ js.Value, args []js.Value) (response any) {
	response = csrFailure()
	defer func() {
		if recover() != nil {
			response = csrFailure()
		}
	}()
	if len(args) != 5 || args[0].Type() != js.TypeString || args[4].Type() != js.TypeString || len(args[4].String()) > 16<<10 {
		return response
	}
	operation, option := args[0].String(), args[4].String()
	input, ok := pfxBytes(args[1], csrworkbench.MaxRequestBytes, true)
	if !ok {
		return response
	}
	defer clear(input)
	certificate, ok := pfxBytes(args[2], 1<<20, true)
	if !ok {
		return response
	}
	defer clear(certificate)
	password, ok := pfxBytes(args[3], 256, true)
	if !ok {
		return response
	}
	defer clear(password)
	var output csrworkbench.Output
	var public any
	var err error
	switch operation {
	case "generate", "key":
		algorithm, params, format, ok := csrOptions(option)
		if !ok || len(certificate) != 0 {
			return response
		}
		if operation == "generate" {
			if len(input) != 0 || format != "" {
				return response
			}
			output, err = csrworkbench.Generate(algorithm, params, password)
		} else {
			if len(input) == 0 || algorithm != "" {
				return response
			}
			output, err = csrworkbench.FromKey(input, password, params, format)
		}
	case "inspect":
		if len(certificate) != 0 || len(password) != 0 || option != "" {
			return response
		}
		public, err = csrworkbench.Inspect(input)
	case "convert":
		if len(certificate) != 0 || len(password) != 0 || len(option) != 99 || option[95] != ':' {
			return response
		}
		output, err = csrworkbench.Convert(input, option[:95], option[96:])
	case "match":
		if len(password) != 0 || len(option) != 95 {
			return response
		}
		public, err = csrworkbench.Match(input, certificate, option)
	default:
		return response
	}
	if err != nil {
		clear(output.Bytes)
		clear(output.CSR)
		return response
	}
	if public != nil {
		encoded, err := json.Marshal(struct {
			SchemaVersion string `json:"schema_version"`
			OK            bool   `json:"ok"`
			Result        any    `json:"result"`
			Error         any    `json:"error"`
		}{csrworkbench.SchemaVersion, true, public, nil})
		if err != nil || len(encoded) > 32768 {
			return response
		}
		return string(encoded)
	}
	defer clear(output.Bytes)
	defer clear(output.CSR)
	if len(output.Bytes) == 0 || len(output.Bytes) > 256<<10 || len(output.CSR) == 0 || len(output.CSR) > 96<<10 || output.Filename == "" {
		return response
	}
	encoded, err := json.Marshal(output.Summary)
	if err != nil || len(encoded) > 16384 {
		return response
	}
	bytes := js.Global().Get("Uint8Array").New(len(output.Bytes))
	csr := js.Global().Get("Uint8Array").New(len(output.CSR))
	if js.CopyBytesToJS(bytes, output.Bytes) != len(output.Bytes) || js.CopyBytesToJS(csr, output.CSR) != len(output.CSR) {
		bytes.Call("fill", 0)
		csr.Call("fill", 0)
		return response
	}
	return js.ValueOf(map[string]any{"schema_version": csrworkbench.SchemaVersion, "ok": true, "error": nil,
		"result": js.ValueOf(map[string]any{"bytes": bytes, "csr": csr, "filename": output.Filename, "format": output.Format, "summary": string(encoded)})})
}
