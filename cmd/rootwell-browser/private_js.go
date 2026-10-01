//go:build js && wasm

package main

import (
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/limits"
)

func copyPrivateBytes(value js.Value, maximum int) ([]byte, bool) {
	if value.Type() != js.TypeObject || !value.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, false
	}
	length := value.Get("byteLength")
	if length.Type() != js.TypeNumber || length.Float() < 1 || length.Float() > float64(maximum) {
		return nil, false
	}
	bytes := make([]byte, length.Int())
	if js.CopyBytesToGo(bytes, value) != len(bytes) {
		clear(bytes)
		return nil, false
	}
	return bytes, true
}

func privateInspectFailure(code string) string {
	return `{"schema_version":"rootwell.browser.private-convert.v1","ok":false,"result":null,"error":"` + code + `"}`
}

func inspectPrivateKey(_ js.Value, arguments []js.Value) (response any) {
	response = privateInspectFailure("invalid-private-key")
	defer func() {
		if recover() != nil {
			response = privateInspectFailure("invalid-private-key")
		}
	}()
	if len(arguments) != 2 {
		return response
	}
	input, ok := copyPrivateBytes(arguments[0], int(limits.MaxPrivateKeyBytes))
	if !ok {
		return response
	}
	defer clear(input)
	password, ok := copyOptionalPrivatePassword(arguments[1])
	if !ok {
		return response
	}
	defer clear(password)
	summary, err := browserprivateconvert.InspectWithPassword(input, password)
	if err != nil {
		if errors.Is(err, browserprivateconvert.ErrInputPasswordRequired) {
			return privateInspectFailure("input-password-required")
		}
		return response
	}
	encoded, err := json.Marshal(struct {
		SchemaVersion string                        `json:"schema_version"`
		OK            bool                          `json:"ok"`
		Result        browserprivateconvert.Summary `json:"result"`
		Error         any                           `json:"error"`
	}{browserprivateconvert.SchemaVersion, true, summary, nil})
	if err != nil {
		return response
	}
	return string(encoded)
}

func privateExportFailure() js.Value {
	return js.ValueOf(map[string]any{
		"schema_version": browserprivateconvert.SchemaVersion,
		"ok":             false,
		"result":         nil,
		"error":          "private-export-failed",
	})
}

func exportPrivateKey(_ js.Value, arguments []js.Value) (response any) {
	response = privateExportFailure()
	defer func() {
		if recover() != nil {
			response = privateExportFailure()
		}
	}()
	if len(arguments) != 5 || arguments[1].Type() != js.TypeString || len(arguments[1].String()) != 95 || arguments[3].Type() != js.TypeString {
		return response
	}
	input, ok := copyPrivateBytes(arguments[0], int(limits.MaxPrivateKeyBytes))
	if !ok {
		return response
	}
	defer clear(input)
	inputPassword, ok := copyOptionalPrivatePassword(arguments[2])
	if !ok {
		return response
	}
	defer clear(inputPassword)
	outputPassword, ok := copyOptionalPrivatePassword(arguments[4])
	if !ok {
		return response
	}
	defer clear(outputPassword)
	output, filename, err := browserprivateconvert.Export(input, arguments[1].String(), inputPassword, arguments[3].String(), outputPassword)
	if err != nil {
		return response
	}
	defer clear(output)
	resultBytes := js.Global().Get("Uint8Array").New(len(output))
	if js.CopyBytesToJS(resultBytes, output) != len(output) {
		resultBytes.Call("fill", 0)
		return response
	}
	return js.ValueOf(map[string]any{
		"schema_version": browserprivateconvert.SchemaVersion,
		"ok":             true,
		"error":          nil,
		"result": js.ValueOf(map[string]any{
			"filename": filename,
			"format":   arguments[3].String(),
			"bytes":    resultBytes,
		}),
	})
}

func copyOptionalPrivatePassword(value js.Value) ([]byte, bool) {
	if value.Type() != js.TypeObject || !value.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, false
	}
	length := value.Get("byteLength")
	if length.Type() != js.TypeNumber || length.Float() < 0 || length.Float() > 256 {
		return nil, false
	}
	bytes := make([]byte, length.Int())
	if js.CopyBytesToGo(bytes, value) != len(bytes) {
		clear(bytes)
		return nil, false
	}
	return bytes, true
}
