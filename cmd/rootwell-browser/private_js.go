//go:build js && wasm

package main

import (
	"encoding/json"
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

func privateInspectFailure() string {
	return `{"schema_version":"rootwell.browser.private-convert.v1","ok":false,"result":null,"error":"invalid-private-key"}`
}

func inspectPrivateKey(_ js.Value, arguments []js.Value) (response any) {
	response = privateInspectFailure()
	defer func() {
		if recover() != nil {
			response = privateInspectFailure()
		}
	}()
	if len(arguments) != 1 {
		return response
	}
	input, ok := copyPrivateBytes(arguments[0], int(limits.MaxPrivateKeyBytes))
	if !ok {
		return response
	}
	defer clear(input)
	summary, err := browserprivateconvert.Inspect(input)
	if err != nil {
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

func exportEncryptedPrivateKey(_ js.Value, arguments []js.Value) (response any) {
	response = privateExportFailure()
	defer func() {
		if recover() != nil {
			response = privateExportFailure()
		}
	}()
	if len(arguments) != 3 || arguments[1].Type() != js.TypeString || len(arguments[1].String()) != 95 {
		return response
	}
	input, ok := copyPrivateBytes(arguments[0], int(limits.MaxPrivateKeyBytes))
	if !ok {
		return response
	}
	defer clear(input)
	password, ok := copyPrivateBytes(arguments[2], 128)
	if !ok {
		return response
	}
	defer clear(password)
	output, filename, err := browserprivateconvert.ExportEncrypted(input, arguments[1].String(), password)
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
			"bytes":    resultBytes,
		}),
	})
}
