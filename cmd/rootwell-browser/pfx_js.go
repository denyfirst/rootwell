//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/denyfirst/rootwell/internal/browserpfx"
)

func pfxFailure() js.Value {
	return js.ValueOf(map[string]any{"schema_version": browserpfx.SchemaVersion, "ok": false,
		"result": nil, "error": "pfx-operation-failed"})
}

func pfxBytes(value js.Value, maximum int, allowEmpty bool) ([]byte, bool) {
	if value.Type() != js.TypeObject || !value.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, false
	}
	length := value.Get("byteLength")
	if length.Type() != js.TypeNumber || length.Float() > float64(maximum) || length.Float() < 0 || (!allowEmpty && length.Int() == 0) {
		return nil, false
	}
	output := make([]byte, length.Int())
	if js.CopyBytesToGo(output, value) != len(output) {
		clear(output)
		return nil, false
	}
	return output, true
}

func pfxInspect(_ js.Value, arguments []js.Value) (response any) {
	response = `{"schema_version":"rootwell.browser.pfx.v1","ok":false,"result":null,"error":"pfx-operation-failed"}`
	defer func() {
		if recover() != nil {
			response = `{"schema_version":"rootwell.browser.pfx.v1","ok":false,"result":null,"error":"pfx-operation-failed"}`
		}
	}()
	if len(arguments) != 2 {
		return response
	}
	input, ok := pfxBytes(arguments[0], 1<<20, false)
	if !ok {
		return response
	}
	defer clear(input)
	password, ok := pfxBytes(arguments[1], 128, false)
	if !ok {
		return response
	}
	defer clear(password)
	summary, err := browserpfx.Inspect(input, password)
	if err != nil {
		return response
	}
	encoded, err := json.Marshal(struct {
		SchemaVersion string             `json:"schema_version"`
		OK            bool               `json:"ok"`
		Result        browserpfx.Summary `json:"result"`
		Error         any                `json:"error"`
	}{browserpfx.SchemaVersion, true, summary, nil})
	if err != nil || len(encoded) > 65536 {
		return response
	}
	return string(encoded)
}

func pfxOutput(_ js.Value, arguments []js.Value) (response any) {
	response = pfxFailure()
	defer func() {
		if recover() != nil {
			response = pfxFailure()
		}
	}()
	if len(arguments) != 7 || arguments[0].Type() != js.TypeString {
		return response
	}
	operation := arguments[0].String()
	var inputs [3][]byte
	defer func() {
		for _, input := range inputs {
			clear(input)
		}
	}()
	maxima := [3]int{1 << 20, 64 << 10, 1 << 20}
	for index := range inputs {
		allowEmpty := index != 0
		var ok bool
		inputs[index], ok = pfxBytes(arguments[index+1], maxima[index], allowEmpty)
		if !ok {
			return response
		}
	}
	password, ok := pfxBytes(arguments[4], 128, false)
	if !ok {
		return response
	}
	defer clear(password)
	second, ok := pfxBytes(arguments[5], 256, true)
	if !ok {
		return response
	}
	defer clear(second)
	if arguments[6].Type() != js.TypeString || len(arguments[6].String()) > 99 {
		return response
	}
	option := arguments[6].String()
	var output []byte
	var filename, format string
	var err error
	switch operation {
	case "create":
		if len(inputs[1]) == 0 || option != "" {
			return response
		}
		output, filename, err = browserpfx.CreateWithInputPassword(inputs[0], inputs[1], inputs[2], password, second)
		format = "pfx"
	case "certificate":
		if len(inputs[1]) != 0 || len(inputs[2]) != 0 || len(second) != 0 || len(option) < 99 {
			return response
		}
		// Exact uppercase fingerprint plus ':' plus a three-letter format.
		fingerprint, requested := option[:95], option[96:]
		if option[95] != ':' {
			return response
		}
		output, filename, err = browserpfx.ExportCertificate(inputs[0], password, fingerprint, requested)
		format = requested
	case "key":
		if len(inputs[1]) != 0 || len(inputs[2]) != 0 {
			return response
		}
		output, filename, err = browserpfx.ExportKey(inputs[0], password, option, second)
		format = "encrypted-pkcs8-pem"
	default:
		return response
	}
	if err != nil || len(output) == 0 || len(output) > 1<<20 || filename == "" {
		clear(output)
		return response
	}
	defer clear(output)
	bytes := js.Global().Get("Uint8Array").New(len(output))
	if js.CopyBytesToJS(bytes, output) != len(output) {
		bytes.Call("fill", 0)
		return response
	}
	return js.ValueOf(map[string]any{"schema_version": browserpfx.SchemaVersion, "ok": true, "error": nil,
		"result": js.ValueOf(map[string]any{"bytes": bytes, "filename": filename, "format": format})})
}
