//go:build js && wasm

package main

import (
	"github.com/denyfirst/rootwell/internal/browserpfximport"
	"syscall/js"
)

func pfxImport(_ js.Value, args []js.Value) (response any) {
	failure := func() js.Value {
		return js.ValueOf(map[string]any{"schema_version": browserpfximport.Schema, "ok": false, "result": nil, "error": "pfx-import-failed"})
	}
	response = failure()
	defer func() {
		if recover() != nil {
			response = failure()
		}
	}()
	if len(args) != 2 {
		return response
	}
	input, ok := pfxBytes(args[0], 1<<20, false)
	if !ok {
		return response
	}
	defer clear(input)
	password, ok := pfxBytes(args[1], 128, false)
	if !ok {
		return response
	}
	defer clear(password)
	prepared, err := browserpfximport.Prepare(input, password)
	defer prepared.Clear()
	if err != nil {
		return response
	}
	var owned []js.Value
	good := false
	defer func() {
		if !good {
			for _, value := range owned {
				value.Call("fill", 0)
			}
		}
	}()
	values := map[string]any{"fingerprint": prepared.Fingerprint}
	for _, item := range []struct {
		name  string
		bytes []byte
	}{{"certificate", prepared.Certificate}, {"private_key", prepared.PrivateKey}, {"key_password", prepared.KeyPassword}} {
		value := js.Global().Get("Uint8Array").New(len(item.bytes))
		owned = append(owned, value)
		if js.CopyBytesToJS(value, item.bytes) != len(item.bytes) {
			return response
		}
		values[item.name] = value
	}
	response = js.ValueOf(map[string]any{"schema_version": browserpfximport.Schema, "ok": true, "error": nil, "result": values})
	good = true
	return response
}
