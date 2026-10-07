//go:build js && wasm

package main

import (
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certificatepair"
)

func certificateKeyMatch(_ js.Value, args []js.Value) (response any) {
	response = `{"schema_version":"rootwell.browser.key-match.v1","ok":false,"error":"invalid-input","records":null}`
	defer func() {
		if recover() != nil {
			response = `{"schema_version":"rootwell.browser.key-match.v1","ok":false,"error":"invalid-input","records":null}`
		}
	}()
	if len(args) != 3 {
		return response
	}
	certificate, failure := copyPublicInputLimited(args[0], certificatepair.MaxBundleBytes)
	if failure != inputOK {
		return response
	}
	defer clear(certificate)
	key, ok := copyPrivateBytes(args[1], 64<<10)
	if !ok {
		return response
	}
	defer clear(key)
	password, ok := copyOptionalPrivatePassword(args[2])
	if !ok {
		return response
	}
	defer clear(password)
	records, err := certificatepair.Analyze(certificate, key, password)
	if err != nil {
		if errors.Is(err, browserprivateconvert.ErrInputPasswordRequired) {
			return `{"schema_version":"rootwell.browser.key-match.v1","ok":false,"error":"input-password-required","records":null}`
		}
		return response
	}
	type result struct {
		Fingerprint string `json:"fingerprint"`
		Subject     string `json:"subject"`
		Status      string `json:"key_status"`
	}
	items := make([]result, 0, len(records))
	for _, r := range records {
		items = append(items, result{r.Fingerprint, r.Subject, r.KeyStatus})
	}
	encoded, err := json.Marshal(struct {
		Schema  string   `json:"schema_version"`
		OK      bool     `json:"ok"`
		Error   any      `json:"error"`
		Records []result `json:"records"`
	}{"rootwell.browser.key-match.v1", true, nil, items})
	if err != nil {
		return response
	}
	return string(encoded)
}
