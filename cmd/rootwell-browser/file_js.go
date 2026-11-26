//go:build js && wasm

package main

import (
	"errors"
	"syscall/js"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/fileformat"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
)

const fileSchema = "rootwell.browser.file.v1"

func fileFailure(code string) js.Value {
	return js.ValueOf(map[string]any{"schema_version": fileSchema, "ok": false, "result": nil, "error": code})
}

// fileCode names a reading refusal for the pages, which word it.
func fileCode(err error) string {
	switch {
	case errors.Is(err, fileformat.ErrEmpty):
		return "empty-input"
	case errors.Is(err, fileformat.ErrTooLarge):
		return "input-too-large"
	case errors.Is(err, fileformat.ErrCertificateRequest):
		return "certificate-request"
	case errors.Is(err, fileformat.ErrBadCertificate):
		return "damaged-certificate"
	case errors.Is(err, fileformat.ErrSeveralKeys):
		return "several-keys"
	case errors.Is(err, fileformat.ErrTooManyCertificates):
		return "certificate-count-limit"
	case errors.Is(err, fileformat.ErrPKCS7):
		return "p7b-unsupported"
	case errors.Is(err, fileformat.ErrKeyParameters):
		return "key-parameters"
	case errors.Is(err, fileformat.ErrUnknownBlock):
		return "unknown-block"
	case errors.Is(err, fileformat.ErrPasswordRequired), errors.Is(err, browserprivateconvert.ErrInputPasswordRequired):
		return "input-password-required"
	case errors.Is(err, fileformat.ErrWrongPassword), errors.Is(err, browserprivateconvert.ErrInputPasswordWrong):
		return "wrong-password"
	default:
		return "unreadable"
	}
}

func toJS(bytes []byte) (js.Value, bool) {
	value := js.Global().Get("Uint8Array").New(len(bytes))
	if js.CopyBytesToJS(value, bytes) != len(bytes) {
		value.Call("fill", 0)
		return js.Null(), false
	}
	return value, true
}

// readFile says what one chosen file holds and returns its parts in the
// strict forms the other engine functions and the server accept.
func readFile(_ js.Value, arguments []js.Value) (response any) {
	response = fileFailure("unreadable")
	defer func() {
		if recover() != nil {
			response = fileFailure("unreadable")
		}
	}()
	input, failure := copyPublicInput(arguments)
	if failure == inputTooLarge {
		return fileFailure("input-too-large")
	}
	if failure != inputOK {
		return response
	}
	defer clear(input)
	parts, err := fileformat.Split(input)
	defer parts.Clear()
	if err != nil {
		return fileFailure(fileCode(err))
	}
	result := map[string]any{"kind": "pfx", "certificates": nil, "count": parts.Count, "key": nil,
		"key_locked": parts.KeyLocked, "key_old_style": parts.KeyOldStyle}
	if !parts.PFX {
		switch {
		case parts.Certificates != nil && parts.Key != nil:
			result["kind"] = "certificates-and-key"
		case parts.Key != nil:
			result["kind"] = "key"
		default:
			result["kind"] = "certificates"
		}
	}
	var owned []js.Value
	for name, bytes := range map[string][]byte{"certificates": parts.Certificates, "key": parts.Key} {
		if bytes == nil {
			continue
		}
		value, ok := toJS(bytes)
		if !ok {
			for _, made := range owned {
				made.Call("fill", 0)
			}
			return response
		}
		owned = append(owned, value)
		result[name] = value
	}
	return js.ValueOf(map[string]any{"schema_version": fileSchema, "ok": true, "error": nil, "result": js.ValueOf(result)})
}

// unlockKey opens an old-style encrypted PEM key that readFile returned,
// for the page that sends a key to this Rootwell, and returns it unlocked.
func unlockKey(_ js.Value, arguments []js.Value) (response any) {
	response = fileFailure("unreadable")
	defer func() {
		if recover() != nil {
			response = fileFailure("unreadable")
		}
	}()
	if len(arguments) != 2 {
		return response
	}
	key, ok := copyPrivateBytes(arguments[0], int(limits.MaxPrivateKeyBytes))
	if !ok {
		return response
	}
	defer clear(key)
	password, ok := copyOptionalPrivatePassword(arguments[1])
	if !ok {
		return response
	}
	defer clear(password)
	opened, err := fileformat.Unlock(key, password)
	if err != nil {
		return fileFailure(fileCode(err))
	}
	defer clear(opened)
	value, ok := toJS(opened)
	if !ok {
		return response
	}
	return js.ValueOf(map[string]any{"schema_version": fileSchema, "ok": true, "error": nil, "result": js.ValueOf(map[string]any{"key": value})})
}

// pfxCode names a PFX refusal for the pages.
func pfxCode(err error, fallback string) string {
	switch pfxinspect.Code(err) {
	case "wrong-password":
		return "pfx-wrong-password"
	case "not-pfx":
		return "pfx-not-pfx"
	case "no-integrity":
		return "pfx-no-integrity"
	case "unsupported":
		return "pfx-unsupported"
	case "contents":
		if errors.Is(err, pfxinspect.ErrInvalid) {
			return "pfx-contents"
		}
	}
	return fallback
}

// normalizedKey prepares a chosen key for the strict key readers: a byte
// order mark, EC parameters or text around it go, and an old-style key is
// opened with its password. The cleanup clears what Key made.
func normalizedKey(input, password []byte) ([]byte, []byte, func(), error) {
	key, keyPassword, err := fileformat.Key(input, password)
	if err != nil {
		return nil, nil, func() {}, err
	}
	cleanup := func() {
		if len(key) != 0 && len(input) != 0 && &key[0] != &input[0] {
			clear(key)
		}
	}
	return key, keyPassword, cleanup, nil
}
