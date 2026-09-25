//go:build js && wasm

package main

import (
	"math"
	"syscall/js"
	"time"

	"github.com/denyfirst/rootwell/internal/browserbundleexport"
	"github.com/denyfirst/rootwell/internal/browserchain"
	"github.com/denyfirst/rootwell/internal/browserexplore"
	"github.com/denyfirst/rootwell/internal/browserexport"
	"github.com/denyfirst/rootwell/internal/browserinspect"
	"github.com/denyfirst/rootwell/internal/browserverify"
	"github.com/denyfirst/rootwell/internal/limits"
)

func main() {
	inspectFunction := js.FuncOf(inspectCertificate)
	exploreFunction := js.FuncOf(exploreCertificates)
	analyzeFunction := js.FuncOf(analyzeChainCandidates)
	bundleExportFunction := js.FuncOf(exportPublicBundle)
	verifySimpleFunction := js.FuncOf(verifySimple)
	verifyExplicitFunction := js.FuncOf(verifyExplicit)
	exportFunction := js.FuncOf(exportPublicCertificate)
	js.Global().Set("rootwellInspect", inspectFunction)
	js.Global().Set("rootwellExplore", exploreFunction)
	js.Global().Set("rootwellAnalyze", analyzeFunction)
	js.Global().Set("rootwellExportBundle", bundleExportFunction)
	js.Global().Set("rootwellVerifySimple", verifySimpleFunction)
	js.Global().Set("rootwellVerifyExplicit", verifyExplicitFunction)
	js.Global().Set("rootwellExport", exportFunction)
	js.Global().Set("rootwellInspectMaxBytes", float64(limits.MaxInputBytes))
	if ready := js.Global().Get("rootwellWasmReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}

func verifySimple(_ js.Value, arguments []js.Value) (response any) {
	response = browserverify.FailureResponse("internal-failure")
	defer func() {
		if recover() != nil {
			response = browserverify.FailureResponse("internal-failure")
		}
	}()
	if len(arguments) != 4 {
		return browserverify.FailureResponse("invalid-browser-request")
	}
	hostname, now, contextFailure := verifyContext(arguments[2], arguments[3])
	if contextFailure != "" {
		return browserverify.FailureResponse(contextFailure)
	}
	sources, failure := copyPublicCollection(arguments[0])
	if failure == inputTooLarge {
		return browserverify.FailureResponse("input-too-large")
	}
	if failure != inputOK {
		return browserverify.FailureResponse("invalid-browser-request")
	}
	defer clearCollection(sources)
	remaining := int(limits.MaxInputBytes)
	for _, source := range sources {
		remaining -= len(source)
	}
	trust, failure := copyPublicInputLimited(arguments[1], remaining)
	if failure == inputTooLarge {
		return browserverify.FailureResponse("input-too-large")
	}
	if failure != inputOK {
		return browserverify.FailureResponse("invalid-browser-request")
	}
	defer clear(trust)
	return browserverify.Simple(sources, trust, hostname, now)
}

func verifyExplicit(_ js.Value, arguments []js.Value) (response any) {
	response = browserverify.FailureResponse("internal-failure")
	defer func() {
		if recover() != nil {
			response = browserverify.FailureResponse("internal-failure")
		}
	}()
	if len(arguments) != 5 {
		return browserverify.FailureResponse("invalid-browser-request")
	}
	hostname, now, contextFailure := verifyContext(arguments[3], arguments[4])
	if contextFailure != "" {
		return browserverify.FailureResponse(contextFailure)
	}
	inputs := make([][]byte, 0, 3)
	defer func() { clearCollection(inputs) }()
	remaining := int(limits.MaxInputBytes)
	for _, argument := range arguments[:3] {
		input, failure := copyPublicInputLimited(argument, remaining)
		if failure == inputTooLarge {
			return browserverify.FailureResponse("input-too-large")
		}
		if failure != inputOK {
			return browserverify.FailureResponse("invalid-browser-request")
		}
		inputs = append(inputs, input)
		remaining -= len(input)
	}
	return browserverify.Explicit(inputs[0], inputs[1], inputs[2], hostname, now)
}

func verifyContext(hostnameValue, timeValue js.Value) (string, time.Time, string) {
	if hostnameValue.Type() != js.TypeString || timeValue.Type() != js.TypeString {
		return "", time.Time{}, "invalid-browser-request"
	}
	stringType := js.Global().Get("String")
	hostnameLength := stringType.New(hostnameValue).Get("length").Int()
	timeLength := stringType.New(timeValue).Get("length").Int()
	if hostnameLength < 1 || hostnameLength > 253 {
		return "", time.Time{}, "invalid-browser-request"
	}
	if timeLength < 20 || timeLength > 64 {
		return "", time.Time{}, "invalid-time"
	}
	now, err := time.Parse(time.RFC3339Nano, timeValue.String())
	if err != nil {
		return "", time.Time{}, "invalid-time"
	}
	return hostnameValue.String(), now, ""
}

func copyPublicInputLimited(value js.Value, remaining int) ([]byte, inputFailure) {
	if value.Type() != js.TypeObject || !value.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, inputInvalid
	}
	length := value.Get("byteLength")
	if length.Type() != js.TypeNumber || length.Float() < 0 {
		return nil, inputInvalid
	}
	if length.Float() > float64(remaining) {
		return nil, inputTooLarge
	}
	return copyPublicInput([]js.Value{value})
}

func analyzeChainCandidates(_ js.Value, arguments []js.Value) (response any) {
	response = browserchain.FailureResponse("internal-failure")
	defer func() {
		if recover() != nil {
			response = browserchain.FailureResponse("internal-failure")
		}
	}()
	if len(arguments) != 1 {
		return browserchain.FailureResponse("invalid-browser-request")
	}
	inputs, failure := copyPublicCollection(arguments[0])
	if failure != inputOK {
		return browserchain.FailureResponse("invalid-browser-request")
	}
	defer clearCollection(inputs)
	return browserchain.Process(inputs)
}

func exportPublicBundle(_ js.Value, arguments []js.Value) (response any) {
	response = bundleExportFailure(browserbundleexport.ErrorInternal)
	defer func() {
		if recover() != nil {
			response = bundleExportFailure(browserbundleexport.ErrorInternal)
		}
	}()
	if len(arguments) != 3 {
		return bundleExportFailure(browserbundleexport.ErrorInvalidRequest)
	}
	expected, ok := copyFingerprints(arguments[1])
	if !ok {
		return bundleExportFailure(browserbundleexport.ErrorInvalidRequest)
	}
	selected, ok := copyFingerprints(arguments[2])
	if !ok || len(selected) > len(expected) {
		return bundleExportFailure(browserbundleexport.ErrorInvalidRequest)
	}
	inputs, failure := copyPublicCollection(arguments[0])
	if failure == inputTooLarge {
		return bundleExportFailure(browserbundleexport.ErrorTooLarge)
	}
	if failure != inputOK {
		return bundleExportFailure(browserbundleexport.ErrorInvalidRequest)
	}
	defer clearCollection(inputs)
	result, code := browserbundleexport.Prepare(inputs, expected, selected)
	if code != "" {
		return bundleExportFailure(code)
	}
	defer clear(result.Bytes)
	output := js.Global().Get("Uint8Array").New(len(result.Bytes))
	if copied := js.CopyBytesToJS(output, result.Bytes); copied != len(result.Bytes) {
		output.Call("fill", 0)
		return bundleExportFailure(browserbundleexport.ErrorInternal)
	}
	selectedValues := js.Global().Get("Array").New()
	for _, fingerprint := range result.Fingerprints {
		selectedValues.Call("push", fingerprint)
	}
	return js.ValueOf(map[string]any{
		"schema_version": browserbundleexport.SchemaVersion,
		"ok":             true,
		"error":          nil,
		"result": js.ValueOf(map[string]any{
			"fingerprints": selectedValues,
			"filename":     result.Filename,
			"bytes":        output,
		}),
	})
}

func bundleExportFailure(code browserbundleexport.ErrorCode) js.Value {
	return js.ValueOf(map[string]any{
		"schema_version": browserbundleexport.SchemaVersion,
		"ok":             false,
		"result":         nil,
		"error":          string(code),
	})
}

func copyFingerprints(value js.Value) ([]string, bool) {
	if !js.Global().Get("Array").Call("isArray", value).Bool() {
		return nil, false
	}
	length := value.Get("length")
	if length.Type() != js.TypeNumber || length.Float() < 1 || length.Float() > 64 {
		return nil, false
	}
	result := make([]string, 0, length.Int())
	for index := 0; index < length.Int(); index++ {
		item := value.Index(index)
		if item.Type() != js.TypeString || js.Global().Get("String").New(item).Get("length").Int() != 95 {
			return nil, false
		}
		result = append(result, item.String())
	}
	return result, true
}

func copyPublicCollection(value js.Value) (inputs [][]byte, failure inputFailure) {
	failure = inputInvalid
	defer func() {
		if failure != inputOK {
			clearCollection(inputs)
			inputs = nil
		}
	}()
	if !js.Global().Get("Array").Call("isArray", value).Bool() {
		return nil, inputInvalid
	}
	length := value.Get("length")
	if length.Type() != js.TypeNumber || length.Float() < 1 || length.Float() > 8 {
		return nil, inputInvalid
	}
	count := length.Int()
	inputs = make([][]byte, 0, count)
	totalBytes := 0
	for index := 0; index < count; index++ {
		file := value.Index(index)
		if file.Type() != js.TypeObject || !file.InstanceOf(js.Global().Get("Uint8Array")) {
			return inputs, inputInvalid
		}
		byteLength := file.Get("byteLength")
		if byteLength.Type() != js.TypeNumber || byteLength.Float() > float64(int(limits.MaxInputBytes)-totalBytes) || byteLength.Float() < 0 {
			return inputs, inputTooLarge
		}
		input, copyFailure := copyPublicInput([]js.Value{file})
		if copyFailure != inputOK {
			return inputs, copyFailure
		}
		inputs = append(inputs, input)
		totalBytes += len(input)
	}
	return inputs, inputOK
}

func clearCollection(inputs [][]byte) {
	for _, input := range inputs {
		clear(input)
	}
}

func inspectCertificate(_ js.Value, arguments []js.Value) (response any) {
	response = browserinspect.FailureResponse(browserinspect.ErrorInternal)
	defer func() {
		if recover() != nil {
			response = browserinspect.FailureResponse(browserinspect.ErrorInternal)
		}
	}()

	input, failure := copyPublicInput(arguments)
	if failure == inputTooLarge {
		return browserinspect.FailureResponse(browserinspect.ErrorTooLarge)
	}
	if failure != inputOK {
		return browserinspect.FailureResponse(browserinspect.ErrorInvalidRequest)
	}
	defer clear(input)
	return browserinspect.Process(input, time.Now())
}

func exploreCertificates(_ js.Value, arguments []js.Value) (response any) {
	response = browserexplore.FailureResponse(browserexplore.ErrorInternal)
	defer func() {
		if recover() != nil {
			response = browserexplore.FailureResponse(browserexplore.ErrorInternal)
		}
	}()

	input, failure := copyPublicInput(arguments)
	if failure == inputTooLarge {
		return browserexplore.FailureResponse(browserexplore.ErrorTooLarge)
	}
	if failure != inputOK {
		return browserexplore.FailureResponse(browserexplore.ErrorInvalidRequest)
	}
	defer clear(input)
	return browserexplore.Process(input)
}

func exportPublicCertificate(_ js.Value, arguments []js.Value) (response any) {
	response = exportFailure(browserexport.ErrorInternal)
	defer func() {
		if recover() != nil {
			response = exportFailure(browserexport.ErrorInternal)
		}
	}()
	if len(arguments) != 3 || arguments[1].Type() != js.TypeString || arguments[2].Type() != js.TypeString {
		return exportFailure(browserexport.ErrorInvalidRequest)
	}
	input, failure := copyPublicInput(arguments[:1])
	if failure == inputTooLarge {
		return exportFailure(browserexport.ErrorTooLarge)
	}
	if failure != inputOK {
		return exportFailure(browserexport.ErrorInvalidRequest)
	}
	defer clear(input)

	result, code := browserexport.Prepare(input, arguments[1].String(), arguments[2].String())
	if code != "" {
		return exportFailure(code)
	}
	defer clear(result.Bytes)
	output := js.Global().Get("Uint8Array").New(len(result.Bytes))
	if copied := js.CopyBytesToJS(output, result.Bytes); copied != len(result.Bytes) {
		output.Call("fill", 0)
		return exportFailure(browserexport.ErrorInternal)
	}
	return js.ValueOf(map[string]any{
		"schema_version": browserexport.SchemaVersion,
		"ok":             true,
		"error":          nil,
		"result": js.ValueOf(map[string]any{
			"encoding":    result.Encoding,
			"fingerprint": result.Fingerprint,
			"filename":    result.Filename,
			"bytes":       output,
		}),
	})
}

func exportFailure(code browserexport.ErrorCode) js.Value {
	return js.ValueOf(map[string]any{
		"schema_version": browserexport.SchemaVersion,
		"ok":             false,
		"result":         nil,
		"error":          string(code),
	})
}

type inputFailure uint8

const (
	inputOK inputFailure = iota
	inputInvalid
	inputTooLarge
)

// copyPublicInput checks the JavaScript request before allocating a Go copy.
// Neither browser operation retains the returned buffer after processing.
func copyPublicInput(arguments []js.Value) ([]byte, inputFailure) {
	if len(arguments) != 1 || arguments[0].Type() != js.TypeObject {
		return nil, inputInvalid
	}
	uint8Array := js.Global().Get("Uint8Array")
	if !arguments[0].InstanceOf(uint8Array) {
		return nil, inputInvalid
	}
	lengthValue := arguments[0].Get("byteLength")
	if lengthValue.Type() != js.TypeNumber {
		return nil, inputInvalid
	}
	lengthFloat := lengthValue.Float()
	if lengthFloat > float64(limits.MaxInputBytes) {
		return nil, inputTooLarge
	}
	if lengthFloat < 0 || math.Trunc(lengthFloat) != lengthFloat {
		return nil, inputInvalid
	}
	length := int(lengthFloat)
	input := make([]byte, length)
	if copied := js.CopyBytesToGo(input, arguments[0]); copied != length {
		clear(input)
		return nil, inputInvalid
	}
	return input, inputOK
}
