//go:build js && wasm

package main

import (
	"math"
	"syscall/js"
	"time"

	"github.com/denyfirst/rootwell/internal/browserinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

func main() {
	inspectFunction := js.FuncOf(inspectCertificate)
	js.Global().Set("rootwellInspect", inspectFunction)
	js.Global().Set("rootwellInspectMaxBytes", float64(limits.MaxInputBytes))
	if ready := js.Global().Get("rootwellWasmReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}

func inspectCertificate(_ js.Value, arguments []js.Value) (response any) {
	response = browserinspect.FailureResponse(browserinspect.ErrorInternal)
	defer func() {
		if recover() != nil {
			response = browserinspect.FailureResponse(browserinspect.ErrorInternal)
		}
	}()

	if len(arguments) != 1 || arguments[0].Type() != js.TypeObject {
		return browserinspect.FailureResponse(browserinspect.ErrorInvalidRequest)
	}
	uint8Array := js.Global().Get("Uint8Array")
	if !arguments[0].InstanceOf(uint8Array) {
		return browserinspect.FailureResponse(browserinspect.ErrorInvalidRequest)
	}
	lengthValue := arguments[0].Get("byteLength")
	if lengthValue.Type() != js.TypeNumber {
		return browserinspect.FailureResponse(browserinspect.ErrorInvalidRequest)
	}
	lengthFloat := lengthValue.Float()
	if lengthFloat > float64(limits.MaxInputBytes) {
		return browserinspect.FailureResponse(browserinspect.ErrorTooLarge)
	}
	if lengthFloat < 0 || math.Trunc(lengthFloat) != lengthFloat {
		return browserinspect.FailureResponse(browserinspect.ErrorInvalidRequest)
	}
	length := int(lengthFloat)

	input := make([]byte, length)
	defer clear(input)
	if copied := js.CopyBytesToGo(input, arguments[0]); copied != length {
		return browserinspect.FailureResponse(browserinspect.ErrorInvalidRequest)
	}
	return browserinspect.Process(input, time.Now())
}
