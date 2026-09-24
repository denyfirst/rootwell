//go:build js && wasm

package main

import (
	"math"
	"syscall/js"
	"time"

	"github.com/denyfirst/rootwell/internal/browserexplore"
	"github.com/denyfirst/rootwell/internal/browserinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

func main() {
	inspectFunction := js.FuncOf(inspectCertificate)
	exploreFunction := js.FuncOf(exploreCertificates)
	js.Global().Set("rootwellInspect", inspectFunction)
	js.Global().Set("rootwellExplore", exploreFunction)
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
