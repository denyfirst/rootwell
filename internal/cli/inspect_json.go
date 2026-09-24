package cli

import (
	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/inspectreport"
)

var errInvalidJSONText = inspectreport.ErrInvalidText

type inspectJSON = inspectreport.Document

func renderCertificateJSON(result certinspect.Result, timeWindow certinspect.TimeWindow) (string, error) {
	document, err := inspectreport.New(result, timeWindow)
	if err != nil {
		return "", err
	}
	return inspectreport.Marshal(document)
}
