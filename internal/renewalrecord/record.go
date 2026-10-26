// Package renewalrecord defines a public-data-only internal connector seam.
// It contains no network, signer, credentials, persistence or scheduling.
package renewalrecord

import (
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
)

type Observation struct {
	CertificateID string
	Available     bool
	Information   renewalpolicy.Information
}

type Failure struct {
	Temporary bool
	Hint      providerretry.Hint
}

func (*Failure) Error() string { return "renewal information not confirmed" }
