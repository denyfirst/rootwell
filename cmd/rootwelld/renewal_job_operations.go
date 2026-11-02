package main

import (
	"context"
	"crypto"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

// Only existing locked transactions and fixed reviewed connectors. No arbitrary
// runner, receipt checker, trust roots, replay flag, or recovery/maintenance mode.
func (g *gate) executeRenewalAction(ctx context.Context, s session, expected uint64, fp string, d inventorystore.CycleDecision, permit func() bool) (uint64, error) {
	defer clear(s.dataKey[:])
	path, key, id, rev := g.accessPath, s.dataKey[:], s.installationID[:], s.revision
	switch d.Action {
	case "timing":
		connect := g.timingConnect
		if connect == nil {
			connect = acmestaging.RenewalInformation
		}
		_, gen, err := instanceaccess.RunStagingRenewalTiming(path, key, id, rev, expected, fp, permit, func(allowed func() bool, der []byte) (renewalrecord.Observation, error) {
			return connect(ctx, allowed, der)
		})
		return gen, err
	case "close":
		_, gen, err := instanceaccess.CloseStagingRequest(path, key, id, rev, expected, permit)
		return gen, err
	case "order", "order-read":
		connect := g.orderConnect
		if connect == nil {
			connect = acmestaging.DNSOrder
		}
		use := func(signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
			return connect(ctx, permit, signer, account, order, names, checkpoint)
		}
		if d.Action == "order" {
			_, gen, err := instanceaccess.RunStagingRenewalOrder(path, key, id, rev, expected, fp, permit, use)
			return gen, err
		}
		_, gen, err := instanceaccess.RunStagingOrder(path, key, id, rev, expected, nil, true, permit, use)
		return gen, err
	case "dns-plan":
		_, gen, err := instanceaccess.PrepareStagingDNSPlan(path, key, id, rev, expected, permit)
		return gen, err
	case "dns-add", "dns-check", "dns-cleanup":
		connect := g.dnsConnect
		if connect == nil {
			connect = acmestaging.CloudflareTXT
		}
		mode := map[string]string{"dns-add": "add", "dns-check": "check", "dns-cleanup": "cleanup"}[d.Action]
		_, gen, err := instanceaccess.RunStagingDNS(path, key, id, rev, expected, d.Index, mode, permit, func(allowed func() bool, token []byte, scope dnsrecord.Scope, state dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
			return connect(ctx, allowed, token, scope, state, cleanup, readOnly, checkpoint)
		})
		return gen, err
	case "ack":
		_, gen, err := instanceaccess.AcknowledgeStagingDNS(path, key, id, rev, expected, permit)
		return gen, err
	case "validate", "validation-read":
		connect := g.validationConnect
		if connect == nil {
			connect = acmestaging.DNSValidation
		}
		_, gen, err := instanceaccess.RunStagingValidation(path, key, id, rev, expected, d.Action == "validation-read", permit, func(signer crypto.Signer, account string, info acmeorder.Instructions, names []string, readOnly bool) (acmeorder.Validation, error) {
			return connect(ctx, permit, signer, account, info, names, readOnly)
		})
		return gen, err
	case "key":
		_, gen, err := instanceaccess.PrepareStagingCertificateRequest(path, key, id, rev, expected, permit)
		return gen, err
	case "certificate", "certificate-read":
		connect := g.certificateConnect
		if connect == nil {
			connect = acmestaging.Certificate
		}
		_, gen, err := instanceaccess.RunStagingCertificate(path, key, id, rev, expected, d.Action == "certificate-read", permit, func(signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
			return connect(ctx, permit, signer, account, order, expires, names, private, csr, readOnly)
		})
		return gen, err
	}
	return 0, inventorystore.ErrInvalid
}
