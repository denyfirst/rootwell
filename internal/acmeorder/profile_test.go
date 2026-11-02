package acmeorder

import (
	"testing"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/acmeprofile"
)

func TestLegacyOrderValidationCannotSelectProduction(t *testing.T) {
	if Origin != acmeprofile.Staging.Origin() || acmeplan.Provider != acmeprofile.Staging.Provider() || acmeplan.Directory != acmeprofile.Staging.Directory() {
		t.Fatal("legacy fixed profile drift")
	}
	account := acmeprofile.Production.Origin() + "/acme/acct/1234"
	order := acmeprofile.Production.Origin() + "/acme/order/1234/5678"
	if !acmeprofile.Production.AccountURL(account) || !acmeprofile.Production.OrderURL(order, account) {
		t.Fatal("fixed production syntax refused")
	}
	if AccountURL(account) || OrderURL(order, account) || ResourceURL(acmeprofile.Production.Origin()+"/acme/authz/1234", "authorization") || ResourceURL(acmeprofile.Production.Origin()+"/acme/chall/1234/a", "challenge") {
		t.Fatal("staging runtime promoted production URI")
	}
}
