package inventorystore

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/providerretry"
)

func TestCAOperationWaitFoldsIntoExactResultAndKeepsLongerPolicy(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	defer clear(key)
	image, _, g, err := BeginStagingOrder(key, id, image, 4, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	before, _, _ := decode(key, id, image)
	hint := providerretry.Hint{NotBefore: at.Add(time.Hour)}
	constrained, err := constrainCAWaitAt(key, id, image, g, hint, at)
	if err != nil {
		t.Fatal("valid fixed-provider hint refused", err)
	}
	after, _, err := decode(key, id, constrained)
	if err != nil || after.Generation != g || !reflect.DeepEqual(before.ACMEOrders, after.ACMEOrders) || !reflect.DeepEqual(before.ACMEAccounts, after.ACMEAccounts) || !reflect.DeepEqual(before.History, after.History) {
		t.Fatal("wait changed original scope/generation", err)
	}
	wait, _, err := readStagingWaitAt(key, id, constrained, at)
	if err != nil || wait.Ready || wait.Blocked || wait.NotBefore != timingStamp(hint.NotBefore) {
		t.Fatal("known wait not enforced", err)
	}
	next, _, ng, err := UpdateStagingOrder(key, id, constrained, g, orderURLFixture, nil, false)
	if err != nil || ng != g+1 {
		t.Fatal("wait did not fit existing local result transition", err)
	}
	shorter, err := constrainCAWaitAt(key, id, next, ng, providerretry.Hint{NotBefore: at.Add(time.Minute)}, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	wait, _, err = readStagingWaitAt(key, id, shorter, at.Add(time.Second))
	if err != nil || wait.NotBefore != timingStamp(hint.NotBefore) {
		t.Fatal("later operation shortened previous provider wait")
	}
	blocked, err := constrainCAWaitAt(key, id, shorter, ng, providerretry.Hint{Blocked: true}, at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := constrainCAWaitAt(key, id, blocked, ng, providerretry.Hint{}, at.Add(3*time.Second))
	if err != nil || !bytes.Equal(blocked, unchanged) {
		t.Fatal("empty hint cleared a sticky block")
	}
	wait, _, err = readStagingWaitAt(key, id, unchanged, at.Add(2*time.Hour))
	if err != nil || !wait.Blocked || wait.Ready {
		t.Fatal("elapsed time revived blocked provider policy")
	}
}

func TestCAFailureWaitPreservesPendingScopeAndRefusesMissingCapacity(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	defer clear(key)
	if out, err := ConstrainStagingCAWait(key, id, image, 4, providerretry.Hint{Blocked: true}); err == nil || out != nil {
		t.Fatal("no active CA scope gained observation authority")
	}
	image, _, g, err := BeginStagingOrder(key, id, image, 4, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(image)
	if out, err := ConstrainStagingCAWait(key, id, image, g-1, providerretry.Hint{Blocked: true}); !errors.Is(err, ErrStaleGeneration) || out != nil {
		t.Fatal("stale hint accepted")
	}
	hint := providerretry.Hint{NotBefore: time.Now().UTC().Add(time.Hour)}
	next, ng, err := SaveStagingCAFailureWait(key, id, image, g, hint)
	if err != nil || ng != g+1 || !bytes.Equal(image, before) {
		t.Fatal("failure wait mutated input or refused", err)
	}
	state, sg, err := ReadStagingOrder(key, id, next)
	if err != nil || sg != ng || state.State != "request-pending" {
		t.Fatal("failure wait invented CA verdict", err)
	}
	events, _, err := History(key, id, next)
	if err != nil || events[len(events)-1].Action != "acme-provider-wait-saved" {
		t.Fatal("fixed wait event missing")
	}
	full := fillArchiveHistory(t, key, id, image, maxHistory-2)
	_, fg, _ := Open(key, id, full)
	if out, _, err := SaveStagingCAFailureWait(key, id, full, fg, hint); err == nil || out != nil {
		t.Fatal("failure metadata stole two pending order outcomes")
	}
	if out, err := constrainCAWaitAt(key, id, image, g, hint, time.Now().UTC().Add(-time.Hour)); err == nil || out != nil {
		t.Fatal("clock rollback saved CA metadata")
	}
}
