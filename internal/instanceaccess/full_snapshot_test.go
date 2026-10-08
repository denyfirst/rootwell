package instanceaccess

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func fullFixture(t *testing.T) ([]byte, []byte, string, string, []byte, []byte) {
	t.Helper()
	path, password, key, id := readyV2Fixture(t)
	code, err := changeRecoveryLocked(path, password, "", recoveryEnroll, replace, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	body, err := readAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	image, err := inventorystore.Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	image, _, err = inventorystore.Append(key, id, image, cert, "Platform", "prod")
	if err != nil {
		t.Fatal(err)
	}
	return body, image, password, code, key, id
}

func TestFullSnapshotPasswordAndCodeRoundTrip(t *testing.T) {
	body, image, password, code, _, id := fullFixture(t)
	snapshot, err := createFullSnapshot(body, image, password, code)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snapshot, []byte("Platform")) || bytes.Contains(snapshot, []byte("prod")) {
		t.Fatal("metadata leaked")
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{password, SnapshotPassword}, {code, SnapshotRecoveryCode}} {
		opened, openedID, openedImage, gen, err := openFullSnapshot(snapshot, tc.credential, tc.method)
		if err != nil || !bytes.Equal(opened, body) || !bytes.Equal(openedID, id) || !bytes.Equal(openedImage, image) || gen != 2 {
			t.Fatalf("full snapshot did not open: %v", err)
		}
	}
}

func TestFullSnapshotRetainsStagingAccountKeyAndHistory(t *testing.T) {
	body, image, password, code, key, id := fullFixture(t)
	defer clear(key)
	next, account, gen, err := inventorystore.PrepareStagingAccount(key, id, image, 2)
	if err != nil || gen != 3 {
		t.Fatal("account preparation failed")
	}
	snapshot, err := createFullSnapshot(body, next, password, code)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{password, SnapshotPassword}, {code, SnapshotRecoveryCode}} {
		_, _, restored, generation, err := openFullSnapshot(snapshot, tc.credential, tc.method)
		if err != nil || generation != 3 || !bytes.Equal(restored, next) {
			t.Fatal("full snapshot changed account image")
		}
		status, _, err := inventorystore.ReadStagingAccount(key, id, restored)
		if err != nil || status != account {
			t.Fatal("restored account changed identity")
		}
		events, _, err := inventorystore.History(key, id, restored)
		if err != nil || len(events) != 2 || events[1].Action != "acme-key-prepared" {
			t.Fatal("snapshot lost account history")
		}
	}
}

func TestFullSnapshotRefusesWrongCredentialsAndIncompletePairs(t *testing.T) {
	body, image, password, code, key, id := fullFixture(t)
	for _, tc := range []struct{ password, code string }{{"wrong", code}, {password, "wrong"}} {
		if result, err := createFullSnapshot(body, image, tc.password, tc.code); err == nil || result != nil {
			t.Fatal("wrong credential created full snapshot")
		}
	}
	otherID := bytes.Repeat([]byte{0x12}, 16)
	wrongImage, err := inventorystore.Create(key, otherID)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := createFullSnapshot(body, wrongImage, password, code); !errors.Is(err, ErrInvalidFullSnapshot) || result != nil {
		t.Fatal("cross-installation image was paired")
	}
	snapshot, err := createFullSnapshot(body, image, password, code)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{"wrong", SnapshotPassword}, {"wrong", SnapshotRecoveryCode}, {code, SnapshotPassword}, {password, SnapshotRecoveryCode}} {
		if opened, _, _, _, err := openFullSnapshot(snapshot, tc.credential, tc.method); err == nil || opened != nil {
			t.Fatal("wrong credential opened full snapshot")
		}
	}
	changed := bytes.Clone(snapshot)
	changed[len(changed)-33] ^= 1
	if opened, _, _, _, err := openFullSnapshot(changed, password, SnapshotPassword); err == nil || opened != nil {
		t.Fatal("tampered image opened")
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	other, err := inventorystore.Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err = inventorystore.Append(key, id, other, cert, "Operator", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != len(image) {
		t.Fatal("test needs equal-length authenticated images")
	}
	mixed := bytes.Clone(snapshot)
	copy(mixed[fullHeader+int(binary.BigEndian.Uint32(mixed[len(fullMagic):])):len(mixed)-sha256.Size], other)
	if opened, _, _, _, err := openFullSnapshot(mixed, password, SnapshotPassword); err == nil || opened != nil {
		t.Fatal("valid but unpaired image opened")
	}
	for _, bad := range [][]byte{snapshot[:len(snapshot)-1], append(bytes.Clone(snapshot), 'x'), []byte("bad")} {
		if opened, _, _, _, err := openFullSnapshot(bad, code, SnapshotRecoveryCode); err == nil || opened != nil {
			t.Fatal("malformed full snapshot opened")
		}
	}
	_ = id
}

func FuzzOpenFullSnapshot(f *testing.F) {
	key, id := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 16)
	wrap, code, err := CreateRecoveryWrap(id, key)
	if err != nil {
		f.Fatal(err)
	}
	const password = "a sufficiently long fuzz password"
	body, err := sealWithRecovery(key, password, ready, id, wrap)
	if err != nil {
		f.Fatal(err)
	}
	image, err := inventorystore.Create(key, id)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := createFullSnapshot(body, image, password, code)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFullSnapshotFile {
			return
		}
		_, _, _, _, _ = openFullSnapshot(data, password, SnapshotPassword)
	})
}
