//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func inventoryFixture(t *testing.T) (string, string, string, []byte, []byte, string) {
	t.Helper()
	path, password, key, id := readyV2Fixture(t)
	code, err := EnrollRecovery(path, password)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "initial.rwfull")
	if err := InitializeInventory(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	return path, password, code, key, id, backup
}

func TestLinuxInventoryDurableImportAndFreshFullRestore(t *testing.T) {
	path, password, code, key, id, initial := inventoryFixture(t)
	if info, err := os.Lstat(initial); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe initial backup: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(filepath.Dir(path), inventoryName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe inventory: %v", err)
	}
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	added, gen, err := AppendInventory(path, key, id, revision, cert, "Platform", "production/nginx")
	if err != nil || len(added) != 1 || gen != 2 {
		t.Fatalf("append: %d %v", gen, err)
	}
	if result, _, err := AppendInventory(path, key, id, revision, cert, "", ""); !errors.Is(err, publicinventory.ErrDuplicate) || result != nil {
		t.Fatalf("duplicate saved: %v", err)
	}
	if result, _, err := AppendInventory(path, key, id, revision, []byte("PRIVATE KEY"), "", ""); err == nil || result != nil {
		t.Fatal("malformed input saved")
	}
	stored, gen, err := ReadInventory(path, key, id, revision)
	if err != nil || gen != 2 || len(stored) != 1 || stored[0].Owner != "Platform" {
		t.Fatalf("restart read: %d %v", gen, err)
	}
	if _, _, err := ReadInventory(path, key, id, sha256.Sum256([]byte("stale"))); !errors.Is(err, ErrStaleUpgrade) {
		t.Fatalf("stale session read: %v", err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "full.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{password, SnapshotPassword}, {code, SnapshotRecoveryCode}} {
		openedID, openedGen, err := VerifyFullSnapshot(backup, tc.credential, tc.method)
		if err != nil || openedGen != 2 || !bytes.Equal(openedID, id) {
			t.Fatalf("verify: %v", err)
		}
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	restoredKey, restoredID, err := OpenWithIdentity(fresh, password)
	if err != nil || !bytes.Equal(restoredKey, key) || !bytes.Equal(restoredID, id) {
		t.Fatalf("restored key changed: %v", err)
	}
	restoredRevision, err := Revision(fresh)
	if err != nil {
		t.Fatal(err)
	}
	records, gen, err := ReadInventory(fresh, restoredKey, restoredID, restoredRevision)
	if err != nil || gen != 2 || len(records) != 1 || records[0].Location != "production/nginx" {
		t.Fatalf("restored inventory: %d %v", gen, err)
	}
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); !errors.Is(err, ErrSnapshotNotEmpty) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	const next = "a different sufficiently long password"
	if _, err := RecoverPassword(fresh, code, next); err != nil {
		t.Fatal(err)
	}
	newKey, newID, err := OpenWithIdentity(fresh, next)
	if err != nil || !bytes.Equal(newKey, key) || !bytes.Equal(newID, id) {
		t.Fatalf("recovered restore changed key: %v", err)
	}
	newRev, err := Revision(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if records, _, err := ReadInventory(fresh, newKey, newID, newRev); err != nil || len(records) != 1 {
		t.Fatalf("recovered inventory missing: %v", err)
	}
}

func TestLinuxInventoryAssociationsSurviveRestartAndFullRestore(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	added, generation, err := AppendInventory(path, key, id, revision, cert, "Platform", "production/nginx")
	if err != nil || generation != 2 {
		t.Fatalf("initial import: %v", err)
	}
	fingerprint := added[0].Fingerprint
	updated, generation, err := AssociateInventoryLocation(path, key, id, revision, 2, fingerprint, "production/haproxy")
	if err != nil || generation != 3 || updated.ImportGeneration != 2 || len(updated.Locations) != 2 {
		t.Fatalf("durable association: %v", err)
	}
	before, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		generation            uint64
		fingerprint, location string
		want                  error
	}{
		{2, fingerprint, "stale/location", inventorystore.ErrStaleGeneration},
		{3, fingerprint, "production/haproxy", publicinventory.ErrLocationDuplicate},
		{3, "unknown", "new/location", inventorystore.ErrNotFound},
	} {
		if _, _, err := AssociateInventoryLocation(path, key, id, revision, tc.generation, tc.fingerprint, tc.location); !errors.Is(err, tc.want) {
			t.Fatalf("unsafe association accepted: %v", err)
		}
		after, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejected association changed image")
		}
	}
	records, generation, err := ReadInventory(path, key, id, revision)
	if err != nil || generation != 3 || len(records) != 1 || len(records[0].Locations) != 2 {
		t.Fatalf("restart read lost locations: %v", err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "with-locations.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	restoredRevision, err := Revision(fresh)
	if err != nil {
		t.Fatal(err)
	}
	restored, generation, err := ReadInventory(fresh, key, id, restoredRevision)
	if err != nil || generation != 3 || len(restored) != 1 || len(restored[0].Locations) != 2 || restored[0].Locations[1] != "production/haproxy" {
		t.Fatalf("full restore lost locations: %v", err)
	}
}

func TestLinuxInventoryOwnerCorrectionIsDurableAndRestorable(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	added, generation, err := AppendInventory(path, key, id, revision, cert, "Platform", "production/nginx")
	if err != nil || generation != 2 {
		t.Fatalf("initial import: %v", err)
	}
	updated, generation, err := UpdateInventoryOwner(path, key, id, revision, 2, added[0].Fingerprint, "Security")
	if err != nil || generation != 3 || updated.Owner != "Security" || updated.ImportGeneration != 2 {
		t.Fatalf("owner correction: %v", err)
	}
	before, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		generation uint64
		owner      string
		want       error
	}{
		{2, "stale", inventorystore.ErrStaleGeneration},
		{3, "Security", publicinventory.ErrOwnerUnchanged},
		{3, "bad\nowner", publicinventory.ErrLabel},
	} {
		if _, _, err := UpdateInventoryOwner(path, key, id, revision, tc.generation, added[0].Fingerprint, tc.owner); !errors.Is(err, tc.want) {
			t.Fatalf("unsafe owner correction accepted: %v", err)
		}
		after, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejected owner correction changed image")
		}
	}
	backup := filepath.Join(privateSnapshotDir(t), "with-corrected-owner.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	newRevision, err := Revision(fresh)
	if err != nil {
		t.Fatal(err)
	}
	restored, generation, err := ReadInventory(fresh, key, id, newRevision)
	if err != nil || generation != 3 || len(restored) != 1 || restored[0].Owner != "Security" || restored[0].ImportGeneration != 2 {
		t.Fatalf("restore lost corrected owner: %v", err)
	}
}

func TestLinuxInventoryRefusesUnsafeAndBusyOperations(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	other := filepath.Join(privateSnapshotDir(t), "second.rwfull")
	if err := InitializeInventory(path, other, password, code); !errors.Is(err, ErrInventoryExists) {
		t.Fatalf("reinit accepted: %v", err)
	}
	if _, err := os.Lstat(other); !os.IsNotExist(err) {
		t.Fatal("duplicate initialization wrote backup")
	}
	release, err := AcquireOperationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExportFullSnapshot(path, other, password, code); !errors.Is(err, ErrOperationBusy) {
		t.Fatalf("live daemon export: %v", err)
	}
	release()
	if err := ExportFullSnapshot(path, other, "wrong", code); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password export: %v", err)
	}
	if _, err := os.Lstat(other); !os.IsNotExist(err) {
		t.Fatal("rejected export wrote file")
	}
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadInventory(path, bytes.Repeat([]byte{0x44}, 32), id, revision); err == nil {
		t.Fatal("wrong key opened inventory")
	}
	if _, _, err := ReadInventory(path, key, bytes.Repeat([]byte{0x44}, 16), revision); err == nil {
		t.Fatal("wrong identity opened inventory")
	}
	inventoryPath := filepath.Join(filepath.Dir(path), inventoryName)
	body, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 1
	if err := os.WriteFile(inventoryPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if records, _, err := ReadInventory(path, key, id, revision); err == nil || records != nil {
		t.Fatal("tampered inventory opened")
	}
}

func TestLinuxInventoryPostRenameSyncFaultIsUncertain(t *testing.T) {
	path, _, _, key, id, _ := inventoryFixture(t)
	inventoryPath := filepath.Join(filepath.Dir(path), inventoryName)
	image, err := readInventory(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := inventorystore.Append(key, id, image, cert, "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = replaceInventoryWithSync(inventoryPath, next, func(string) error { return errors.New("simulated directory fsync failure") })
	if !errors.Is(err, ErrInventoryUncertain) {
		t.Fatalf("post-rename fault not uncertain: %v", err)
	}
	read, err := readInventory(inventoryPath)
	if err != nil || !bytes.Equal(read, next) {
		t.Fatalf("uncertain write unreadable: %v", err)
	}
}

func TestLinuxInventoryPreRenameDiskFaultPreservesOriginal(t *testing.T) {
	path, _, _, _, _, _ := inventoryFixture(t)
	inventoryPath := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceInventoryWithHooks(inventoryPath, []byte("replacement"), func(f *os.File, _ []byte) error {
		_, _ = f.Write([]byte("partial"))
		return syscall.ENOSPC
	}, syncAccessDirectory)
	if !errors.Is(err, ErrInvalidFullSnapshot) {
		t.Fatalf("disk-full fault accepted: %v", err)
	}
	after, err := readInventory(inventoryPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("pre-rename fault replaced inventory")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".rootwell-inventory-") {
			t.Fatal("pre-rename fault left temp image")
		}
	}
}

func TestLinuxFullSnapshotRefusesUnsafePathsAndTampering(t *testing.T) {
	path, password, code, _, _, _ := inventoryFixture(t)
	permissive := privateSnapshotDir(t)
	if err := os.Chmod(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	unsafePath := filepath.Join(permissive, "unsafe.rwfull")
	if err := ExportFullSnapshot(path, unsafePath, password, code); !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive backup directory accepted: %v", err)
	}
	if _, err := os.Lstat(unsafePath); !os.IsNotExist(err) {
		t.Fatal("unsafe export wrote file")
	}
	backup := filepath.Join(privateSnapshotDir(t), "full.rwfull")
	if err := ExportFullSnapshot(path, backup, password, "wrong-code"); !errors.Is(err, ErrInvalidRecovery) {
		t.Fatalf("wrong code exported: %v", err)
	}
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	if err := ExportFullSnapshot(path, backup, password, code); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("snapshot overwritten: %v", err)
	}
	link := filepath.Join(privateSnapshotDir(t), "linked.rwfull")
	if err := os.Symlink(backup, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFullSnapshot(link, password, SnapshotPassword); !errors.Is(err, ErrInvalidFullSnapshot) {
		t.Fatalf("symlink backup accepted: %v", err)
	}
	body, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(backup, body, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); !errors.Is(err, ErrInvalidFullSnapshot) {
		t.Fatalf("tampered snapshot restored: %v", err)
	}
	if _, err := os.Lstat(fresh); !os.IsNotExist(err) {
		t.Fatal("rejected restore created access file")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(fresh), inventoryName)); !os.IsNotExist(err) {
		t.Fatal("rejected restore created inventory")
	}
}
