package instanceaccess

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	snapshotMagic    = "RWACCESS1"
	snapshotLabel    = "rootwell.access-snapshot.v1:"
	snapshotOverhead = len(snapshotMagic) + 16 + 4 + sha256.Size
	maxSnapshotFile  = snapshotOverhead + maxFile
)

var (
	ErrInvalidSnapshot     = errors.New("access snapshot or credential is invalid")
	ErrSnapshotExists      = errors.New("access snapshot destination already exists")
	ErrSnapshotNotEmpty    = errors.New("restore destination is not empty")
	ErrSnapshotUnsupported = errors.New("access snapshots are unsupported on this platform")
)

type SnapshotUnlock uint8

const (
	SnapshotPassword SnapshotUnlock = iota + 1
	SnapshotRecoveryCode
)

// createAccessSnapshot makes a bounded, access-only encrypted snapshot. The
// access envelope is already encrypted; a data-key MAC binds its exact bytes
// to the snapshot header. It does not include future inventory records.
func createAccessSnapshot(body []byte, password, code string) ([]byte, error) {
	key, _, id, err := unsealBody(body, password)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	e, err := parseEnvelope(body)
	if err != nil || e.Version != 3 || e.State != ready {
		return nil, ErrRecoveryMissing
	}
	if !bytes.Equal(id, e.InstallationID) {
		return nil, ErrInvalidSnapshot
	}
	codeKey, err := OpenRecoveryWrap(e.RecoveryWrap, code, id)
	if err != nil || !bytes.Equal(codeKey, key) {
		clear(codeKey)
		return nil, ErrInvalidRecovery
	}
	clear(codeKey)
	snapshot := make([]byte, snapshotOverhead+len(body))
	copy(snapshot, snapshotMagic)
	if _, err := rand.Read(snapshot[len(snapshotMagic) : len(snapshotMagic)+16]); err != nil {
		return nil, errors.New("access snapshot identity could not be generated")
	}
	// #nosec G115 -- parseEnvelope bounds body to 4 KiB before this conversion.
	binary.BigEndian.PutUint32(snapshot[len(snapshotMagic)+16:], uint32(len(body)))
	copy(snapshot[len(snapshotMagic)+20:], body)
	copy(snapshot[len(snapshot)-sha256.Size:], snapshotMAC(key, snapshot[:len(snapshot)-sha256.Size]))
	return snapshot, nil
}

// openAccessSnapshot validates a complete access-only snapshot with either
// the password or the separately stored offline recovery code. No plaintext
// data key is returned to the caller.
func openAccessSnapshot(snapshot []byte, credential string, method SnapshotUnlock) ([]byte, []byte, error) {
	if (method != SnapshotPassword && method != SnapshotRecoveryCode) || len(credential) == 0 || len(credential) > maxPass ||
		len(snapshot) < snapshotOverhead+1 || len(snapshot) > maxSnapshotFile ||
		!bytes.Equal(snapshot[:len(snapshotMagic)], []byte(snapshotMagic)) {
		return nil, nil, ErrInvalidSnapshot
	}
	declared := binary.BigEndian.Uint32(snapshot[len(snapshotMagic)+16:])
	if declared == 0 || declared > maxFile || len(snapshot) != snapshotOverhead+int(declared) {
		return nil, nil, ErrInvalidSnapshot
	}
	body := snapshot[len(snapshotMagic)+20 : len(snapshot)-sha256.Size]
	e, err := parseEnvelope(body)
	if err != nil || e.Version != 3 || e.State != ready {
		return nil, nil, ErrInvalidSnapshot
	}
	var key []byte
	if method == SnapshotPassword {
		key, _, _, err = unsealBody(body, credential)
	} else {
		key, err = OpenRecoveryWrap(e.RecoveryWrap, credential, e.InstallationID)
		if err == nil && !hmac.Equal(recoveryCheck(key, e.InstallationID, e.RecoveryWrap), e.RecoveryCheck) {
			err = ErrInvalidSnapshot
		}
	}
	if err != nil {
		clear(key)
		return nil, nil, ErrInvalidSnapshot
	}
	defer clear(key)
	if !hmac.Equal(snapshotMAC(key, snapshot[:len(snapshot)-sha256.Size]), snapshot[len(snapshot)-sha256.Size:]) {
		return nil, nil, ErrInvalidSnapshot
	}
	return bytes.Clone(body), bytes.Clone(e.InstallationID), nil
}

func snapshotMAC(key, contents []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(snapshotLabel))
	_, _ = mac.Write(contents)
	return mac.Sum(nil)
}
