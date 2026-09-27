package instanceaccess

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

const (
	fullMagic           = "RWFULL01"
	fullLabel           = "rootwell.full-snapshot.v1:"
	maxFullSnapshotFile = 100 << 20
	fullHeader          = len(fullMagic) + 8
)

var (
	ErrInvalidFullSnapshot = errors.New("complete inventory snapshot or credential is invalid")
	ErrInventoryMissing    = errors.New("durable inventory is not initialized")
	ErrInventoryExists     = errors.New("durable inventory already exists")
	ErrInventoryUncertain  = errors.New("inventory operation may have been written; inspect before retrying")
)

// createFullSnapshot binds the exact access envelope and a complete encrypted
// inventory image under the same data key. Password and separately held
// recovery code are both required at export time.
func createFullSnapshot(accessBody, image []byte, password, code string) ([]byte, error) {
	accessSnapshot, err := createAccessSnapshot(accessBody, password, code)
	if err != nil {
		return nil, err
	}
	key, state, id, err := unsealBody(accessBody, password)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if state != ready {
		return nil, ErrChangeRequired
	}
	if _, _, err := inventorystore.Open(key, id, image); err != nil {
		return nil, ErrInvalidFullSnapshot
	}
	if len(image) == 0 || len(image) > maxFullSnapshotFile-fullHeader-len(accessSnapshot)-sha256.Size {
		return nil, ErrInvalidFullSnapshot
	}
	out := make([]byte, fullHeader+len(accessSnapshot)+len(image)+sha256.Size)
	copy(out, fullMagic)
	// #nosec G115 -- both component sizes are bounded by the 100 MiB full file limit.
	binary.BigEndian.PutUint32(out[len(fullMagic):], uint32(len(accessSnapshot)))
	// #nosec G115 -- both component sizes are bounded by the 100 MiB full file limit.
	binary.BigEndian.PutUint32(out[len(fullMagic)+4:], uint32(len(image)))
	copy(out[fullHeader:], accessSnapshot)
	copy(out[fullHeader+len(accessSnapshot):], image)
	copy(out[len(out)-sha256.Size:], fullSnapshotMAC(key, out[:len(out)-sha256.Size]))
	return out, nil
}

func openFullSnapshot(snapshot []byte, credential string, method SnapshotUnlock) ([]byte, []byte, []byte, uint64, error) {
	if len(snapshot) < fullHeader+snapshotOverhead+1+1+sha256.Size || len(snapshot) > maxFullSnapshotFile ||
		!bytes.Equal(snapshot[:len(fullMagic)], []byte(fullMagic)) {
		return nil, nil, nil, 0, ErrInvalidFullSnapshot
	}
	accessLen := binary.BigEndian.Uint32(snapshot[len(fullMagic):])
	imageLen := binary.BigEndian.Uint32(snapshot[len(fullMagic)+4:])
	if accessLen < uint32(snapshotOverhead+1) || accessLen > uint32(maxSnapshotFile) || imageLen == 0 ||
		uint64(fullHeader)+uint64(accessLen)+uint64(imageLen)+sha256.Size != uint64(len(snapshot)) {
		return nil, nil, nil, 0, ErrInvalidFullSnapshot
	}
	accessSnapshot := snapshot[fullHeader : fullHeader+int(accessLen)]
	image := snapshot[fullHeader+int(accessLen) : len(snapshot)-sha256.Size]
	body, id, key, err := openAccessSnapshotWithKey(accessSnapshot, credential, method)
	if err != nil {
		return nil, nil, nil, 0, ErrInvalidFullSnapshot
	}
	defer clear(key)
	if !hmac.Equal(fullSnapshotMAC(key, snapshot[:len(snapshot)-sha256.Size]), snapshot[len(snapshot)-sha256.Size:]) {
		return nil, nil, nil, 0, ErrInvalidFullSnapshot
	}
	_, generation, err := inventorystore.Open(key, id, image)
	if err != nil {
		return nil, nil, nil, 0, ErrInvalidFullSnapshot
	}
	return body, id, bytes.Clone(image), generation, nil
}

func fullSnapshotMAC(key, contents []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(fullLabel))
	_, _ = mac.Write(contents)
	return mac.Sum(nil)
}
