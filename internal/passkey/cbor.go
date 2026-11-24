package passkey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf8"
)

// errCBOR hides why an authenticator's data was refused.
var errCBOR = errors.New("malformed authenticator data")

const (
	maxDepth = 8
	maxItems = 64
)

// decodeCBOR reads one CBOR item strictly, as WebAuthn uses it: unsigned and
// negative integers, byte and text strings, arrays, maps with integer or text
// keys, and true, false and null. Indefinite lengths, tags and floats are
// refused, and so are duplicate map keys. It returns what follows the item.
//
// Values come back as int64, []byte, string, []any, map[any]any, bool or nil.
func decodeCBOR(data []byte) (any, []byte, error) { return decodeItem(data, 0) }

func argument(info byte, b []byte) (uint64, []byte, error) {
	switch {
	case info < 24:
		return uint64(info), b, nil
	case info == 24 && len(b) >= 1:
		return uint64(b[0]), b[1:], nil
	case info == 25 && len(b) >= 2:
		return uint64(binary.BigEndian.Uint16(b)), b[2:], nil
	case info == 26 && len(b) >= 4:
		return uint64(binary.BigEndian.Uint32(b)), b[4:], nil
	case info == 27 && len(b) >= 8:
		return binary.BigEndian.Uint64(b), b[8:], nil
	}
	return 0, nil, errCBOR
}

func decodeItem(b []byte, depth int) (any, []byte, error) {
	if len(b) == 0 || depth > maxDepth {
		return nil, nil, errCBOR
	}
	major, info := b[0]>>5, b[0]&0x1f
	if major == 7 {
		switch info {
		case 20:
			return false, b[1:], nil
		case 21:
			return true, b[1:], nil
		case 22:
			return nil, b[1:], nil
		}
		return nil, nil, errCBOR
	}
	arg, rest, err := argument(info, b[1:])
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return int64(arg), rest, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return -1 - int64(arg), rest, nil
	case 2, 3:
		if arg > uint64(len(rest)) {
			return nil, nil, errCBOR
		}
		value := bytes.Clone(rest[:arg])
		if major == 3 {
			if !utf8.Valid(value) {
				return nil, nil, errCBOR
			}
			return string(value), rest[arg:], nil
		}
		return value, rest[arg:], nil
	case 4:
		if arg > maxItems {
			return nil, nil, errCBOR
		}
		items := make([]any, 0, arg)
		for range arg {
			var item any
			if item, rest, err = decodeItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			items = append(items, item)
		}
		return items, rest, nil
	case 5:
		if arg > maxItems {
			return nil, nil, errCBOR
		}
		m := make(map[any]any, arg)
		for range arg {
			var key, value any
			if key, rest, err = decodeItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			switch key.(type) {
			case int64, string:
			default:
				return nil, nil, errCBOR
			}
			if _, seen := m[key]; seen {
				return nil, nil, errCBOR
			}
			if value, rest, err = decodeItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			m[key] = value
		}
		return m, rest, nil
	}
	return nil, nil, errCBOR
}
