// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"bytes"
	"errors"
	"testing"
)

// A section whose nonce is not the cipher's length is refused, not handed to the
// cipher, which panics on one.
func TestOpenGroupRefusesANonceOfTheWrongLength(t *testing.T) {
	key := GroupKey{ID: "g1", Key: bytes.Repeat([]byte{7}, 32)}
	for _, n := range [][]byte{nil, {1, 2, 3}, bytes.Repeat([]byte{1}, 25)} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("OpenGroup panicked on a %d-byte nonce: %v", len(n), p)
				}
			}()
			if _, err := OpenGroup(&EncryptedSection{GroupID: "g1", KeyID: "g1", Nonce: n, Ciphertext: []byte("ct")}, key); !errors.Is(err, ErrGroupKeyMismatch) {
				t.Fatalf("a %d-byte nonce: err = %v, want ErrGroupKeyMismatch", len(n), err)
			}
		}()
	}
}
