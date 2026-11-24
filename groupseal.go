// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrGroupKeyMissing is returned when seal or open is called without the matching group key.
var ErrGroupKeyMissing = errors.New("reach: group key missing")

// ErrGroupKeyMismatch is returned when decrypt fails the AEAD tag check.
var ErrGroupKeyMismatch = errors.New("reach: group key mismatch")

// GroupKey is a 32-byte ChaCha20-Poly1305 symmetric key shared by one group of
// nodes.
// Key distribution is out of scope for this package — consumers provision
// keys via a restricted whisper topic, enrollment, or manual config.
type GroupKey struct {
	ID  string // short identifier; rotates weekly
	Key []byte // exactly 32 bytes
}

// PrivateAddresses is the cleartext payload sealed in EncryptedSection.
// When members of the group decrypt the section they see these addresses; when
// non-members decrypt nothing they just see the outer record without this data.
type PrivateAddresses struct {
	Addresses []Address `json:"addrs"`
}

// SealGroup encrypts a slice of addresses for same-group peers only.
// The resulting EncryptedSection is safe to publish in the ledger.
func SealGroup(addrs []Address, key GroupKey) (*EncryptedSection, error) {
	if len(key.Key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("reach: group key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key.Key))
	}
	payload := PrivateAddresses{Addresses: addrs}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("reach: marshal private addresses: %w", err)
	}

	aead, err := chacha20poly1305.New(key.Key)
	if err != nil {
		return nil, fmt.Errorf("reach: aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("reach: nonce: %w", err)
	}

	ct := aead.Seal(nil, nonce, plaintext, []byte(key.ID))
	return &EncryptedSection{
		GroupID:      key.ID, // by convention GroupID == KeyID is the short key fingerprint
		KeyID:      key.ID,
		Nonce:      nonce,
		Ciphertext: ct,
	}, nil
}

// OpenGroup decrypts an EncryptedSection with the given key. Returns ErrGroupKeyMismatch
// if the tag check fails (wrong key, tampered ciphertext, etc.).
func OpenGroup(section *EncryptedSection, key GroupKey) ([]Address, error) {
	if section == nil {
		return nil, nil
	}
	if len(key.Key) != chacha20poly1305.KeySize {
		return nil, ErrGroupKeyMissing
	}
	aead, err := chacha20poly1305.New(key.Key)
	if err != nil {
		return nil, err
	}
	// aead.Open panics on a nonce of any other length, and the nonce is the
	// record's own bytes, so a section is refused before Open sees one.
	if len(section.Nonce) != aead.NonceSize() {
		return nil, ErrGroupKeyMismatch
	}
	plaintext, err := aead.Open(nil, section.Nonce, section.Ciphertext, []byte(key.ID))
	if err != nil {
		return nil, ErrGroupKeyMismatch
	}
	var payload PrivateAddresses
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("reach: unmarshal private addresses: %w", err)
	}
	return payload.Addresses, nil
}
