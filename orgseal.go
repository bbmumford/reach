// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrOrgKeyMissing is returned when seal or open is called without the matching org key.
var ErrOrgKeyMissing = errors.New("reach: org key missing")

// ErrOrgKeyMismatch is returned when decrypt fails the AEAD tag check.
var ErrOrgKeyMismatch = errors.New("reach: org key mismatch")

// OrgKey is a 32-byte ChaCha20-Poly1305 symmetric key for an organisation.
// Key distribution is out of scope for this package — consumers provision
// keys via a restricted whisper topic, enrollment, or manual config.
type OrgKey struct {
	ID  string // short identifier; rotates weekly
	Key []byte // exactly 32 bytes
}

// PrivateAddresses is the cleartext payload sealed in EncryptedSection.
// When members of an org decrypt the section they see these addresses; when
// non-members decrypt nothing they just see the outer record without this data.
type PrivateAddresses struct {
	Addresses []Address `json:"addrs"`
}

// SealOrg encrypts a slice of addresses for same-org peers only.
// The resulting EncryptedSection is safe to publish in the ledger.
func SealOrg(addrs []Address, key OrgKey) (*EncryptedSection, error) {
	if len(key.Key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("reach: org key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key.Key))
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
		OrgID:      key.ID, // by convention OrgID == KeyID is the short key fingerprint
		KeyID:      key.ID,
		Nonce:      nonce,
		Ciphertext: ct,
	}, nil
}

// OpenOrg decrypts an EncryptedSection with the given key. Returns ErrOrgKeyMismatch
// if the tag check fails (wrong key, tampered ciphertext, etc.).
func OpenOrg(section *EncryptedSection, key OrgKey) ([]Address, error) {
	if section == nil {
		return nil, nil
	}
	if len(key.Key) != chacha20poly1305.KeySize {
		return nil, ErrOrgKeyMissing
	}
	aead, err := chacha20poly1305.New(key.Key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, section.Nonce, section.Ciphertext, []byte(key.ID))
	if err != nil {
		return nil, ErrOrgKeyMismatch
	}
	var payload PrivateAddresses
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("reach: unmarshal private addresses: %w", err)
	}
	return payload.Addresses, nil
}
