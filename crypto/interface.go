// Package crypto provides encryption utilities for column-level encryption
// with support for multiple algorithms and key management providers.
package crypto

import (
	"encoding/json"
	"errors"
)

// Error definitions
var (
	ErrKeyNotFound    = errors.New("encryption key not found")
	ErrInvalidKey     = errors.New("invalid encryption key")
	ErrDecryptionFailed = errors.New("decryption failed")
)

// KeyProvider defines the interface for key management services.
// Implementations can use environment variables, AWS KMS, HashiCorp Vault, etc.
type KeyProvider interface {
	// GetKey retrieves the encryption key for the given keyID.
	GetKey(keyID string) ([]byte, error)

	// EncryptKey encrypts a key for storage.
	EncryptKey(key []byte, keyID string) ([]byte, error)

	// DecryptKey decrypts an encrypted key.
	DecryptKey(encryptedKey []byte) ([]byte, error)

	// KeyID returns the unique identifier for this provider.
	KeyID() string
}

// Encrypter interface supports multiple encryption algorithms.
type Encrypter interface {
	// Encrypt encrypts plaintext using the provided key provider.
	Encrypt(plaintext string, keyProvider KeyProvider) (string, error)

	// Decrypt decrypts encrypted data using the provided key provider.
	Decrypt(encrypted string, keyProvider KeyProvider) (string, error)

	// Algorithm returns the name of the encryption algorithm.
	Algorithm() string

	// KeySize returns the required key size in bytes.
	KeySize() int
}

// DataEnvelope holds encrypted data with metadata for versioning
// and algorithm identification. This enables seamless key rotation
// and algorithm upgrades.
type DataEnvelope struct {
	Algorithm    string `json:"alg"`     // Encryption algorithm used
	KeyID        string `json:"kid"`     // Key identifier for KMS/Vault
	EncryptedKey string `json:"ek"`      // Encapsulated key (for ML-KEM)
	Nonce        string `json:"nonce"`   // Random nonce for symmetric encryption
	Ciphertext   string `json:"ct"`      // Encrypted data
	Version      int    `json:"v"`       // Schema version for future changes
}

// Marshal serializes the envelope to JSON.
func (e *DataEnvelope) Marshal() string {
	data, _ := json.Marshal(e)
	return string(data)
}

// Unmarshal deserializes JSON data into an envelope.
func (e *DataEnvelope) Unmarshal(data string) error {
	return json.Unmarshal([]byte(data), e)
}

// IsEncrypted checks if the data appears to be encrypted.
func IsEncrypted(data string) bool {
	var envelope DataEnvelope
	return envelope.Unmarshal(data) == nil && envelope.Ciphertext != ""
}
