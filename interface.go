// Package pocketcrypto provides column-level encryption for PocketBase
// with support for AES-256-GCM authenticated encryption, post-quantum
// ML-KEM-768 key encapsulation, and multiple key management providers.
package pocketcrypto

import (
	"context"
	"encoding/json"
	"errors"
	"os"
)

// Error definition
var ErrInvalidKey = errors.New("invalid encryption key")

// KeyProvider defines the interface for key management services.
type KeyProvider interface {
	GetKey(keyID string) ([]byte, error)
	EncryptKey(key []byte, keyID string) ([]byte, error)
	DecryptKey(encryptedKey []byte) ([]byte, error)
	KeyID() string
}

// RotatableProvider extends KeyProvider with rotation support.
type RotatableProvider interface {
	KeyProvider
	RotateKey(ctx context.Context) (string, error)
	GetKeyVersion(keyID string, version int) ([]byte, error)
	CurrentKeyVersion() int
}

// Encrypter interface supports multiple encryption algorithms.
type Encrypter interface {
	Encrypt(plaintext string, keyProvider KeyProvider) (string, error)
	Decrypt(encrypted string, keyProvider KeyProvider) (string, error)
	Algorithm() string
	KeySize() int
}

// DataEnvelope holds encrypted data with metadata.
type DataEnvelope struct {
	Algorithm    string `json:"alg"`
	KeyID        string `json:"kid"`
	EncryptedKey string `json:"ek"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ct"`
	Version      int    `json:"v"`
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

// ProviderType defines the type of key provider.
type ProviderType string

const (
	ProviderTypeLocal  ProviderType = "local"
	ProviderTypeAWSKMS ProviderType = "aws-kms"
	ProviderTypeVault  ProviderType = "vault"
)

// KeyVersionInfo contains metadata about a key version.
type KeyVersionInfo struct {
	Version   int
	CreatedAt int64
	Algorithm string
}

// EncryptedRecord represents a record with encrypted fields.
type EncryptedRecord struct {
	ID              string            `json:"id"`
	EncryptedFields map[string]string `json:"encrypted_fields"`
}

// CollectionConfig holds configuration for encrypting a collection.
type CollectionConfig struct {
	Collection string   `json:"collection"`
	Fields     []string `json:"fields"`
}

// unknownProviderTypeError is an error for unknown provider types.
type unknownProviderTypeError struct{}

func (e *unknownProviderTypeError) Error() string {
	return "unknown key provider type"
}

var errUnknownProviderType = &unknownProviderTypeError{}

// newProvider creates a KeyProvider based on the specified type.
func newProvider(providerType ProviderType) (KeyProvider, error) {
	if providerType == "" {
		providerType = ProviderType(os.Getenv("KEY_PROVIDER"))
	}

	if providerType == "" {
		providerType = ProviderTypeLocal
	}

	switch providerType {
	case ProviderTypeLocal:
		return newLocalProvider()
	case ProviderTypeAWSKMS:
		return newAWSKMSProviderFromEnv()
	case ProviderTypeVault:
		return newVaultProvider()
	default:
		return nil, errUnknownProviderType
	}
}

// IsEncrypted checks if the data appears to be encrypted.
func IsEncrypted(data string) bool {
	var envelope DataEnvelope
	return envelope.Unmarshal(data) == nil && envelope.Ciphertext != ""
}
