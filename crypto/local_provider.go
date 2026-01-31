package crypto

import (
	"encoding/base64"
	"errors"
	"os"
)

// LocalProvider provides key management using environment variables.
// This is intended for development and testing only.
// For production, use AWSKMSProvider or VaultProvider.
type LocalProvider struct {
	masterKey []byte
}

// NewLocalProvider creates a new LocalProvider by reading the encryption key
// from the ENCRYPTION_KEY environment variable.
// The key must be base64-encoded and 32 bytes decoded (for AES-256).
func NewLocalProvider() (*LocalProvider, error) {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		return nil, errors.New("ENCRYPTION_KEY environment variable is not set")
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, errors.New("invalid base64 encoding in ENCRYPTION_KEY")
	}

	if len(key) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be 32 bytes (256 bits) when decoded")
	}

	return &LocalProvider{masterKey: key}, nil
}

// NewLocalProviderFromKey creates a LocalProvider directly from a key byte slice.
// This is useful for testing.
func NewLocalProviderFromKey(key []byte) (*LocalProvider, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &LocalProvider{masterKey: keyCopy}, nil
}

// GetKey retrieves the master encryption key.
func (p *LocalProvider) GetKey(keyID string) ([]byte, error) {
	return p.masterKey, nil
}

// EncryptKey returns the key as-is. For local provider, the key is not
// further encrypted (this is not recommended for production).
func (p *LocalProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

// DecryptKey returns the encrypted key as-is.
func (p *LocalProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

// KeyID returns the identifier for this provider.
func (p *LocalProvider) KeyID() string {
	return "local-master"
}

// MasterKey returns a copy of the master key for backup purposes.
func (p *LocalProvider) MasterKey() []byte {
	result := make([]byte, len(p.masterKey))
	copy(result, p.masterKey)
	return result
}
