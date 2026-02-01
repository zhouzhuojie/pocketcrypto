package pocketcrypto

import (
	"encoding/base64"
	"errors"
	"os"
)

// LocalProvider provides key management using environment variables.
type LocalProvider struct {
	masterKey []byte
}

// newLocalProvider creates a new LocalProvider from the ENCRYPTION_KEY environment variable.
func newLocalProvider() (*LocalProvider, error) {
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

// newLocalProviderFromKey creates a LocalProvider directly from a key byte slice.
func newLocalProviderFromKey(key []byte) (*LocalProvider, error) {
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

// EncryptKey returns the key as-is.
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

// MasterKey returns a copy of the master key.
func (p *LocalProvider) MasterKey() []byte {
	result := make([]byte, len(p.masterKey))
	copy(result, p.masterKey)
	return result
}
