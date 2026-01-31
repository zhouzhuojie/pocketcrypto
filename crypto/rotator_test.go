package crypto

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRotatableProvider is a mock RotatableProvider for testing.
type mockRotatableProvider struct {
	key            []byte
	currentVersion int
}

func (m *mockRotatableProvider) GetKey(keyID string) ([]byte, error)   { return m.key, nil }
func (m *mockRotatableProvider) EncryptKey(key []byte, keyID string) ([]byte, error) { return key, nil }
func (m *mockRotatableProvider) DecryptKey(encryptedKey []byte) ([]byte, error) { return encryptedKey, nil }
func (m *mockRotatableProvider) KeyID() string                            { return "test" }

func (m *mockRotatableProvider) RotateKey(ctx context.Context) (string, error) {
	m.currentVersion++
	return "v2", nil
}

func (m *mockRotatableProvider) GetKeyVersion(keyID string, version int) ([]byte, error) {
	return m.key, nil
}

func (m *mockRotatableProvider) CurrentKeyVersion() int {
	return m.currentVersion
}

func TestKeyRotator_NewKeyRotator(t *testing.T) {
	provider := &mockRotatableProvider{key: make([]byte, 32)}
	rotator := NewKeyRotator(provider, &AES256GCM{})
	assert.NotNil(t, rotator)
}

func TestKeyRotator_LazyDecrypt_SameKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	provider := &mockRotatableProvider{key: key, currentVersion: 1}
	rotator := NewKeyRotator(provider, &AES256GCM{})

	// Encrypt with the key
	encrypter := &AES256GCM{}
	encrypted, err := encrypter.Encrypt("test data", provider)
	require.NoError(t, err)

	// Decrypt with lazy rotation - should not need rotation
	plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, provider)
	require.NoError(t, err)
	assert.Equal(t, "test data", plaintext)
	assert.False(t, rotated, "should not rotate when using same key")
	assert.Empty(t, newEncrypted, "no re-encryption needed")
}

// multiKeyProvider is a helper for testing key rotation.
type multiKeyProvider struct {
	keys          map[string][]byte
	currentKeyID  string
	currentVersion int
}

func (m *multiKeyProvider) GetKey(keyID string) ([]byte, error) {
	if key, ok := m.keys[keyID]; ok {
		return key, nil
	}
	// Fallback to current key
	return m.keys[m.currentKeyID], nil
}

func (m *multiKeyProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

func (m *multiKeyProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

func (m *multiKeyProvider) KeyID() string {
	return m.currentKeyID
}

func (m *multiKeyProvider) RotateKey(ctx context.Context) (string, error) {
	m.currentVersion++
	return "new-version", nil
}

func (m *multiKeyProvider) GetKeyVersion(keyID string, version int) ([]byte, error) {
	return m.keys[keyID], nil
}

func (m *multiKeyProvider) CurrentKeyVersion() int {
	return m.currentVersion
}

func TestKeyRotator_LazyDecrypt_DifferentKeys(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0xAA}, 32)
	newKey := bytes.Repeat([]byte{0xBB}, 32)

	// Create a simple provider for encryption with old key
	oldProvider := &simpleProvider{key: oldKey, keyID: "old-key"}
	newProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "new-key",
	}

	encrypter := &AES256GCM{}

	// Encrypt with old key
	encrypted, err := encrypter.Encrypt("rotating data", oldProvider)
	require.NoError(t, err)

	rotator := NewKeyRotator(newProvider, encrypter)

	// Decrypt with lazy rotation
	plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, newProvider)
	require.NoError(t, err)
	assert.Equal(t, "rotating data", plaintext)
	assert.True(t, rotated, "should rotate when using different key")
	assert.NotEmpty(t, newEncrypted)

	// Verify new encrypted value can be decrypted with new key
	decryptedAgain, err := encrypter.Decrypt(newEncrypted, newProvider)
	require.NoError(t, err)
	assert.Equal(t, "rotating data", decryptedAgain)
}

// simpleProvider is a minimal provider for testing
type simpleProvider struct {
	key   []byte
	keyID string
}

func (p *simpleProvider) GetKey(keyID string) ([]byte, error)   { return p.key, nil }
func (p *simpleProvider) EncryptKey(key []byte, keyID string) ([]byte, error) { return key, nil }
func (p *simpleProvider) DecryptKey(encryptedKey []byte) ([]byte, error) { return encryptedKey, nil }
func (p *simpleProvider) KeyID() string                            { return p.keyID }

func TestEncryptedRecord(t *testing.T) {
	record := EncryptedRecord{
		ID: "test-id",
		EncryptedFields: map[string]string{
			"private_key": "encrypted-data-1",
			"seed_phrase": "encrypted-data-2",
		},
	}

	assert.Equal(t, "test-id", record.ID)
	assert.Equal(t, 2, len(record.EncryptedFields))
	assert.Equal(t, "encrypted-data-1", record.EncryptedFields["private_key"])
}

func TestKeyVersionInfo(t *testing.T) {
	info := KeyVersionInfo{
		Version:   1,
		Algorithm: "AES-256-GCM",
	}

	assert.Equal(t, 1, info.Version)
	assert.Equal(t, "AES-256-GCM", info.Algorithm)
}

func TestRotatableProviderInterface(t *testing.T) {
	// Verify RotatableProvider is a superset of KeyProvider
	var _ KeyProvider = &mockRotatableProvider{}
	var _ RotatableProvider = &mockRotatableProvider{}
}
