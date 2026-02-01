package crypto

import (
	"bytes"
	"context"
	"fmt"
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

func TestKeyRotator_RotateCollection(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0xAA}, 32)
	newKey := bytes.Repeat([]byte{0xBB}, 32)

	// Use multiKeyProvider for both old and new to ensure KeyID is set correctly
	oldProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "old-key",
		currentVersion: 1,
	}
	newProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "new-key",
		currentVersion: 2,
	}

	encrypter := &AES256GCM{}

	// Helper to create records with old encryption
	createRecords := func(count int) []EncryptedRecord {
		records := make([]EncryptedRecord, count)
		for i := 0; i < count; i++ {
			encrypted, err := encrypter.Encrypt("batch-data", oldProvider)
			require.NoError(t, err)
			records[i] = EncryptedRecord{
				ID:              string(rune('A' + i)),
				EncryptedFields: map[string]string{"private_key": encrypted},
			}
		}
		return records
	}

	t.Run("full batch rotation", func(t *testing.T) {
		records := createRecords(10)
		rotator := NewKeyRotator(newProvider, encrypter)

		var updated []EncryptedRecord
		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			5, // batch size of 5
			func(record *EncryptedRecord) error {
				updated = append(updated, *record)
				return nil
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 10, migrated)
		assert.Equal(t, 0, skipped)
		assert.Len(t, updated, 10)
	})

	t.Run("default batch size", func(t *testing.T) {
		records := createRecords(10)
		rotator := NewKeyRotator(newProvider, encrypter)

		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			0, // should use default batch size
			func(record *EncryptedRecord) error {
				return nil
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 10, migrated)
		assert.Equal(t, 0, skipped)
	})

	t.Run("batch rotation with partial batches", func(t *testing.T) {
		records := createRecords(7)
		rotator := NewKeyRotator(newProvider, encrypter)

		// 7 records with batch size of 3 should result in 3 batches (3, 3, 1)
		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			3,
			func(record *EncryptedRecord) error {
				return nil
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 7, migrated)
		assert.Equal(t, 0, skipped)
	})
}

func TestKeyRotator_RotateCollection_Errors(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0xAA}, 32)
	newKey := bytes.Repeat([]byte{0xBB}, 32)

	oldProvider := &simpleProvider{key: oldKey, keyID: "old-key"}
	newProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "new-key",
	}

	encrypter := &AES256GCM{}
	rotator := NewKeyRotator(newProvider, encrypter)

	// Create mixed records (some valid, some invalid)
	records := []EncryptedRecord{
		{
			ID: "valid-1",
			EncryptedFields: map[string]string{
				"private_key": mustEncrypt(t, encrypter, "data1", oldProvider),
			},
		},
		{
			ID: "invalid",
			EncryptedFields: map[string]string{
				"private_key": "invalid-encrypted-data",
			},
		},
		{
			ID: "valid-2",
			EncryptedFields: map[string]string{
				"private_key": mustEncrypt(t, encrypter, "data2", oldProvider),
			},
		},
	}

	t.Run("skip invalid records", func(t *testing.T) {
		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			10,
			func(record *EncryptedRecord) error {
				return nil
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 2, migrated)
		assert.Equal(t, 1, skipped)
		_ = migrated // use variable to avoid unused error
		_ = skipped
	})

	t.Run("update function error counts as skip", func(t *testing.T) {
		failProvider := &multiKeyProvider{
			keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
			currentKeyID:  "new-key",
		}
		failRotator := NewKeyRotator(failProvider, encrypter)

		records := []EncryptedRecord{
			{
				ID: "test-1",
				EncryptedFields: map[string]string{
					"private_key": mustEncrypt(t, encrypter, "data", oldProvider),
				},
			},
		}

		migrated, skipped, err := failRotator.RotateCollection(
			context.Background(),
			records,
			10,
			func(record *EncryptedRecord) error {
				return fmt.Errorf("update failed")
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 0, migrated)
		assert.Equal(t, 1, skipped)
		_ = migrated
		_ = skipped
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		failProvider := &multiKeyProvider{
			keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
			currentKeyID:  "new-key",
		}
		failRotator := NewKeyRotator(failProvider, encrypter)

		// Create many records
		manyRecords := make([]EncryptedRecord, 20)
		for i := 0; i < 20; i++ {
			manyRecords[i] = EncryptedRecord{
				ID: string(rune('A' + i)),
				EncryptedFields: map[string]string{
					"private_key": mustEncrypt(t, encrypter, "data", oldProvider),
				},
			}
		}

		// Cancel context after processing a few records
		cancel()

		_, _, err := failRotator.RotateCollection(
			ctx,
			manyRecords,
			5,
			func(record *EncryptedRecord) error {
				return nil
			},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context")
	})
}

func TestKeyRotator_RotateRecord(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0xAA}, 32)
	newKey := bytes.Repeat([]byte{0xBB}, 32)

	oldProvider := &simpleProvider{key: oldKey, keyID: "old-key"}
	newProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "new-key",
	}

	encrypter := &AES256GCM{}
	rotator := NewKeyRotator(newProvider, encrypter)

	t.Run("rotate single record", func(t *testing.T) {
		encrypted, err := encrypter.Encrypt("secret data", oldProvider)
		require.NoError(t, err)

		record := &EncryptedRecord{
			ID:              "test-id",
			EncryptedFields: map[string]string{"private_key": encrypted},
		}

		updated, rotated, err := rotator.RotateRecord(record)
		require.NoError(t, err)
		assert.True(t, rotated)
		assert.NotEmpty(t, updated.EncryptedFields["private_key"])

		// Verify the new encrypted value can be decrypted
		decrypted, err := encrypter.Decrypt(updated.EncryptedFields["private_key"], newProvider)
		require.NoError(t, err)
		assert.Equal(t, "secret data", decrypted)
	})

	t.Run("no rotation needed", func(t *testing.T) {
		encrypted, err := encrypter.Encrypt("secret data", newProvider)
		require.NoError(t, err)

		record := &EncryptedRecord{
			ID:              "test-id",
			EncryptedFields: map[string]string{"private_key": encrypted},
		}

		updated, rotated, err := rotator.RotateRecord(record)
		require.NoError(t, err)
		assert.False(t, rotated)
		assert.Equal(t, encrypted, updated.EncryptedFields["private_key"])
	})
}

func TestKeyRotator_RotateKey(t *testing.T) {
	provider := &mockRotatableProvider{key: make([]byte, 32), currentVersion: 1}
	rotator := NewKeyRotator(provider, &AES256GCM{})

	err := rotator.RotateKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, provider.currentVersion)
}

func TestKeyRotator_StaticProvider(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	provider := &staticProvider{keyID: "static-key", key: key}

	t.Run("GetKey returns stored key", func(t *testing.T) {
		result, err := provider.GetKey("any-key-id")
		require.NoError(t, err)
		assert.Equal(t, key, result)
	})

	t.Run("EncryptKey returns key as-is", func(t *testing.T) {
		result, err := provider.EncryptKey(key, "key-id")
		require.NoError(t, err)
		assert.Equal(t, key, result)
	})

	t.Run("DecryptKey returns encrypted key as-is", func(t *testing.T) {
		encrypted := bytes.Repeat([]byte{0xBB}, 32)
		result, err := provider.DecryptKey(encrypted)
		require.NoError(t, err)
		assert.Equal(t, encrypted, result)
	})

	t.Run("KeyID returns configured keyID", func(t *testing.T) {
		assert.Equal(t, "static-key", provider.KeyID())
	})
}

// Helper function for encryption in tests
func mustEncrypt(t *testing.T, encrypter Encrypter, data string, provider KeyProvider) string {
	encrypted, err := encrypter.Encrypt(data, provider)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}
	return encrypted
}
