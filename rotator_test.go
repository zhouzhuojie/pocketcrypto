package pocketcrypto

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotatableMockKeyProvider implements RotatableProvider for testing
type rotatableMockKeyProvider struct {
	keys           map[string][]byte
	currentKeyID   string
	currentVersion int
}

func (m *rotatableMockKeyProvider) GetKey(keyID string) ([]byte, error) {
	if key, ok := m.keys[keyID]; ok {
		return key, nil
	}
	// Fallback to current key
	return m.keys[m.currentKeyID], nil
}

func (m *rotatableMockKeyProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

func (m *rotatableMockKeyProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

func (m *rotatableMockKeyProvider) KeyID() string {
	return m.currentKeyID
}

func (m *rotatableMockKeyProvider) RotateKey(ctx context.Context) (string, error) {
	m.currentVersion++
	return "new-version", nil
}

func (m *rotatableMockKeyProvider) GetKeyVersion(keyID string, version int) ([]byte, error) {
	return m.keys[keyID], nil
}

func (m *rotatableMockKeyProvider) CurrentKeyVersion() int {
	return m.currentVersion
}

func TestKeyRotator_LazyDecrypt(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	oldProvider := &rotatableMockKeyProvider{keys: map[string][]byte{"old-key": oldKey}, currentKeyID: "old-key"}
	newProvider := &rotatableMockKeyProvider{keys: map[string][]byte{"old-key": oldKey, "new-key": newKey}, currentKeyID: "new-key"}
	encrypter := &AES256GCM{}

	rotator := newKeyRotator(newProvider, encrypter)

	t.Run("same key no rotation", func(t *testing.T) {
		encrypted, err := encrypter.Encrypt("test-data", newProvider)
		require.NoError(t, err)

		plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, newProvider)
		require.NoError(t, err)
		assert.Equal(t, "test-data", plaintext)
		assert.False(t, rotated)
		assert.Empty(t, newEncrypted)
	})

	t.Run("different key triggers rotation", func(t *testing.T) {
		// Encrypt with old key
		encrypted, err := encrypter.Encrypt("rotating-data", oldProvider)
		require.NoError(t, err)

		// Decrypt with new provider (should trigger rotation)
		plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, newProvider)
		require.NoError(t, err)
		assert.Equal(t, "rotating-data", plaintext)
		assert.True(t, rotated)
		assert.NotEmpty(t, newEncrypted)

		// Verify new encrypted data can be decrypted with new key
		decrypted, err := encrypter.Decrypt(newEncrypted, newProvider)
		require.NoError(t, err)
		assert.Equal(t, "rotating-data", decrypted)
	})

	t.Run("unknown key ID returns error", func(t *testing.T) {
		encrypted := mustEncryptWithKeyID("unknown-data", "unknown-key", oldKey)
		_, _, _, err := rotator.LazyDecrypt(encrypted, newProvider)
		assert.Error(t, err)
	})
}

func TestKeyRotator_RotateCollection(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	oldProvider := &rotatableMockKeyProvider{keys: map[string][]byte{"old-key": oldKey}, currentKeyID: "old-key"}
	newProvider := &rotatableMockKeyProvider{keys: map[string][]byte{"old-key": oldKey, "new-key": newKey}, currentKeyID: "new-key"}
	encrypter := &AES256GCM{}

	rotator := newKeyRotator(newProvider, encrypter)

	t.Run("batch rotation", func(t *testing.T) {
		records := make([]EncryptedRecord, 50)
		for i := 0; i < 50; i++ {
			encrypted, err := encrypter.Encrypt("batch-data", oldProvider)
			require.NoError(t, err)
			records[i] = EncryptedRecord{
				ID:              string(rune('A' + i)),
				EncryptedFields: map[string]string{"private_key": encrypted},
			}
		}

		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			10, // batch size
			func(record *EncryptedRecord) error {
				return nil
			},
		)
		require.NoError(t, err)
		assert.Equal(t, 50, migrated)
		assert.Equal(t, 0, skipped)
	})

	t.Run("batch rotation with errors", func(t *testing.T) {
		records := []EncryptedRecord{
			{ID: "A", EncryptedFields: map[string]string{"data": "invalid-encrypted"}},
			{ID: "B", EncryptedFields: map[string]string{"data": ""}},
		}

		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			10,
			func(record *EncryptedRecord) error {
				return nil
			},
		)
		require.NoError(t, err)
		assert.Equal(t, 0, migrated)
		assert.Equal(t, 2, skipped)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		records := make([]EncryptedRecord, 100)
		for i := 0; i < 100; i++ {
			encrypted, _ := encrypter.Encrypt("data", oldProvider)
			records[i] = EncryptedRecord{
				ID:              string(rune('A' + i)),
				EncryptedFields: map[string]string{"data": encrypted},
			}
		}

		// Cancel after a few records
		go func() {
			cancel()
		}()

		_, _, err := rotator.RotateCollection(ctx, records, 100, func(r *EncryptedRecord) error {
			return nil
		})
		assert.Error(t, err)
	})
}

func TestKeyRotator_RotateRecord(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x01}, 32)
	key2 := bytes.Repeat([]byte{0x02}, 32)

	provider1 := &rotatableMockKeyProvider{keys: map[string][]byte{"key1": key1}, currentKeyID: "key1"}
	provider2 := &rotatableMockKeyProvider{keys: map[string][]byte{"key1": key1, "key2": key2}, currentKeyID: "key2"}
	encrypter := &AES256GCM{}

	rotator := newKeyRotator(provider2, encrypter)

	t.Run("rotate single record", func(t *testing.T) {
		encrypted, err := encrypter.Encrypt("data", provider1)
		require.NoError(t, err)

		record := &EncryptedRecord{
			ID:              "test",
			EncryptedFields: map[string]string{"private_key": encrypted},
		}

		updatedRecord, rotated, err := rotator.RotateRecord(record)
		require.NoError(t, err)
		assert.True(t, rotated)
		assert.NotEqual(t, encrypted, updatedRecord.EncryptedFields["private_key"])
	})
}

// Helper function
func mustEncryptWithKeyID(plaintext, keyID string, key []byte) string {
	aes := &AES256GCM{}
	encrypted, _ := aes.encryptWithKey(plaintext, key, keyID)
	return encrypted
}

func TestKeyRotator_EdgeCases(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)
	encrypter := &AES256GCM{}

	newProvider := &rotatableMockKeyProvider{
		keys:         map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID: "new-key",
	}
	rotator := newKeyRotator(newProvider, encrypter)

	t.Run("empty encrypted data returns error", func(t *testing.T) {
		_, _, _, err := rotator.LazyDecrypt("", newProvider)
		assert.Error(t, err) // Empty string is not a valid envelope
	})

	t.Run("already encrypted with current key", func(t *testing.T) {
		encrypted, err := encrypter.Encrypt("fresh-data", newProvider)
		require.NoError(t, err)

		plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, newProvider)
		require.NoError(t, err)
		assert.Equal(t, "fresh-data", plaintext)
		assert.False(t, rotated)
		assert.Empty(t, newEncrypted)
	})

	t.Run("non-encrypted data returns error", func(t *testing.T) {
		_, _, _, err := rotator.LazyDecrypt("this is plain text", newProvider)
		assert.Error(t, err) // Plain text is not a valid envelope
	})

	t.Run("invalid envelope format", func(t *testing.T) {
		invalidData := "not-valid-json"
		_, _, _, err := rotator.LazyDecrypt(invalidData, newProvider)
		assert.Error(t, err)
	})

	t.Run("multiple fields mixed keys", func(t *testing.T) {
		// Encrypt with old key directly
		oldEncrypted := mustEncryptWithKeyID("old-secret", "old-key", oldKey)
		newEncrypted := mustEncryptWithKeyID("new-secret", "new-key", newKey)

		// Create record with both old and new encrypted fields
		record := &EncryptedRecord{
			ID: "mixed",
			EncryptedFields: map[string]string{
				"old_field": oldEncrypted,
				"new_field": newEncrypted,
			},
		}

		rotatedRecord, rotated, err := rotator.RotateRecord(record)
		require.NoError(t, err)
		assert.True(t, rotated)

		// Only old_field should be rotated
		assert.NotEqual(t, oldEncrypted, rotatedRecord.EncryptedFields["old_field"])
		assert.Equal(t, newEncrypted, rotatedRecord.EncryptedFields["new_field"])
	})

	t.Run("all fields already new key", func(t *testing.T) {
		encrypted, _ := encrypter.Encrypt("data", newProvider)
		record := &EncryptedRecord{
			ID:              "all-new",
			EncryptedFields: map[string]string{"field1": encrypted, "field2": encrypted},
		}

		rotatedRecord, rotated, err := rotator.RotateRecord(record)
		require.NoError(t, err)
		assert.False(t, rotated)
		assert.Equal(t, encrypted, rotatedRecord.EncryptedFields["field1"])
		assert.Equal(t, encrypted, rotatedRecord.EncryptedFields["field2"])
	})

	t.Run("provider error on decrypt", func(t *testing.T) {
		// Create a provider that fails on GetKey
		failingProvider := &errorKeyProvider{
			rotatableMockKeyProvider: &rotatableMockKeyProvider{
				keys:         newProvider.keys,
				currentKeyID: newProvider.currentKeyID,
			},
			getKeyError: true,
		}

		oldEncrypted, _ := encrypter.Encrypt("data", newProvider)

		_, _, _, err := rotator.LazyDecrypt(oldEncrypted, failingProvider)
		assert.Error(t, err)
	})

	t.Run("empty fields map", func(t *testing.T) {
		record := &EncryptedRecord{
			ID:              "empty",
			EncryptedFields: map[string]string{},
		}

		rotatedRecord, rotated, err := rotator.RotateRecord(record)
		require.NoError(t, err)
		assert.False(t, rotated)
		assert.Empty(t, rotatedRecord.EncryptedFields)
	})

	t.Run("zero batch size defaults to 100", func(t *testing.T) {
		records := []EncryptedRecord{
			{ID: "1", EncryptedFields: map[string]string{"data": ""}},
		}

		migrated, skipped, err := rotator.RotateCollection(context.Background(), records, 0, func(r *EncryptedRecord) error {
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 0, migrated)
		assert.Equal(t, 1, skipped) // Empty data gets skipped
	})
}

// errorKeyProvider is a mock provider that can simulate errors
type errorKeyProvider struct {
	*rotatableMockKeyProvider
	getKeyError bool
}

func (m *errorKeyProvider) GetKey(keyID string) ([]byte, error) {
	if m.getKeyError {
		return nil, assert.AnError
	}
	return m.rotatableMockKeyProvider.GetKey(keyID)
}
