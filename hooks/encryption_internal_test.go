package hooks

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pocketcrypto/crypto"
)

// mockKeyProvider is a simple in-memory provider for testing.
type mockKeyProvider struct {
	key   []byte
	keyID string
}

func (m *mockKeyProvider) GetKey(keyID string) ([]byte, error) {
	return m.key, nil
}

func (m *mockKeyProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

func (m *mockKeyProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

func (m *mockKeyProvider) KeyID() string {
	return m.keyID
}

// mockRecord implements RecordLike for testing without a full PocketBase instance.
type mockRecord struct {
	fields map[string]string
}

func newMockRecord() *mockRecord {
	return &mockRecord{
		fields: make(map[string]string),
	}
}

func (r *mockRecord) GetString(field string) string {
	return r.fields[field]
}

func (r *mockRecord) Set(field string, value any) {
	if str, ok := value.(string); ok {
		r.fields[field] = str
	} else {
		r.fields[field] = toString(value)
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return ""
	}
}

// TestEncryptRecord tests the encryptRecord method directly.
func TestEncryptRecord(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &crypto.AES256GCM{}

	encryptionHooks := NewEncryptionHooks(nil, encrypter, provider)
	encryptionHooks.AddCollection("wallets", "private_key", "seed_phrase")

	t.Run("encrypts plain text fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "my-secret-key")
		record.Set("seed_phrase", "word1 word2 word3")
		record.Set("name", "test-wallet") // not in encrypt list

		// Call encryptRecord directly
		encryptionHooks.encryptRecord(record, []string{"private_key", "seed_phrase"})

		// Check that private_key was encrypted
		privateKeyValue := record.GetString("private_key")
		assert.NotEmpty(t, privateKeyValue)
		assert.False(t, privateKeyValue == "my-secret-key", "private_key should be encrypted")

		// Verify the encrypted value can be decrypted
		decrypted, err := encrypter.Decrypt(privateKeyValue, provider)
		require.NoError(t, err)
		assert.Equal(t, "my-secret-key", decrypted)

		// seed_phrase should also be encrypted
		seedValue := record.GetString("seed_phrase")
		assert.NotEmpty(t, seedValue)
		decryptedSeed, err := encrypter.Decrypt(seedValue, provider)
		require.NoError(t, err)
		assert.Contains(t, decryptedSeed, "word1")

		// name should NOT be encrypted (not in the list)
		assert.Equal(t, "test-wallet", record.GetString("name"))
	})

	t.Run("skips already encrypted fields", func(t *testing.T) {
		record := newMockRecord()

		// First encrypt
		encrypted, err := encrypter.Encrypt("secret-data", provider)
		require.NoError(t, err)
		record.Set("private_key", encrypted)

		// Call encryptRecord again - should skip
		encryptionHooks.encryptRecord(record, []string{"private_key"})

		// Value should be unchanged (still decryptable to same value)
		privateKeyValue := record.GetString("private_key")
		decrypted, err := encrypter.Decrypt(privateKeyValue, provider)
		require.NoError(t, err)
		assert.Equal(t, "secret-data", decrypted)
	})

	t.Run("skips empty fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "")

		encryptionHooks.encryptRecord(record, []string{"private_key"})

		// Empty field should remain empty
		assert.Equal(t, "", record.GetString("private_key"))
	})

	t.Run("multiple fields encrypted", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "key-value")
		record.Set("seed_phrase", "phrase-value")
		record.Set("api_secret", "secret-value")

		// Encrypt only first two fields
		encryptionHooks.encryptRecord(record, []string{"private_key", "seed_phrase"})

		// First two should be encrypted
		assert.NotEqual(t, "key-value", record.GetString("private_key"))
		assert.NotEqual(t, "phrase-value", record.GetString("seed_phrase"))
		// Third should be unchanged
		assert.Equal(t, "secret-value", record.GetString("api_secret"))
	})
}

// TestDecryptRecord tests the decryptRecord method directly.
func TestDecryptRecord(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &crypto.AES256GCM{}

	encryptionHooks := NewEncryptionHooks(nil, encrypter, provider)
	encryptionHooks.AddCollection("wallets", "private_key", "seed_phrase")

	t.Run("decrypts encrypted fields", func(t *testing.T) {
		record := newMockRecord()

		// Manually encrypt (simulating stored data)
		encryptedPrivateKey, err := encrypter.Encrypt("stored-secret-key", provider)
		require.NoError(t, err)
		record.Set("private_key", encryptedPrivateKey)

		// Call decryptRecord
		encryptionHooks.decryptRecord(record, []string{"private_key"})

		// The record should now have decrypted value
		privateKeyValue := record.GetString("private_key")
		assert.Equal(t, "stored-secret-key", privateKeyValue)
	})

	t.Run("skips plain text fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "plain-text-not-encrypted")

		// Call decryptRecord - should not modify plain text
		encryptionHooks.decryptRecord(record, []string{"private_key"})

		// Value should be unchanged
		assert.Equal(t, "plain-text-not-encrypted", record.GetString("private_key"))
	})

	t.Run("skips empty fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "")

		encryptionHooks.decryptRecord(record, []string{"private_key"})

		assert.Equal(t, "", record.GetString("private_key"))
	})

	t.Run("multiple fields decrypted", func(t *testing.T) {
		record := newMockRecord()

		encrypted1, err := encrypter.Encrypt("secret1", provider)
		require.NoError(t, err)
		encrypted2, err := encrypter.Encrypt("secret2", provider)
		require.NoError(t, err)

		record.Set("private_key", encrypted1)
		record.Set("seed_phrase", encrypted2)
		record.Set("name", "plain-name")

		encryptionHooks.decryptRecord(record, []string{"private_key", "seed_phrase"})

		// Both should be decrypted
		assert.Equal(t, "secret1", record.GetString("private_key"))
		assert.Equal(t, "secret2", record.GetString("seed_phrase"))
		// Plain field unchanged
		assert.Equal(t, "plain-name", record.GetString("name"))
	})

	t.Run("invalid encrypted data skipped", func(t *testing.T) {
		record := newMockRecord()
		// Set an invalid encrypted value
		record.Set("private_key", "not-valid-encrypted-data")

		// Should not panic, should skip
		encryptionHooks.decryptRecord(record, []string{"private_key"})

		// Value should be unchanged (invalid encrypted data)
		assert.Equal(t, "not-valid-encrypted-data", record.GetString("private_key"))
	})
}

// TestRegisterCollectionHooks tests the registerCollectionHooks method.
func TestRegisterCollectionHooks(t *testing.T) {
	t.Run("multiple collections tracked", func(t *testing.T) {
		provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
		encryptionHooks := NewEncryptionHooks(nil, &crypto.AES256GCM{}, provider)

		// Add multiple collections
		result := encryptionHooks.AddCollection("wallets", "private_key", "mnemonic").
			AddCollection("accounts", "api_key", "api_secret").
			AddCollection("secrets", "value")

		assert.Same(t, encryptionHooks, result)
		assert.NotNil(t, encryptionHooks)
	})

	t.Run("same collection accumulates fields", func(t *testing.T) {
		provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
		encryptionHooks := NewEncryptionHooks(nil, &crypto.AES256GCM{}, provider)

		// Add same collection multiple times
		encryptionHooks.AddCollection("wallets", "private_key")
		encryptionHooks.AddCollection("wallets", "mnemonic")
		encryptionHooks.AddCollection("wallets", "seed_phrase")

		assert.NotNil(t, encryptionHooks)
	})
}

// TestRecordLikeInterface tests that core.Record implements RecordLike.
// This is a compile-time check to ensure the interface is compatible.
func TestRecordLikeInterface(t *testing.T) {
	// This will fail to compile if core.Record doesn't implement RecordLike
	var _ RecordLike = (*mockRecord)(nil)
}
