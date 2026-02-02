package pocketcrypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionHooks_EncryptRecord(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &AES256GCM{}

	hooks := newEncryptionHooks(nil, encrypter, provider)
	hooks.AddCollection("wallets", "private_key", "seed_phrase")

	t.Run("encrypts plain text fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "my-secret-key")
		record.Set("seed_phrase", "word1 word2 word3")
		record.Set("name", "test-wallet")

		hooks.encryptRecord(record, []string{"private_key", "seed_phrase"})

		privateKeyValue := record.GetString("private_key")
		assert.NotEmpty(t, privateKeyValue)
		assert.False(t, privateKeyValue == "my-secret-key")

		decrypted, err := encrypter.Decrypt(privateKeyValue, provider)
		require.NoError(t, err)
		assert.Equal(t, "my-secret-key", decrypted)
	})

	t.Run("skips already encrypted fields", func(t *testing.T) {
		record := newMockRecord()

		encrypted, err := encrypter.Encrypt("secret-data", provider)
		require.NoError(t, err)
		record.Set("private_key", encrypted)

		hooks.encryptRecord(record, []string{"private_key"})

		privateKeyValue := record.GetString("private_key")
		decrypted, err := encrypter.Decrypt(privateKeyValue, provider)
		require.NoError(t, err)
		assert.Equal(t, "secret-data", decrypted)
	})

	t.Run("skips empty fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "")

		hooks.encryptRecord(record, []string{"private_key"})

		assert.Equal(t, "", record.GetString("private_key"))
	})
}

func TestEncryptionHooks_DecryptRecord(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &AES256GCM{}

	hooks := newEncryptionHooks(nil, encrypter, provider)
	hooks.AddCollection("wallets", "private_key", "seed_phrase")

	t.Run("decrypts encrypted fields", func(t *testing.T) {
		record := newMockRecord()

		encryptedPrivateKey, err := encrypter.Encrypt("stored-secret-key", provider)
		require.NoError(t, err)
		record.Set("private_key", encryptedPrivateKey)

		hooks.decryptRecord(record, []string{"private_key"})

		privateKeyValue := record.GetString("private_key")
		assert.Equal(t, "stored-secret-key", privateKeyValue)
	})

	t.Run("skips plain text fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "plain-text-not-encrypted")

		hooks.decryptRecord(record, []string{"private_key"})

		assert.Equal(t, "plain-text-not-encrypted", record.GetString("private_key"))
	})

	t.Run("skips empty fields", func(t *testing.T) {
		record := newMockRecord()
		record.Set("private_key", "")

		hooks.decryptRecord(record, []string{"private_key"})

		assert.Equal(t, "", record.GetString("private_key"))
	})
}

func TestEncryptionHooks_AddCollection(t *testing.T) {
	provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
	hooks := newEncryptionHooks(nil, &AES256GCM{}, provider)

	result := hooks.AddCollection("wallets", "private_key", "mnemonic").
		AddCollection("accounts", "api_key", "api_secret").
		AddCollection("secrets", "value")

	assert.Same(t, hooks, result)
}

func TestEncryptionHooks_LazyDecrypt(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	t.Run("decrypts with current key", func(t *testing.T) {
		provider := newTestProvider(newKey, nil)
		encrypter := &AES256GCM{}
		hooks := newEncryptionHooks(nil, encrypter, provider)

		encrypted, err := encrypter.Encrypt("test-data", provider)
		require.NoError(t, err)

		result, err := hooks.lazyDecrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, "test-data", result)
	})

	t.Run("lazy rotates with previous key", func(t *testing.T) {
		provider := newTestProvider(newKey, oldKey)
		encrypter := &AES256GCM{}
		hooks := newEncryptionHooks(nil, encrypter, provider)

		// Encrypt with old key
		oldProvider := newTestProvider(oldKey, nil)
		encrypted, err := encrypter.Encrypt("old-data", oldProvider)
		require.NoError(t, err)

		// Decrypt with provider that has both keys
		result, err := hooks.lazyDecrypt(encrypted)
		require.NoError(t, err)
		assert.NotEqual(t, encrypted, result)

		// Verify the re-encrypted data can be decrypted with new key
		plaintext, err := encrypter.Decrypt(result, provider)
		require.NoError(t, err)
		assert.Equal(t, "old-data", plaintext)
	})

	t.Run("fails when no previous key available", func(t *testing.T) {
		provider := newTestProvider(newKey, nil) // No previous key
		encrypter := &AES256GCM{}
		hooks := newEncryptionHooks(nil, encrypter, provider)

		// Encrypt with a different key that provider doesn't know
		diffKey := bytes.Repeat([]byte{0x03}, 32)
		diffProvider := newTestProvider(diffKey, nil)
		encrypted, err := encrypter.Encrypt("unknown-data", diffProvider)
		require.NoError(t, err)

		_, err = hooks.lazyDecrypt(encrypted)
		assert.Error(t, err)
	})
}

// newTestProvider creates a provider for testing with optional previous key.
func newTestProvider(current, previous []byte) *testProvider {
	return &testProvider{
		currentKey:   current,
		previousKey:  previous,
		currentKeyID: "current",
	}
}

type testProvider struct {
	currentKey   []byte
	previousKey  []byte
	currentKeyID string
}

func (p *testProvider) GetKey(keyID string) ([]byte, error) {
	if keyID == "previous" && p.previousKey != nil {
		return p.previousKey, nil
	}
	return p.currentKey, nil
}

func (p *testProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

func (p *testProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

func (p *testProvider) KeyID() string {
	return p.currentKeyID
}

// mockRecord implements the record interface for testing
type mockRecord struct {
	fields map[string]any
}

func newMockRecord() *mockRecord {
	return &mockRecord{
		fields: make(map[string]any),
	}
}

func (r *mockRecord) GetString(field string) string {
	if v, ok := r.fields[field]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (r *mockRecord) Set(field string, value any) {
	r.fields[field] = value
}
