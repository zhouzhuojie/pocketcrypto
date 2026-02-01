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

// mockRecord implements RecordLike for testing
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
	}
}
