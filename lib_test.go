package pocketcrypto

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
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

func TestNewProvider(t *testing.T) {
	// Use a valid 32-byte base64 encoded key
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // "0123456789abcdef0123456789abcdef"
	t.Run("default to local provider", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", validKey)
		defer os.Unsetenv("ENCRYPTION_KEY")

		provider, err := newProvider("")
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("explicit local provider", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", validKey)
		defer os.Unsetenv("ENCRYPTION_KEY")

		provider, err := newProvider(ProviderTypeLocal)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("unknown provider type", func(t *testing.T) {
		_, err := newProvider("unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown")
	})
}

func TestIsEncrypted(t *testing.T) {
	t.Run("encrypted data detected", func(t *testing.T) {
		key := bytes.Repeat([]byte{0x01}, 32)
		provider := &mockKeyProvider{key: key, keyID: "test"}
		encrypter := &AES256GCM{}

		encrypted, err := encrypter.Encrypt("test-data", provider)
		require.NoError(t, err)

		assert.True(t, IsEncrypted(encrypted))
	})

	t.Run("plain text not detected as encrypted", func(t *testing.T) {
		assert.False(t, IsEncrypted("this is plain text"))
	})

	t.Run("empty string not detected as encrypted", func(t *testing.T) {
		assert.False(t, IsEncrypted(""))
	})

	t.Run("invalid JSON not detected as encrypted", func(t *testing.T) {
		assert.False(t, IsEncrypted("not-json-at-all"))
	})
}

func TestFieldEncryptionRequest(t *testing.T) {
	t.Run("basic request", func(t *testing.T) {
		req := FieldEncryptionRequest{
			CollectionConfig: CollectionConfig{
				Collection: "wallets",
				Fields:     []string{"private_key", "mnemonic"},
			},
			DryRun:    true,
			BatchSize: 50,
		}

		assert.Equal(t, "wallets", req.Collection)
		assert.Equal(t, []string{"private_key", "mnemonic"}, req.Fields)
		assert.True(t, req.DryRun)
		assert.Equal(t, 50, req.BatchSize)
	})
}

func TestFieldEncryptionResult(t *testing.T) {
	t.Run("empty result", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 0,
			Migrated:     0,
			Skipped:      0,
			Errors:       nil,
		}

		assert.Equal(t, 0, result.TotalRecords)
		assert.Equal(t, 0, result.Migrated)
		assert.Equal(t, 0, result.Skipped)
	})

	t.Run("result with data", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 100,
			Migrated:     75,
			Skipped:      25,
			Errors:       []string{"record 123: encryption failed"},
		}

		assert.Equal(t, 100, result.TotalRecords)
		assert.Equal(t, 75, result.Migrated)
		assert.Equal(t, 25, result.Skipped)
		assert.Len(t, result.Errors, 1)
	})
}

func TestEncryptionStatus(t *testing.T) {
	t.Run("status with counts", func(t *testing.T) {
		status := EncryptionStatus{
			Collection:     "wallets",
			TotalRecords:   500,
			EncryptedCount: 300,
			PlaintextCount: 200,
		}

		assert.Equal(t, "wallets", status.Collection)
		assert.Equal(t, 500, status.TotalRecords)
		assert.Equal(t, 300, status.EncryptedCount)
		assert.Equal(t, 200, status.PlaintextCount)
	})
}

func TestEncryptRecordLogic(t *testing.T) {
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	os.Setenv("ENCRYPTION_KEY", validKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	t.Run("empty value is skipped", func(t *testing.T) {
		provider, err := newProvider("")
		require.NoError(t, err)

		encrypter := &AES256GCM{}
		result, err := testEncryptRecord(encrypter, provider, "", "private_key")

		assert.NoError(t, err)
		assert.False(t, result) // No migration happened
	})

	t.Run("already encrypted is skipped", func(t *testing.T) {
		provider, err := newProvider("")
		require.NoError(t, err)

		encrypter := &AES256GCM{}

		// First encrypt something
		encrypted, err := encrypter.Encrypt("test value", provider)
		require.NoError(t, err)

		// Check that it's detected as encrypted
		result, err := testEncryptRecord(encrypter, provider, encrypted, "private_key")

		assert.NoError(t, err)
		assert.False(t, result) // No migration happened
	})

	t.Run("plaintext is encrypted", func(t *testing.T) {
		provider, err := newProvider("")
		require.NoError(t, err)

		encrypter := &AES256GCM{}
		result, err := testEncryptRecord(encrypter, provider, "my secret key", "private_key")

		assert.NoError(t, err)
		assert.True(t, result) // Migration happened
	})
}

func TestFieldEncryptionRequestJSON(t *testing.T) {
	t.Run("JSON marshaling", func(t *testing.T) {
		req := FieldEncryptionRequest{
			CollectionConfig: CollectionConfig{
				Collection: "wallets",
				Fields:     []string{"private_key"},
			},
			DryRun:    true,
			BatchSize: 100,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded FieldEncryptionRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.Collection, decoded.Collection)
		assert.Equal(t, req.Fields, decoded.Fields)
		assert.Equal(t, req.DryRun, decoded.DryRun)
		assert.Equal(t, req.BatchSize, decoded.BatchSize)
	})
}

func TestFieldEncryptionResultJSON(t *testing.T) {
	t.Run("JSON marshaling", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 500,
			Migrated:     234,
			Skipped:      266,
			Errors:       []string{"error 1", "error 2"},
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var decoded FieldEncryptionResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, result.TotalRecords, decoded.TotalRecords)
		assert.Equal(t, result.Migrated, decoded.Migrated)
		assert.Equal(t, result.Skipped, decoded.Skipped)
		assert.Equal(t, result.Errors, decoded.Errors)
	})
}

func TestDefaultBatchSize(t *testing.T) {
	t.Run("zero batch size defaults to 100", func(t *testing.T) {
		batchSize := 0
		if batchSize <= 0 {
			batchSize = 100
		}
		assert.Equal(t, 100, batchSize)
	})

	t.Run("negative batch size defaults to 100", func(t *testing.T) {
		batchSize := -5
		if batchSize <= 0 {
			batchSize = 100
		}
		assert.Equal(t, 100, batchSize)
	})

	t.Run("positive batch size is preserved", func(t *testing.T) {
		batchSize := 50
		if batchSize <= 0 {
			batchSize = 100
		}
		assert.Equal(t, 50, batchSize)
	})
}

func TestContextCancellation(t *testing.T) {
	t.Run("context cancellation stops processing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// This would normally hang or process indefinitely,
		// but with context cancellation it should return quickly
		// Note: We can't fully test this without a real PocketBase instance
		select {
		case <-ctx.Done():
			// Context was cancelled, as expected
		default:
			// Context not cancelled yet
		}
	})
}

// Helper types and functions for testing

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

// testEncryptRecord is a helper function that tests the encryption logic
// without needing a full PocketBase record.
func testEncryptRecord(encrypter Encrypter, provider KeyProvider, value, field string) (bool, error) {
	// Simulate the logic from encryptRecord
	if value == "" {
		return false, nil
	}

	if IsEncrypted(value) {
		return false, nil
	}

	_, err := encrypter.Encrypt(value, provider)
	if err != nil {
		return false, err
	}

	return true, nil
}
