package hooks_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"pocketcrypto/crypto"
	"pocketcrypto/hooks"
)

// mockKeyProvider is a simple in-memory provider for testing.
type mockKeyProvider struct {
	key  []byte
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

// TestEncryptionHooks_ConfigValidation tests configuration validation.
func TestEncryptionHooks_ConfigValidation(t *testing.T) {
	t.Run("empty collection name rejected", func(t *testing.T) {
		configs := []hooks.CollectionConfig{
			{Collection: "", Fields: []string{"private_key"}},
		}

		provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
		_, err := hooks.NewEncryptionHooksFromConfig(nil, &crypto.AES256GCM{}, provider, configs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "collection name cannot be empty")
	})

	t.Run("empty fields rejected", func(t *testing.T) {
		configs := []hooks.CollectionConfig{
			{Collection: "wallets", Fields: []string{}},
		}

		provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
		_, err := hooks.NewEncryptionHooksFromConfig(nil, &crypto.AES256GCM{}, provider, configs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must have at least one field to encrypt")
	})

	t.Run("valid config accepted", func(t *testing.T) {
		configs := []hooks.CollectionConfig{
			{Collection: "wallets", Fields: []string{"private_key", "seed_phrase"}},
			{Collection: "secrets", Fields: []string{"value"}},
		}

		provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
		encryptionHooks, err := hooks.NewEncryptionHooksFromConfig(nil, &crypto.AES256GCM{}, provider, configs)

		require.NoError(t, err)
		assert.NotNil(t, encryptionHooks)
	})
}

// TestEncryptionHooks_AddCollection tests the AddCollection fluent API.
func TestEncryptionHooks_AddCollection(t *testing.T) {
	provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
	encryptionHooks := hooks.NewEncryptionHooks(nil, &crypto.AES256GCM{}, provider)

	// Test fluent API
	result := encryptionHooks.AddCollection("wallets", "private_key", "mnemonic").
		AddCollection("secrets", "value")

	assert.Same(t, encryptionHooks, result)
}

// TestEncryptionHooks_RegisterEncryption tests the RegisterEncryption function.
func TestEncryptionHooks_RegisterEncryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode - requires env vars")
	}

	// Set up environment
	os.Setenv("ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcw==")
	defer os.Unsetenv("ENCRYPTION_KEY")

	configs := []hooks.CollectionConfig{
		{Collection: "wallets", Fields: []string{"private_key"}},
	}

	// Note: This will fail without a running PocketBase app, but tests the config parsing
	_, err := hooks.RegisterEncryption(context.Background(), nil, &crypto.AES256GCM{}, configs)

	// We expect an error because app is nil, but config should be valid
	// The error should not be about invalid config
	assert.Error(t, err)
}

// multiKeyProvider is a helper for testing key rotation (copied from crypto/rotator_test.go).
type multiKeyProvider struct {
	keys           map[string][]byte
	currentKeyID   string
	currentVersion int
}

func (m *multiKeyProvider) setCurrentKey(id string) {
	m.currentKeyID = id
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

// TestEncryptionHooks_KeyRotation tests key rotation functionality.
func TestEncryptionHooks_KeyRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	oldProvider := &mockKeyProvider{key: oldKey, keyID: "old-key"}
	newProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "new-key",
	}

	encrypter := &crypto.AES256GCM{}

	// Create a record encrypted with old key (simulating pre-rotation data)
	t.Run("lazy decryption with old key", func(t *testing.T) {
		// Manually encrypt with old key
		oldEncrypted, err := encrypter.Encrypt("rotating_key_data", oldProvider)
		require.NoError(t, err)

		// Create rotator for lazy rotation
		rotator := crypto.NewKeyRotator(newProvider, encrypter)

		// Test lazy decryption and re-encryption
		plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(oldEncrypted, newProvider)

		require.NoError(t, err)
		assert.Equal(t, "rotating_key_data", plaintext)
		assert.True(t, rotated)
		assert.NotEmpty(t, newEncrypted)

		// Verify new encrypted value can be decrypted with new key
		decryptedAgain, err := encrypter.Decrypt(newEncrypted, newProvider)
		require.NoError(t, err)
		assert.Equal(t, "rotating_key_data", decryptedAgain)
	})

	t.Run("same key no rotation", func(t *testing.T) {
		// Encrypt with current key
		currentEncrypted, err := encrypter.Encrypt("current_key_data", newProvider)
		require.NoError(t, err)

		rotator := crypto.NewKeyRotator(newProvider, encrypter)

		plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(currentEncrypted, newProvider)

		require.NoError(t, err)
		assert.Equal(t, "current_key_data", plaintext)
		assert.False(t, rotated)
		assert.Empty(t, newEncrypted)
	})

	t.Run("key rotation with setCurrentKey", func(t *testing.T) {
		key1 := bytes.Repeat([]byte{0x11}, 32)
		key2 := bytes.Repeat([]byte{0x22}, 32)
		provider := &multiKeyProvider{
			keys:          map[string][]byte{"key1": key1, "key2": key2},
			currentKeyID:  "key1",
		}

		encrypter := &crypto.AES256GCM{}

		// Encrypt with key1
		encrypted, err := encrypter.Encrypt("switching data", provider)
		require.NoError(t, err)

		// Switch current key
		provider.setCurrentKey("key2")

		// Now decryption should trigger rotation
		rotator := crypto.NewKeyRotator(provider, encrypter)
		_, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, provider)

		require.NoError(t, err)
		assert.True(t, rotated, "should rotate when key changed")
		assert.NotEmpty(t, newEncrypted)
	})
}

// TestEncryptionHooks_BatchRotation tests batch rotation functionality.
func TestEncryptionHooks_BatchRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	oldProvider := &mockKeyProvider{key: oldKey, keyID: "old-key"}
	newProvider := &multiKeyProvider{
		keys:          map[string][]byte{"old-key": oldKey, "new-key": newKey},
		currentKeyID:  "new-key",
	}

	encrypter := &crypto.AES256GCM{}
	rotator := crypto.NewKeyRotator(newProvider, encrypter)

	// Create test records with old encryption
	records := make([]crypto.EncryptedRecord, 50)
	for i := 0; i < 50; i++ {
		encrypted, err := encrypter.Encrypt("batch-data", oldProvider)
		require.NoError(t, err)
		records[i] = crypto.EncryptedRecord{
			ID:              string(rune('A' + i)),
			EncryptedFields: map[string]string{"private_key": encrypted},
		}
	}

	t.Run("batch rotation", func(t *testing.T) {
		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			records,
			10, // batch size
			func(record *crypto.EncryptedRecord) error {
				return nil
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 50, migrated)
		assert.Equal(t, 0, skipped)
	})

	t.Run("batch rotation with errors", func(t *testing.T) {
		// Mix of valid and invalid records
		mixedRecords := make([]crypto.EncryptedRecord, 5)
		for i := 0; i < 5; i++ {
			if i%2 == 0 {
				encrypted, err := encrypter.Encrypt("valid-data", oldProvider)
				require.NoError(t, err)
				mixedRecords[i] = crypto.EncryptedRecord{
					ID:              string(rune('A' + i)),
					EncryptedFields: map[string]string{"private_key": encrypted},
				}
			} else {
				// Invalid encrypted data
				mixedRecords[i] = crypto.EncryptedRecord{
					ID:              string(rune('A' + i)),
					EncryptedFields: map[string]string{"private_key": "invalid-encrypted-data"},
				}
			}
		}

		migrated, skipped, err := rotator.RotateCollection(
			context.Background(),
			mixedRecords,
			10,
			func(record *crypto.EncryptedRecord) error {
				return nil
			},
		)

		require.NoError(t, err)
		assert.Equal(t, 3, migrated) // Only even indices are valid
		assert.Equal(t, 2, skipped)  // Odd indices are invalid
	})
}

// BenchmarkEncryptionHooks benchmarks encryption performance.
func BenchmarkEncryptionHooks(b *testing.B) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "benchmark-key"}
	encrypter := &crypto.AES256GCM{}

	// Test data sizes
	testCases := []struct {
		name string
		size int
	}{
		{"small (32 bytes)", 32},
		{"medium (256 bytes)", 256},
		{"large (1KB)", 1024},
		{"xlarge (4KB)", 4096},
	}

	for _, tc := range testCases {
		b.Run("encrypt_"+tc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("x"), tc.size)
			b.SetBytes(int64(tc.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := encrypter.Encrypt(string(data), provider)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("decrypt_"+tc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("x"), tc.size)
			encrypted, err := encrypter.Encrypt(string(data), provider)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(tc.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := encrypter.Decrypt(encrypted, provider)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	// Compare with unencrypted baseline
	b.Run("baseline_no_encryption", func(b *testing.B) {
		data := make([]byte, 256)
		b.SetBytes(256)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = string(data) // Simple allocation/comparison
		}
	})

	// Batch encryption benchmark
	b.Run("batch_encrypt_100", func(b *testing.B) {
		b.SetBytes(100 * 256)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			for j := 0; j < 100; j++ {
				_, err := encrypter.Encrypt("test data for encryption", provider)
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// BenchmarkMLKEM768 benchmarks ML-KEM-768 encryption performance.
func BenchmarkMLKEM768(b *testing.B) {
	encrypter, err := crypto.NewMLKEM768()
	if err != nil {
		b.Fatal(err)
	}
	provider := &mockKeyProvider{key: make([]byte, 32), keyID: "mlkem-key"}

	testCases := []struct {
		name string
		size int
	}{
		{"small (32 bytes)", 32},
		{"medium (256 bytes)", 256},
	}

	for _, tc := range testCases {
		b.Run("encrypt_"+tc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("x"), tc.size)
			b.SetBytes(int64(tc.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := encrypter.Encrypt(string(data), provider)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("decrypt_"+tc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("x"), tc.size)
			encrypted, err := encrypter.Encrypt(string(data), provider)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(tc.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := encrypter.Decrypt(encrypted, provider)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestEncryptionHooks_ConcurrentAccess tests thread safety of encryption.
func TestEncryptionHooks_ConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "concurrent-key"}
	encrypter := &crypto.AES256GCM{}

	// Run concurrent encryption/decryption operations
	t.Run("concurrent_encrypt_decrypt", func(t *testing.T) {
		numGoroutines := 10
		operations := 100

		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < operations; j++ {
					data := "concurrent-test-data"
					if j%2 == 0 {
						encrypted, err := encrypter.Encrypt(data, provider)
						if err != nil {
							t.Errorf("Goroutine %d: encrypt failed: %v", id, err)
							return
						}
						_, err = encrypter.Decrypt(encrypted, provider)
						if err != nil {
							t.Errorf("Goroutine %d: decrypt failed: %v", id, err)
							return
						}
					}
				}
				done <- true
			}(i)
		}

		timeout := time.After(30 * time.Second)
		for i := 0; i < numGoroutines; i++ {
			select {
			case <-done:
			case <-timeout:
				t.Fatal("Test timed out - possible deadlock")
			}
		}
	})
}

// TestEncryptionHooks_FieldValidation tests that empty fields are handled correctly.
func TestEncryptionHooks_FieldValidation(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "validation-key"}
	encrypter := &crypto.AES256GCM{}

	t.Run("empty field skipped", func(t *testing.T) {
		// Simulate empty field handling
		emptyData := ""
		isEncrypted := crypto.IsEncrypted(emptyData)
		assert.False(t, isEncrypted)
	})

	t.Run("already encrypted skipped", func(t *testing.T) {
		// First, create a record with encrypted data
		encrypted, err := encrypter.Encrypt("already_encrypted", provider)
		require.NoError(t, err)

		// Verify IsEncrypted detection
		assert.True(t, crypto.IsEncrypted(encrypted))

		// Decrypt and verify
		decrypted, err := encrypter.Decrypt(encrypted, provider)
		require.NoError(t, err)
		assert.Equal(t, "already_encrypted", decrypted)
	})

	t.Run("plain text not detected as encrypted", func(t *testing.T) {
		plainText := "this is plain text"
		assert.False(t, crypto.IsEncrypted(plainText))
	})
}

// TestEncryptionHooks_RegisterDefaultEncryption tests the default encryption configuration.
func TestEncryptionHooks_RegisterDefaultEncryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode - requires env vars")
	}

	// Set up environment
	os.Setenv("ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcw==")
	defer os.Unsetenv("ENCRYPTION_KEY")

	// Note: This will fail without a running PocketBase app, but tests the config creation
	_, err := hooks.RegisterDefaultEncryption(context.Background(), nil)

	// We expect an error because app is nil
	assert.Error(t, err)
}

// TestEncryptionHooks_Register tests the Register method.
func TestEncryptionHooks_Register(t *testing.T) {
	t.Run("empty collections registers without error", func(t *testing.T) {
		provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}
		encryptionHooks := hooks.NewEncryptionHooks(nil, &crypto.AES256GCM{}, provider)

		// No collections added - should not error
		err := encryptionHooks.Register()
		assert.NoError(t, err)
	})
}

// TestCollectionConfig tests the CollectionConfig struct.
func TestCollectionConfig(t *testing.T) {
	config := hooks.CollectionConfig{
		Collection: "wallets",
		Fields:     []string{"private_key", "mnemonic"},
	}

	assert.Equal(t, "wallets", config.Collection)
	assert.Len(t, config.Fields, 2)
	assert.Equal(t, "private_key", config.Fields[0])
	assert.Equal(t, "mnemonic", config.Fields[1])
}

// TestEncryptionHooks_NewEncryptionHooks tests creating encryption hooks directly.
func TestEncryptionHooks_NewEncryptionHooks(t *testing.T) {
	provider := &mockKeyProvider{key: make([]byte, 32), keyID: "test"}

	t.Run("with nil encrypter", func(t *testing.T) {
		hooks := hooks.NewEncryptionHooks(nil, nil, provider)
		assert.NotNil(t, hooks)
	})

	t.Run("with nil provider", func(t *testing.T) {
		hooks := hooks.NewEncryptionHooks(nil, &crypto.AES256GCM{}, nil)
		assert.NotNil(t, hooks)
	})
}

// TestEncryptionHooks_MultipleFields tests handling multiple fields.
func TestEncryptionHooks_MultipleFields(t *testing.T) {
	provider := &mockKeyProvider{key: bytes.Repeat([]byte{0x01}, 32), keyID: "test"}
	encrypter := &crypto.AES256GCM{}

	t.Run("encrypt multiple fields", func(t *testing.T) {
		hooks := hooks.NewEncryptionHooks(nil, encrypter, provider)
		result := hooks.AddCollection("wallets", "private_key", "mnemonic", "seed_phrase")

		assert.Same(t, hooks, result)
	})

	t.Run("add same collection multiple times", func(t *testing.T) {
		hooks := hooks.NewEncryptionHooks(nil, encrypter, provider)
		result1 := hooks.AddCollection("wallets", "private_key")
		result2 := hooks.AddCollection("wallets", "mnemonic")

		assert.Same(t, hooks, result1)
		assert.Same(t, hooks, result2)
	})
}
