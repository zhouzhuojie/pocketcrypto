package pocketcrypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAES256GCM_EncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &AES256GCM{}

	t.Run("encrypt and decrypt basic data", func(t *testing.T) {
		plaintext := "my-secret-data"

		encrypted, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, err := encrypter.Decrypt(encrypted, provider)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt with different nonces produces different ciphertext", func(t *testing.T) {
		plaintext := "test-data"

		encrypted1, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		encrypted2, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		// Different nonces should produce different ciphertexts
		assert.NotEqual(t, encrypted1, encrypted2)

		// But both should decrypt to the same plaintext
		decrypted1, _ := encrypter.Decrypt(encrypted1, provider)
		decrypted2, _ := encrypter.Decrypt(encrypted2, provider)
		assert.Equal(t, decrypted1, decrypted2)
	})

	t.Run("decrypt with wrong key fails", func(t *testing.T) {
		plaintext := "test-data"

		encrypted, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		wrongKeyProvider := &mockKeyProvider{key: bytes.Repeat([]byte{0x02}, 32), keyID: "wrong-key"}
		_, err = encrypter.Decrypt(encrypted, wrongKeyProvider)
		assert.Error(t, err)
	})

	t.Run("encrypt with nil provider fails", func(t *testing.T) {
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
	})

	t.Run("decrypt with nil provider fails", func(t *testing.T) {
		_, err := encrypter.Decrypt("invalid", nil)
		assert.Error(t, err)
	})
}

func TestAES256GCM_EncryptWithKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	encrypter := &AES256GCM{}

	t.Run("encrypt and decrypt with key", func(t *testing.T) {
		plaintext := "secret-data"

		encrypted, err := encrypter.EncryptWithKey(plaintext, key)
		require.NoError(t, err)

		decrypted, err := encrypter.DecryptWithKey(encrypted, key)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt with wrong key size fails", func(t *testing.T) {
		_, err := encrypter.EncryptWithKey("test", []byte{0x01})
		assert.Error(t, err)
	})

	t.Run("decrypt with wrong key size fails", func(t *testing.T) {
		_, err := encrypter.DecryptWithKey("invalid", []byte{0x01})
		assert.Error(t, err)
	})
}

func TestAES256GCM_AlgorithmInfo(t *testing.T) {
	encrypter := &AES256GCM{}

	assert.Equal(t, "AES-256-GCM", encrypter.Algorithm())
	assert.Equal(t, 32, encrypter.KeySize())
}

// mockKeyProvider for testing
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

func BenchmarkAES256GCM(b *testing.B) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "benchmark-key"}
	encrypter := &AES256GCM{}

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
			_ = string(data)
		}
	})
}

func TestMLKEM768_AlgorithmInfo(t *testing.T) {
	encrypter := &MLKEM768{}

	assert.Equal(t, "ML-KEM-768", encrypter.Algorithm())
	assert.Equal(t, 32, encrypter.KeySize())
}

func TestMLKEM768_EncapsulationKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &MLKEM768{}

	t.Run("nil before initialization", func(t *testing.T) {
		assert.Nil(t, encrypter.EncapsulationKey())
	})

	t.Run("returns bytes after encrypt", func(t *testing.T) {
		_, err := encrypter.Encrypt("test-data", provider)
		require.NoError(t, err)

		encapKey := encrypter.EncapsulationKey()
		assert.NotNil(t, encapKey)
		assert.Greater(t, len(encapKey), 1000) // ML-KEM-768 encapsulation key is ~1184 bytes
	})
}

func TestMLKEM768_SecretKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &MLKEM768{}

	t.Run("nil before initialization", func(t *testing.T) {
		assert.Nil(t, encrypter.SecretKey())
	})

	t.Run("returns bytes after encrypt", func(t *testing.T) {
		_, err := encrypter.Encrypt("test-data", provider)
		require.NoError(t, err)

		secretKey := encrypter.SecretKey()
		assert.NotNil(t, secretKey)
		assert.True(t, len(secretKey) >= 32) // At least 32 bytes (cached key + ML-KEM internal)
	})
}

func TestMLKEM768_EncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &MLKEM768{}

	t.Run("encrypt and decrypt basic data", func(t *testing.T) {
		plaintext := "my-secret-data"

		encrypted, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, err := encrypter.Decrypt(encrypted, provider)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt with different nonces produces different ciphertext", func(t *testing.T) {
		plaintext := "test-data"

		encrypted1, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		encrypted2, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		// Different encapsulations should produce different ciphertexts
		assert.NotEqual(t, encrypted1, encrypted2)

		// But both should decrypt to the same plaintext
		decrypted1, _ := encrypter.Decrypt(encrypted1, provider)
		decrypted2, _ := encrypter.Decrypt(encrypted2, provider)
		assert.Equal(t, decrypted1, decrypted2)
	})

	t.Run("encrypt with nil provider fails", func(t *testing.T) {
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key provider is required")
	})

	t.Run("decrypt with nil provider fails", func(t *testing.T) {
		_, err := encrypter.Decrypt("invalid", nil)
		assert.Error(t, err)
	})

	t.Run("decrypt with wrong key fails", func(t *testing.T) {
		plaintext := "test-data"

		encrypted, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		wrongKeyProvider := &mockKeyProvider{key: bytes.Repeat([]byte{0x02}, 32), keyID: "wrong-key"}
		_, err = encrypter.Decrypt(encrypted, wrongKeyProvider)
		assert.Error(t, err)
	})

	t.Run("decrypt invalid data fails", func(t *testing.T) {
		_, err := encrypter.Decrypt("invalid-encrypted-data", provider)
		assert.Error(t, err)
	})

	t.Run("key caching works", func(t *testing.T) {
		// First call should initialize
		_, err := encrypter.Encrypt("data1", provider)
		require.NoError(t, err)

		encapKey1 := encrypter.EncapsulationKey()

		// Second call should use cached key
		_, err = encrypter.Encrypt("data2", provider)
		require.NoError(t, err)

		encapKey2 := encrypter.EncapsulationKey()
		assert.Equal(t, encapKey1, encapKey2)
	})
}

func TestMLKEM768_KeyCaching(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &MLKEM768{}

	// Initialize by doing an encrypt
	_, err := encrypter.Encrypt("test-data", provider)
	require.NoError(t, err)

	t.Run("different key triggers re-initialization", func(t *testing.T) {
		differentKey := bytes.Repeat([]byte{0x02}, 32)
		diffProvider := &mockKeyProvider{key: differentKey, keyID: "different-key"}

		// Encrypt with different key
		_, err := encrypter.Encrypt("data", diffProvider)
		require.NoError(t, err)

		encapKey := encrypter.EncapsulationKey()
		assert.NotNil(t, encapKey)
	})

	t.Run("wrong key size fails", func(t *testing.T) {
		wrongKeyProvider := &mockKeyProvider{key: bytes.Repeat([]byte{0x01}, 16), keyID: "wrong-size"}
		_, err := encrypter.Encrypt("test", wrongKeyProvider)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})
}

func TestMLKEM768_Decrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "test-key"}
	encrypter := &MLKEM768{}

	t.Run("decrypt with different key ID", func(t *testing.T) {
		// Encrypt with one provider
		plaintext := "secret-data"
		encrypted, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		// Decrypt with same key but different provider
		diffProvider := &mockKeyProvider{key: key, keyID: "different-key"}
		decrypted, err := encrypter.Decrypt(encrypted, diffProvider)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("decrypt invalid ciphertext fails", func(t *testing.T) {
		// Create an invalid envelope
		invalidData := `{"alg":"ML-KEM-768","kid":"test","ek":"not-base64!!!","ct":"{}","v":1}`
		_, err := encrypter.Decrypt(invalidData, provider)
		assert.Error(t, err)
	})

	t.Run("round trip preserves data", func(t *testing.T) {
		testCases := []string{
			"",
			"short",
			"This is a longer test string with special chars: !@#$%^&*()",
			"Unicode: 你好世界 🌍",
			"Line\nbreaks\r\nand\ttabs",
		}

		for _, plaintext := range testCases {
			encrypted, err := encrypter.Encrypt(plaintext, provider)
			require.NoError(t, err, "encrypt failed for: %s", plaintext)

			decrypted, err := encrypter.Decrypt(encrypted, provider)
			require.NoError(t, err, "decrypt failed for: %s", plaintext)
			assert.Equal(t, plaintext, decrypted, "round trip failed for: %s", plaintext)
		}
	})
}
