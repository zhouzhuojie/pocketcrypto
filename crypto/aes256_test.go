package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider is a mock KeyProvider for testing.
type mockProvider struct {
	key []byte
}

func (m *mockProvider) GetKey(keyID string) ([]byte, error)   { return m.key, nil }
func (m *mockProvider) EncryptKey(key []byte, keyID string) ([]byte, error) { return key, nil }
func (m *mockProvider) DecryptKey(encryptedKey []byte) ([]byte, error) { return encryptedKey, nil }
func (m *mockProvider) KeyID() string { return "test-mock" }

func TestAES256_Algorithm(t *testing.T) {
	encrypter := &AES256GCM{}
	assert.Equal(t, "AES-256-GCM", encrypter.Algorithm())
	assert.Equal(t, 32, encrypter.KeySize())
}

func TestAES256_EncryptDecrypt(t *testing.T) {
	provider := &mockProvider{key: make([]byte, 32)}
	encrypter := &AES256GCM{}

	tests := []struct {
		name    string
		input   string
	}{
		{"empty string", ""},
		{"short text", "hello"},
		{"long text", "This is a longer piece of text that spans multiple sentences and contains various characters including special ones like !@#$%^&*()"},
		{"unicode", "こんにちは世界 🔐 Привет мир 🌍"},
		{"json", `{"private_key": "abc123", "encrypted": true}`},
		{"base64", base64.StdEncoding.EncodeToString([]byte("test data"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := encrypter.Encrypt(tt.input, provider)
			require.NoError(t, err, "encrypt should not fail")
			assert.NotEmpty(t, encrypted, "encrypted should not be empty")

			decrypted, err := encrypter.Decrypt(encrypted, provider)
			require.NoError(t, err, "decrypt should not fail")
			assert.Equal(t, tt.input, decrypted, "decrypted should match original")
		})
	}
}

func TestAES256_EncryptWithKey(t *testing.T) {
	encrypter := &AES256GCM{}
	key := make([]byte, 32)

	encrypted, err := encrypter.EncryptWithKey("test data", key)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := encrypter.DecryptWithKey(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, "test data", decrypted)
}

func TestAES256_InvalidKeySize(t *testing.T) {
	encrypter := &AES256GCM{}

	_, err := encrypter.EncryptWithKey("test", make([]byte, 16))
	assert.Error(t, err, "expected error with invalid key size")

	_, err = encrypter.EncryptWithKey("test", make([]byte, 48))
	assert.Error(t, err, "expected error with invalid key size")
}

func TestAES256_TamperedCiphertext(t *testing.T) {
	provider := &mockProvider{key: make([]byte, 32)}
	encrypter := &AES256GCM{}

	encrypted, err := encrypter.Encrypt("test", provider)
	require.NoError(t, err)

	// Tamper with the ciphertext
	var envelope DataEnvelope
	err = envelope.Unmarshal(encrypted)
	require.NoError(t, err)
	data, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	require.NoError(t, err)
	data[0] ^= 0xFF
	envelope.Ciphertext = base64.StdEncoding.EncodeToString(data)

	_, err = encrypter.Decrypt(envelope.Marshal(), provider)
	assert.Error(t, err, "expected error when ciphertext is tampered")
}

func TestAES256_DifferentKeys(t *testing.T) {
	encrypter := &AES256GCM{}
	provider1 := &mockProvider{key: bytes.Repeat([]byte{0x01}, 32)}
	provider2 := &mockProvider{key: bytes.Repeat([]byte{0x02}, 32)}

	encrypted, err := encrypter.Encrypt("test", provider1)
	require.NoError(t, err)

	_, err = encrypter.Decrypt(encrypted, provider2)
	assert.Error(t, err, "expected error when using different key")
}

func TestAES256_NilProvider(t *testing.T) {
	encrypter := &AES256GCM{}

	_, err := encrypter.Encrypt("test", nil)
	assert.Error(t, err, "expected error with nil provider")

	_, err = encrypter.Decrypt("encrypted", nil)
	assert.Error(t, err, "expected error with nil provider")
}

func TestAES256_MultipleEncryptions(t *testing.T) {
	provider := &mockProvider{key: make([]byte, 32)}
	encrypter := &AES256GCM{}

	// Each encryption should produce different ciphertext (due to random nonce)
	ciphertexts := make(map[string]int)
	for i := 0; i < 100; i++ {
		encrypted, err := encrypter.Encrypt("same input", provider)
		require.NoError(t, err)
		ciphertexts[encrypted]++
	}

	// All ciphertexts should be unique
	assert.Equal(t, 100, len(ciphertexts), "all encryptions should produce unique ciphertexts")
}
