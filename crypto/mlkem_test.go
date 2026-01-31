package crypto

import (
	"crypto/mlkem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLKEM768_Algorithm(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	assert.Equal(t, "ML-KEM-768", kem.Algorithm())
	assert.Equal(t, mlkem.SharedKeySize, kem.KeySize())
}

func TestMLKEM768_GenerateKey(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err, "should generate key pair")
	assert.NotNil(t, kem.decapsKey)
	assert.NotNil(t, kem.encapKey)
}

func TestMLKEM768_GenerateKeyFromSeed(t *testing.T) {
	seed := make([]byte, mlkem.SeedSize)
	kem1, err := NewMLKEM768FromSeed(seed)
	require.NoError(t, err)

	// Same seed should produce same key
	kem2, err := NewMLKEM768FromSeed(seed)
	require.NoError(t, err)

	assert.Equal(t, kem1.EncapsulationKeyBytes(), kem2.EncapsulationKeyBytes())
}

func TestMLKEM768_EncryptDecrypt(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	plaintext := "sensitive crypto data"

	encrypted, err := kem.Encrypt(plaintext, nil)
	require.NoError(t, err, "encrypt should not fail")
	assert.NotEmpty(t, encrypted, "encrypted should not be empty")

	decrypted, err := kem.Decrypt(encrypted, nil)
	require.NoError(t, err, "decrypt should not fail")
	assert.Equal(t, plaintext, decrypted, "roundtrip should preserve data")
}

func TestMLKEM768_DifferentKeysCannotDecrypt(t *testing.T) {
	kem1, err := NewMLKEM768()
	require.NoError(t, err)

	kem2, err := NewMLKEM768()
	require.NoError(t, err)

	encrypted, err := kem1.Encrypt("test", nil)
	require.NoError(t, err)

	_, err = kem2.Decrypt(encrypted, nil)
	assert.Error(t, err, "different key should not decrypt")
}

func TestMLKEM768_EncapsulationKeyBytes(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	ekBytes := kem.EncapsulationKeyBytes()
	assert.Len(t, ekBytes, mlkem.EncapsulationKeySize768)
}

func TestMLKEM768_DecapsulationKeyBytes(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	dkBytes := kem.DecapsulationKeyBytes()
	assert.Len(t, dkBytes, mlkem.SeedSize) // 64 bytes
}

func TestMLKEM768_KeySizes(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	assert.Equal(t, mlkem.EncapsulationKeySize768, kem.EncapsulationKeySize())
	assert.Equal(t, mlkem.CiphertextSize768, kem.CiphertextSize())
	assert.Equal(t, mlkem.SharedKeySize, kem.SharedKeySize())
}

func TestMLKEM768_EncryptedEnvelope(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	encrypted, err := kem.Encrypt("test data", nil)
	require.NoError(t, err)

	var envelope DataEnvelope
	err = envelope.Unmarshal(encrypted)
	require.NoError(t, err)

	assert.Equal(t, "ML-KEM-768", envelope.Algorithm)
	assert.NotEmpty(t, envelope.EncryptedKey)
	assert.NotEmpty(t, envelope.Ciphertext)
	assert.Equal(t, 1, envelope.Version)
}

func TestMLKEM768_NoProviderNeeded(t *testing.T) {
	// ML-KEM handles its own key management
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	encrypted, err := kem.Encrypt("test", nil)
	require.NoError(t, err)

	decrypted, err := kem.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, "test", decrypted)
}

func TestMLKEM768_LongPlaintext(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	// Test with large plaintext (simulating a large private key or JSON)
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := kem.Encrypt(string(plaintext), nil)
	require.NoError(t, err)

	decrypted, err := kem.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, string(plaintext), decrypted)
}

func TestMLKEM768_EmptyPlaintext(t *testing.T) {
	kem, err := NewMLKEM768()
	require.NoError(t, err)

	encrypted, err := kem.Encrypt("", nil)
	require.NoError(t, err)

	decrypted, err := kem.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, "", decrypted)
}
