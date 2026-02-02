package pocketcrypto

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLKEM768_EncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "mlkem-test"}
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

	t.Run("same plaintext produces different ciphertext", func(t *testing.T) {
		plaintext := "test-data"

		encrypted1, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		encrypted2, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		// ML-KEM produces different keys per encryption
		assert.NotEqual(t, encrypted1, encrypted2)
	})

	t.Run("encrypted data can be decrypted multiple times", func(t *testing.T) {
		plaintext := "consistent-data"

		encrypted, err := encrypter.Encrypt(plaintext, provider)
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			decrypted, err := encrypter.Decrypt(encrypted, provider)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		}
	})

	t.Run("fails without provider", func(t *testing.T) {
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key provider is required")
	})

	t.Run("fails with wrong key size", func(t *testing.T) {
		wrongKeyProvider := &mockKeyProvider{key: bytes.Repeat([]byte{0x01}, 16), keyID: "wrong"}
		_, err := encrypter.Encrypt("test", wrongKeyProvider)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})
}

func TestMLKEM768_KeyFromProvider(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	provider := &mockKeyProvider{key: key, keyID: "mlkem-key"}
	encrypter := &MLKEM768{}

	_, err := encrypter.Encrypt("test", provider)
	require.NoError(t, err)

	// Verify key is generated from provider key
	assert.NotNil(t, encrypter.EncapsulationKey())
	assert.NotNil(t, encrypter.SecretKey())
	assert.Equal(t, mlkem.EncapsulationKeySize768, len(encrypter.EncapsulationKey()))
}

func TestMLKEM768_AlgorithmInfo(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "mlkem-key"}
	encrypter := &MLKEM768{}

	_, err := encrypter.Encrypt("test", provider)
	require.NoError(t, err)

	assert.Equal(t, "ML-KEM-768", encrypter.Algorithm())
	assert.Equal(t, 32, encrypter.KeySize())
}

func TestMLKEM768_KeyDeterminism(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	provider := &mockKeyProvider{key: key, keyID: "mlkem-key"}

	encrypter1 := &MLKEM768{}
	_, err := encrypter1.Encrypt("init1", provider)
	require.NoError(t, err)

	encrypter2 := &MLKEM768{}
	_, err = encrypter2.Encrypt("init2", provider)
	require.NoError(t, err)

	// Same key should produce same ML-KEM key pair
	assert.Equal(t, encrypter1.EncapsulationKey(), encrypter2.EncapsulationKey())
	assert.Equal(t, encrypter1.SecretKey(), encrypter2.SecretKey())
}

func TestMLKEM768_KeyRotation(t *testing.T) {
	currentKey := bytes.Repeat([]byte{0x02}, 32)
	oldKey := bytes.Repeat([]byte{0x01}, 32)

	// Create provider that can return both current and old keys
	rotatableProvider := &rotatableTestProvider{
		currentKey:  currentKey,
		previousKey: oldKey,
		currentID:   "mlkem-current",
		previousID:  "mlkem-previous",
	}

	encrypter := &MLKEM768{}

	// Encrypt with current key
	plaintext := "rotating-data"
	encrypted, err := encrypter.Encrypt(plaintext, rotatableProvider)
	require.NoError(t, err)

	// Verify we can decrypt with current key
	decrypted, err := encrypter.Decrypt(encrypted, rotatableProvider)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

type rotatableTestProvider struct {
	currentKey   []byte
	previousKey  []byte
	currentID    string
	previousID   string
}

func (p *rotatableTestProvider) GetKey(keyID string) ([]byte, error) {
	if keyID == "previous" && p.previousKey != nil {
		return p.previousKey, nil
	}
	return p.currentKey, nil
}

func (p *rotatableTestProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

func (p *rotatableTestProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

func (p *rotatableTestProvider) KeyID() string {
	return p.currentID
}

func BenchmarkMLKEM768(b *testing.B) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider := &mockKeyProvider{key: key, keyID: "mlkem-key"}
	encrypter := &MLKEM768{}

	_, err := encrypter.Encrypt("bench", provider)
	if err != nil {
		b.Fatal(err)
	}

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

	// Pure ML-KEM benchmark
	b.Run("pure_encapsulate", func(b *testing.B) {
		b.SetBytes(32)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = encrypter.encapKey.Encapsulate()
			if i%1000 == 0 && i > 0 {
				encrypter = &MLKEM768{}
				_, _ = encrypter.Encrypt("bench", provider)
			}
		}
	})
}
