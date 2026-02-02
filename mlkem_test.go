package pocketcrypto

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLKEM768_KeyGeneration(t *testing.T) {
	t.Run("generate new key pair", func(t *testing.T) {
		encrypter, err := newMLKEM768()
		require.NoError(t, err)
		assert.NotNil(t, encrypter)

		// Verify encapsulation key is generated
		encapKey := encrypter.EncapsulationKey()
		assert.NotNil(t, encapKey)
		assert.Equal(t, mlkem.EncapsulationKeySize768, len(encapKey))

		// Verify decapsulation key is generated
		decapKey := encrypter.SecretKey()
		assert.NotNil(t, decapKey)
	})

	t.Run("generate key pair from seed", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0x01}, 64)
		encrypter, err := newMLKEM768FromSeed(seed)
		require.NoError(t, err)
		assert.NotNil(t, encrypter)
	})

	t.Run("encrypt without key fails", func(t *testing.T) {
		encrypter := &MLKEM768{}
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encapsulation key not initialized")
	})

	t.Run("decrypt without key fails", func(t *testing.T) {
		encrypter := &MLKEM768{}
		_, err := encrypter.Decrypt("invalid", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decapsulation key not initialized")
	})
}

func TestMLKEM768_EncryptDecrypt(t *testing.T) {
	encrypter, err := newMLKEM768()
	require.NoError(t, err)
	provider := &mockKeyProvider{key: make([]byte, 32), keyID: "mlkem-key"}

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
}

func TestMLKEM768_AlgorithmInfo(t *testing.T) {
	encrypter, err := newMLKEM768()
	require.NoError(t, err)

	assert.Equal(t, "ML-KEM-768", encrypter.Algorithm())
	assert.Equal(t, 32, encrypter.KeySize())
	assert.Equal(t, mlkem.EncapsulationKeySize768, len(encrypter.EncapsulationKey()))
}

func TestMLKEM768_KeyPersistence(t *testing.T) {
	t.Run("same seed produces same key pair", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0x42}, 64)

		encrypter1, err := newMLKEM768FromSeed(seed)
		require.NoError(t, err)

		encrypter2, err := newMLKEM768FromSeed(seed)
		require.NoError(t, err)

		assert.Equal(t, encrypter1.EncapsulationKey(), encrypter2.EncapsulationKey())
		assert.Equal(t, encrypter1.SecretKey(), encrypter2.SecretKey())
	})

	t.Run("different seeds produce different key pairs", func(t *testing.T) {
		seed1 := bytes.Repeat([]byte{0x01}, 64)
		seed2 := bytes.Repeat([]byte{0x02}, 64)

		encrypter1, err := newMLKEM768FromSeed(seed1)
		require.NoError(t, err)

		encrypter2, err := newMLKEM768FromSeed(seed2)
		require.NoError(t, err)

		assert.NotEqual(t, encrypter1.EncapsulationKey(), encrypter2.EncapsulationKey())
	})
}

func BenchmarkMLKEM768(b *testing.B) {
	encrypter, err := newMLKEM768()
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

	// Pure ML-KEM benchmark (encapsulate/decapsulate)
	b.Run("pure_encapsulate", func(b *testing.B) {
		b.SetBytes(32)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = encrypter.encapKey.Encapsulate()
			// Re-create encrypter since Encapsulate consumes the key
			if i%1000 == 0 && i > 0 {
				encrypter, _ = newMLKEM768()
			}
		}
	})
}
