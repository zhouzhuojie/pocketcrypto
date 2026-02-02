package pocketcrypto

import (
	"bytes"
	"crypto/mlkem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKey = "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEhISE=" // 32 bytes base64

func TestMLKEM768_New(t *testing.T) {
	t.Run("creates MLKEM768 from ENCRYPTION_KEY", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", testKey)
		defer os.Unsetenv("ENCRYPTION_KEY")

		encrypter := &MLKEM768{}
		_, err := encrypter.Encrypt("test", nil)
		require.NoError(t, err)

		// Verify key is generated
		assert.NotNil(t, encrypter.EncapsulationKey())
		assert.NotNil(t, encrypter.SecretKey())
		assert.Equal(t, mlkem.EncapsulationKeySize768, len(encrypter.EncapsulationKey()))
	})

	t.Run("fails without ENCRYPTION_KEY", func(t *testing.T) {
		os.Unsetenv("ENCRYPTION_KEY")
		defer os.Unsetenv("ENCRYPTION_KEY")

		encrypter := &MLKEM768{}
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ENCRYPTION_KEY")
	})

	t.Run("fails with invalid base64 in ENCRYPTION_KEY", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "not-valid-base64!!!")
		defer os.Unsetenv("ENCRYPTION_KEY")

		encrypter := &MLKEM768{}
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64")
	})

	t.Run("fails with wrong key size", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "dGVzdC1rZXktMTYtYnl0ZXM=") // 16 bytes
		defer os.Unsetenv("ENCRYPTION_KEY")

		encrypter := &MLKEM768{}
		_, err := encrypter.Encrypt("test", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})
}

func TestMLKEM768_EncryptDecrypt(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", testKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	encrypter := &MLKEM768{}
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
	os.Setenv("ENCRYPTION_KEY", testKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	encrypter := &MLKEM768{}
	_, err := encrypter.Encrypt("test", nil)
	require.NoError(t, err)

	assert.Equal(t, "ML-KEM-768", encrypter.Algorithm())
	assert.Equal(t, 32, encrypter.KeySize())
	assert.Equal(t, mlkem.EncapsulationKeySize768, len(encrypter.EncapsulationKey()))
}

func TestMLKEM768_KeyDeterminism(t *testing.T) {
	// Same ENCRYPTION_KEY should produce the same ML-KEM key pair
	os.Setenv("ENCRYPTION_KEY", testKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	encrypter1 := &MLKEM768{}
	_, err := encrypter1.Encrypt("init1", nil)
	require.NoError(t, err)

	encrypter2 := &MLKEM768{}
	_, err = encrypter2.Encrypt("init2", nil)
	require.NoError(t, err)

	assert.Equal(t, encrypter1.EncapsulationKey(), encrypter2.EncapsulationKey())
	assert.Equal(t, encrypter1.SecretKey(), encrypter2.SecretKey())
}

func BenchmarkMLKEM768(b *testing.B) {
	os.Setenv("ENCRYPTION_KEY", testKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	encrypter := &MLKEM768{}
	_, err := encrypter.Encrypt("bench", nil)
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
				encrypter = &MLKEM768{}
				_, _ = encrypter.Encrypt("bench", nil)
			}
		}
	})
}
