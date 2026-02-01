package pocketcrypto

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	// Use a valid 32-byte base64 encoded key
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // "0123456789abcdef0123456789abcdef"
	t.Run("default to local provider", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", validKey)
		defer os.Unsetenv("ENCRYPTION_KEY")

		provider, err := newProvider(context.Background(), "")
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("explicit local provider", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", validKey)
		defer os.Unsetenv("ENCRYPTION_KEY")

		provider, err := newProvider(context.Background(), ProviderTypeLocal)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("unknown provider type", func(t *testing.T) {
		_, err := newProvider(context.Background(), "unknown")
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
