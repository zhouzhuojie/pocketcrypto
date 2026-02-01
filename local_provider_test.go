package pocketcrypto

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalProvider_New(t *testing.T) {
	// Valid 32-byte base64 encoded key
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // "0123456789abcdef0123456789abcdef"
	t.Run("create from valid base64 key", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", validKey)
		defer os.Unsetenv("ENCRYPTION_KEY")

		provider, err := newLocalProvider()
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "local-master", provider.KeyID())
	})

	t.Run("missing env var fails", func(t *testing.T) {
		os.Unsetenv("ENCRYPTION_KEY")
		_, err := newLocalProvider()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ENCRYPTION_KEY")
	})

	t.Run("invalid base64 fails", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "not-valid-base64!!!")
		defer os.Unsetenv("ENCRYPTION_KEY")

		_, err := newLocalProvider()
		assert.Error(t, err)
	})

	t.Run("wrong key size fails", func(t *testing.T) {
		// 16 bytes instead of 32
		os.Setenv("ENCRYPTION_KEY", "dGVzdC1rZXktMTYtYnl0ZXM=")
		defer os.Unsetenv("ENCRYPTION_KEY")

		_, err := newLocalProvider()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})
}

func TestLocalProvider_FromKey(t *testing.T) {
	t.Run("create from valid key bytes", func(t *testing.T) {
		key := bytes.Repeat([]byte{0x01}, 32)
		provider, err := newLocalProviderFromKey(key)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("wrong key size fails", func(t *testing.T) {
		key := bytes.Repeat([]byte{0x01}, 16)
		_, err := newLocalProviderFromKey(key)
		assert.Error(t, err)
	})

	t.Run("key is copied", func(t *testing.T) {
		originalKey := bytes.Repeat([]byte{0xAB}, 32)
		provider, err := newLocalProviderFromKey(originalKey)
		require.NoError(t, err)

		// Modify original
		originalKey[0] = 0xCD

		// Provider key should be unchanged
		retrievedKey, _ := provider.GetKey("test")
		assert.Equal(t, byte(0xAB), retrievedKey[0])
	})
}

func TestLocalProvider_Operations(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	provider, err := newLocalProviderFromKey(key)
	require.NoError(t, err)

	t.Run("GetKey returns master key", func(t *testing.T) {
		retrievedKey, err := provider.GetKey("any-id")
		require.NoError(t, err)
		assert.Equal(t, key, retrievedKey)
	})

	t.Run("EncryptKey returns key unchanged", func(t *testing.T) {
		result, err := provider.EncryptKey(key, "test-id")
		require.NoError(t, err)
		assert.Equal(t, key, result)
	})

	t.Run("DecryptKey returns key unchanged", func(t *testing.T) {
		result, err := provider.DecryptKey(key)
		require.NoError(t, err)
		assert.Equal(t, key, result)
	})

	t.Run("MasterKey returns copy", func(t *testing.T) {
		masterKey := provider.MasterKey()
		assert.Equal(t, key, masterKey)

		// Modify returned key
		masterKey[0] = 0xFF

		// Original should be unchanged
		original, _ := provider.GetKey("test")
		assert.Equal(t, byte(0x01), original[0])
	})
}

func TestLocalProvider_Rotation(t *testing.T) {
	currentKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // "0123456789abcdef..."
	oldKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 0x00 x 32

	t.Run("current key only", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", currentKey)
		os.Unsetenv("ENCRYPTION_KEY_OLD")
		defer os.Unsetenv("ENCRYPTION_KEY")
		defer os.Unsetenv("ENCRYPTION_KEY_OLD")

		provider, err := newLocalProvider()
		require.NoError(t, err)

		// GetKey without keyID returns current
		key, _ := provider.GetKey("")
		assert.NotNil(t, key)
	})

	t.Run("both current and old keys", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", currentKey)
		os.Setenv("ENCRYPTION_KEY_OLD", oldKey)
		defer os.Unsetenv("ENCRYPTION_KEY")
		defer os.Unsetenv("ENCRYPTION_KEY_OLD")

		provider, err := newLocalProvider()
		require.NoError(t, err)

		// GetKey("") returns current (starts with '0' = 0x30)
		current, _ := provider.GetKey("")
		assert.Equal(t, byte('0'), current[0])

		// GetKey("previous") returns old (all zeros)
		previous, _ := provider.GetKey("previous")
		assert.Equal(t, byte(0x00), previous[0])
	})

	t.Run("invalid old key fails", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", currentKey)
		os.Setenv("ENCRYPTION_KEY_OLD", "not-valid-base64")
		defer os.Unsetenv("ENCRYPTION_KEY")
		defer os.Unsetenv("ENCRYPTION_KEY_OLD")

		_, err := newLocalProvider()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ENCRYPTION_KEY_OLD")
	})
}
