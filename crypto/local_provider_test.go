package crypto

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalProvider(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	os.Setenv("ENCRYPTION_KEY", keyB64)
	defer os.Unsetenv("ENCRYPTION_KEY")

	provider, err := NewLocalProvider()
	require.NoError(t, err, "should create provider")

	retrievedKey, err := provider.GetKey("test")
	require.NoError(t, err, "GetKey should not fail")
	assert.Equal(t, key, retrievedKey, "key should match")
}

func TestLocalProvider_MissingKey(t *testing.T) {
	os.Unsetenv("ENCRYPTION_KEY")
	defer os.Unsetenv("ENCRYPTION_KEY")

	_, err := NewLocalProvider()
	assert.Error(t, err, "should error when key not set")
}

func TestLocalProvider_InvalidBase64(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "not-valid-base64!!!")
	defer os.Unsetenv("ENCRYPTION_KEY")

	_, err := NewLocalProvider()
	assert.Error(t, err, "should error with invalid base64")
}

func TestLocalProvider_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	os.Setenv("ENCRYPTION_KEY", keyB64)
	defer os.Unsetenv("ENCRYPTION_KEY")

	_, err := NewLocalProvider()
	assert.Error(t, err, "should error with wrong key size")
}

func TestLocalProvider_EncryptDecryptKey(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	os.Setenv("ENCRYPTION_KEY", keyB64)
	defer os.Unsetenv("ENCRYPTION_KEY")

	provider, err := NewLocalProvider()
	require.NoError(t, err)

	encrypted, err := provider.EncryptKey(key, "test-key")
	require.NoError(t, err)
	assert.Equal(t, key, encrypted, "encrypted key should be same as original for local provider")

	decrypted, err := provider.DecryptKey(encrypted)
	require.NoError(t, err)
	assert.Equal(t, key, decrypted, "decrypted key should match original")
}

func TestLocalProvider_KeyID(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	os.Setenv("ENCRYPTION_KEY", keyB64)
	defer os.Unsetenv("ENCRYPTION_KEY")

	provider, err := NewLocalProvider()
	require.NoError(t, err)

	assert.Equal(t, "local-master", provider.KeyID())
}

func TestLocalProvider_MasterKey(t *testing.T) {
	// Create a non-zero key to test properly
	key := bytes.Repeat([]byte{0xAB}, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	os.Setenv("ENCRYPTION_KEY", keyB64)
	defer os.Unsetenv("ENCRYPTION_KEY")

	provider, err := NewLocalProvider()
	require.NoError(t, err)

	masterKey1 := provider.MasterKey()
	assert.Equal(t, key, masterKey1, "MasterKey should return copy of key")

	// Verify it's a copy by modifying the returned key
	masterKey1[0] = 0xFF

	// Get another copy and verify the original is unchanged
	masterKey2 := provider.MasterKey()
	assert.Equal(t, byte(0xAB), masterKey2[0], "internal key should be unchanged after modifying copy")
	assert.NotEqual(t, masterKey1[0], masterKey2[0], "different copies should be independent")
}

func TestLocalProvider_NewLocalProviderFromKey(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		key := bytes.Repeat([]byte{0xAB}, 32)
		provider, err := NewLocalProviderFromKey(key)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "local-master", provider.KeyID())
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := NewLocalProviderFromKey(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("key too short", func(t *testing.T) {
		key := bytes.Repeat([]byte{0xAB}, 16)
		_, err := NewLocalProviderFromKey(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("key too long", func(t *testing.T) {
		key := bytes.Repeat([]byte{0xAB}, 64)
		_, err := NewLocalProviderFromKey(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("key is copied", func(t *testing.T) {
		key := bytes.Repeat([]byte{0xAB}, 32)
		provider, err := NewLocalProviderFromKey(key)
		require.NoError(t, err)

		// Modify original key
		key[0] = 0xFF

		// Provider should still have original key
		masterKey := provider.MasterKey()
		assert.Equal(t, byte(0xAB), masterKey[0], "provider key should not be affected by modifying original")
	})
}
