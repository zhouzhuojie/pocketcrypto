package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory_NewProvider(t *testing.T) {
	// Test with local provider (requires ENCRYPTION_KEY)
	t.Run("local provider", func(t *testing.T) {
		key := make([]byte, 32)
		keyB64 := encode(key)
		t.Setenv("ENCRYPTION_KEY", keyB64)
		t.Setenv("KEY_PROVIDER", "")

		provider, err := NewProviderFromEnv(t.Context())
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "local-master", provider.KeyID())
	})

	t.Run("aws-kms provider", func(t *testing.T) {
		t.Setenv("KEY_PROVIDER", "aws-kms")
		t.Setenv("AWS_KMS_KEY_ID", "test-key-id")

		// This will fail without AWS credentials, but tests the factory path
		_, err := NewProvider(t.Context(), "aws-kms")
		// We don't assert success since AWS credentials may not be available
		_ = err
	})

	t.Run("vault provider", func(t *testing.T) {
		t.Setenv("KEY_PROVIDER", "vault")
		t.Setenv("VAULT_ADDR", "http://localhost:8200")
		t.Setenv("VAULT_TOKEN", "test-token")

		// This will fail without Vault server, but tests the factory path
		_, err := NewProvider(t.Context(), "vault")
		// We don't assert success since Vault may not be available
		_ = err
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := NewProvider(t.Context(), "unknown-provider")
		assert.Error(t, err)
		assert.Equal(t, ErrUnknownProviderType, err)
	})
}

func TestFactory_MustProvider(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := encode(key)
	t.Setenv("ENCRYPTION_KEY", keyB64)

	// Should not panic with valid provider
	assert.NotPanics(t, func() {
		provider := MustProvider(t.Context(), "local")
		assert.NotNil(t, provider)
	})
}

func TestProviderType_String(t *testing.T) {
	tests := []struct {
		pt     ProviderType
		expect string
	}{
		{ProviderTypeLocal, "local"},
		{ProviderTypeAWSKMS, "aws-kms"},
		{ProviderTypeVault, "vault"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			assert.Equal(t, tt.expect, string(tt.pt))
		})
	}
}

func TestUnknownProviderTypeError(t *testing.T) {
	err := ErrUnknownProviderType
	assert.Equal(t, "unknown key provider type", err.Error())
}

// encode is a helper for base64 encoding
func encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
