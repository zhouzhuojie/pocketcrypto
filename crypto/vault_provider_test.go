package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultProvider_KeyID(t *testing.T) {
	provider := &VaultProvider{
		mountPath: "secret",
		keyPath:   "pocketcrypto/encryption-key",
	}
	assert.Equal(t, "vault://secret/pocketcrypto/encryption-key", provider.KeyID())
}

func TestVaultProvider_Interface(t *testing.T) {
	// Verify VaultProvider implements KeyProvider
	var _ KeyProvider = &VaultProvider{}
}
