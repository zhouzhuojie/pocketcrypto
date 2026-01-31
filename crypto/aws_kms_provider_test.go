package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAWSKMSProvider_KeyID(t *testing.T) {
	// Test that KeyID returns properly formatted ID
	provider := &AWSKMSProvider{keyID: "test-key-id"}
	assert.Equal(t, "kms://test-key-id", provider.KeyID())
}

func TestAWSKMSProvider_GetKeyID(t *testing.T) {
	provider := &AWSKMSProvider{keyID: "alias/my-key"}
	assert.Equal(t, "alias/my-key", provider.GetKeyID())
}

func TestAWSKMSProvider_Interface(t *testing.T) {
	// Verify AWSKMSProvider implements KeyProvider
	var _ KeyProvider = &AWSKMSProvider{}
}
