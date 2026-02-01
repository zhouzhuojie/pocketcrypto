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

// kmsClientInterface defines the subset of kms.Client methods used by AWSKMSProvider.
// This allows for testing via interface injection.
type kmsClientInterface interface {
	GenerateDataKey(ctx interface{}, input interface{}) (interface{}, error)
	Encrypt(ctx interface{}, input interface{}) (interface{}, error)
	Decrypt(ctx interface{}, input interface{}) (interface{}, error)
}

// mockableAWSKMSProvider wraps AWSKMSProvider with injectable client for testing.
type mockableAWSKMSProvider struct {
	*AWSKMSProvider
}

func TestAWSKMSProvider_KeyFormats(t *testing.T) {
	testCases := []struct {
		name     string
		keyID    string
		expected string
	}{
		{"plain key ID", "1234abcd-12ab-34cd-56ef-1234567890ab", "kms://1234abcd-12ab-34cd-56ef-1234567890ab"},
		{"alias", "alias/my-key", "kms://alias/my-key"},
		{"ARN", "arn:aws:kms:us-east-1:123456789012:key/1234abcd", "kms://arn:aws:kms:us-east-1:123456789012:key/1234abcd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &AWSKMSProvider{keyID: tc.keyID}
			assert.Equal(t, tc.expected, provider.KeyID())
		})
	}
}
