package crypto

import (
	"context"
	"errors"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSProvider provides key management using AWS Key Management Service.
// This is the recommended provider for production deployments.
//
// Features:
// - Automatic key rotation (configured in KMS)
// - Hardware security module (HSM) backed keys
// - Audit logging via CloudTrail
// - Fine-grained access control via IAM
type AWSKMSProvider struct {
	client *kms.Client
	keyID  string
}

// NewAWSKMSProvider creates a new AWSKMSProvider.
// The keyID can be a key ID, key ARN, alias, or alias ARN.
// Common formats:
// - Key ID: 1234abcd-12ab-34cd-56ef-1234567890ab
// - Alias: alias/my-key
// - ARN: arn:aws:kms:us-east-1:123456789012:key/1234abcd-...
func NewAWSKMSProvider(ctx context.Context, keyID string) (*AWSKMSProvider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	// Verify key exists and is accessible
	client := kms.NewFromConfig(cfg)

	// Test access to the key
	_, err = client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, err
	}

	return &AWSKMSProvider{
		client: client,
		keyID:  keyID,
	}, nil
}

// NewAWSKMSProviderFromEnv creates a new AWSKMSProvider using the
// AWS_KMS_KEY_ID environment variable.
func NewAWSKMSProviderFromEnv(ctx context.Context) (*AWSKMSProvider, error) {
	keyID := os.Getenv("AWS_KMS_KEY_ID")
	if keyID == "" {
		return nil, errors.New("AWS_KMS_KEY_ID environment variable is not set")
	}
	return NewAWSKMSProvider(ctx, keyID)
}

// GetKey generates and returns a data key for encryption.
// This uses KMS GenerateDataKey to get a plaintext key for local encryption
// and a ciphertext key that should be stored alongside the encrypted data.
func (p *AWSKMSProvider) GetKey(keyID string) ([]byte, error) {
	ctx := context.Background()

	output, err := p.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:      &p.keyID,
		KeySpec:    types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, err
	}

	// Return the plaintext key; caller should store the ciphertext
	// for later decryption if needed
	return output.Plaintext, nil
}

// Encrypt encrypts data using KMS Encrypt.
func (p *AWSKMSProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	ctx := context.Background()

	output, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &p.keyID,
		Plaintext: key,
	})
	if err != nil {
		return nil, err
	}
	return output.CiphertextBlob, nil
}

// Decrypt decrypts data using KMS Decrypt.
func (p *AWSKMSProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	ctx := context.Background()

	output, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               &p.keyID,
		CiphertextBlob:      encryptedKey,
	})
	if err != nil {
		return nil, err
	}
	return output.Plaintext, nil
}

// KeyID returns the KMS key identifier.
func (p *AWSKMSProvider) KeyID() string {
	return "kms://" + p.keyID
}

// GetKeyID returns the underlying KMS key ID.
func (p *AWSKMSProvider) GetKeyID() string {
	return p.keyID
}
