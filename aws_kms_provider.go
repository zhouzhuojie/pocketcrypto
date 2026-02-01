package pocketcrypto

import (
	"context"
	"errors"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSProvider provides key management using AWS Key Management Service.
type AWSKMSProvider struct {
	client *kms.Client
	keyID  string
}

// newAWSKMSProvider creates a new AWSKMSProvider.
func newAWSKMSProvider(ctx context.Context, keyID string) (*AWSKMSProvider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := kms.NewFromConfig(cfg)

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

// newAWSKMSProviderFromEnv creates a new AWSKMSProvider using the AWS_KMS_KEY_ID environment variable.
func newAWSKMSProviderFromEnv() (*AWSKMSProvider, error) {
	keyID := os.Getenv("AWS_KMS_KEY_ID")
	if keyID == "" {
		return nil, errors.New("AWS_KMS_KEY_ID environment variable is not set")
	}
	return newAWSKMSProvider(context.Background(), keyID)
}

// GetKey generates and returns a data key for encryption.
func (p *AWSKMSProvider) GetKey(keyID string) ([]byte, error) {
	ctx := context.Background()

	output, err := p.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:      &p.keyID,
		KeySpec:    types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, err
	}

	return output.Plaintext, nil
}

// EncryptKey encrypts data using KMS Encrypt.
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

// DecryptKey decrypts data using KMS Decrypt.
func (p *AWSKMSProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	ctx := context.Background()

	output, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          &p.keyID,
		CiphertextBlob: encryptedKey,
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
