package pocketcrypto

import (
	"context"
	"encoding/base64"
	"errors"
	"os"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// LocalProvider provides key management using environment variables.
type LocalProvider struct {
	masterKey   []byte
	previousKey []byte
}

// newLocalProvider creates a new LocalProvider from environment variables.
// Supports ENCRYPTION_KEY (current/master) and ENCRYPTION_KEY_OLD (previous for rotation).
func newLocalProvider() (*LocalProvider, error) {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		return nil, errors.New("ENCRYPTION_KEY environment variable is not set")
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, errors.New("invalid base64 encoding in ENCRYPTION_KEY")
	}

	if len(key) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be 32 bytes (256 bits) when decoded")
	}

	p := &LocalProvider{masterKey: key}

	// Support previous key for rotation (lazy decryption falls back to it)
	oldKeyStr := os.Getenv("ENCRYPTION_KEY_OLD")
	if oldKeyStr != "" {
		oldKey, err := base64.StdEncoding.DecodeString(oldKeyStr)
		if err != nil {
			return nil, errors.New("invalid base64 encoding in ENCRYPTION_KEY_OLD")
		}
		if len(oldKey) != 32 {
			return nil, errors.New("ENCRYPTION_KEY_OLD must be 32 bytes (256 bits) when decoded")
		}
		p.previousKey = oldKey
	}

	return p, nil
}

// newLocalProviderFromKey creates a LocalProvider directly from a key byte slice.
func newLocalProviderFromKey(key []byte) (*LocalProvider, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &LocalProvider{masterKey: keyCopy}, nil
}

// GetKey retrieves the encryption key.
// For lazy rotation: returns current master key by default.
// Falls back to previous key if the keyID is "previous".
func (p *LocalProvider) GetKey(keyID string) ([]byte, error) {
	if keyID == "previous" && p.previousKey != nil {
		return p.previousKey, nil
	}
	return p.masterKey, nil
}

// EncryptKey returns the key as-is.
func (p *LocalProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

// DecryptKey returns the encrypted key as-is.
func (p *LocalProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

// KeyID returns the identifier for this provider.
func (p *LocalProvider) KeyID() string {
	return "local-master"
}

// MasterKey returns a copy of the master key.
func (p *LocalProvider) MasterKey() []byte {
	result := make([]byte, len(p.masterKey))
	copy(result, p.masterKey)
	return result
}

// HasPrevious returns true if a previous key is configured for rotation.
func (p *LocalProvider) HasPrevious() bool {
	return p.previousKey != nil
}

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

// VaultProvider provides key management using HashiCorp Vault.
type VaultProvider struct {
	client    *vaultapi.Client
	mountPath string
	keyPath   string
}

// newVaultProvider creates a new VaultProvider.
func newVaultProvider() (*VaultProvider, error) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil, errors.New("VAULT_ADDR and VAULT_TOKEN environment variables must be set")
	}

	config := vaultapi.DefaultConfig()
	config.Address = addr

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	mountPath := os.Getenv("VAULT_MOUNT_PATH")
	if mountPath == "" {
		mountPath = "secret"
	}

	keyPath := os.Getenv("VAULT_KEY_PATH")
	if keyPath == "" {
		keyPath = "pocketcrypto/encryption-key"
	}

	return &VaultProvider{
		client:    client,
		mountPath: mountPath,
		keyPath:   keyPath,
	}, nil
}

// GetKey retrieves the encryption key from Vault.
func (p *VaultProvider) GetKey(keyID string) ([]byte, error) {
	secret, err := p.client.Logical().Read(p.mountPath + "/" + p.keyPath)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("encryption key not found in Vault")
	}

	var keyStr string
	if v, ok := secret.Data["key"].(string); ok {
		keyStr = v
	} else if v, ok := secret.Data["value"].(string); ok {
		keyStr = v
	} else {
		return nil, errors.New("encryption key not found in Vault secret data")
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, errors.New("invalid base64 encoding in Vault secret")
	}

	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}

	return key, nil
}

// EncryptKey stores an encrypted version of the key in Vault.
func (p *VaultProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	keyB64 := base64.StdEncoding.EncodeToString(key)

	_, err := p.client.Logical().Write(p.mountPath+"/"+keyID, map[string]interface{}{
		"key": keyB64,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// DecryptKey retrieves and decrypts an encrypted key from Vault.
func (p *VaultProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	secret, err := p.client.Logical().Read(p.mountPath + "/" + string(encryptedKey))
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("encrypted key not found in Vault")
	}

	keyStr, ok := secret.Data["key"].(string)
	if !ok {
		return nil, errors.New("key not found in Vault secret")
	}

	return base64.StdEncoding.DecodeString(keyStr)
}

// KeyID returns the identifier for this provider.
func (p *VaultProvider) KeyID() string {
	return "vault://" + p.mountPath + "/" + p.keyPath
}

// StoreKey stores a new encryption key in Vault.
func (p *VaultProvider) StoreKey(key []byte) error {
	keyB64 := base64.StdEncoding.EncodeToString(key)

	_, err := p.client.Logical().Write(p.mountPath+"/"+p.keyPath, map[string]interface{}{
		"key": keyB64,
	})
	return err
}

// DeleteKey removes the encryption key from Vault.
func (p *VaultProvider) DeleteKey() error {
	_, err := p.client.Logical().Delete(p.mountPath + "/" + p.keyPath)
	return err
}

// Client returns the underlying Vault client.
func (p *VaultProvider) Client() *vaultapi.Client {
	return p.client
}
