package pocketcrypto

import (
	"encoding/base64"
	"errors"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

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
