package pocketcrypto

import (
	"crypto/mlkem"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// MLKEM768 provides post-quantum encryption using ML-KEM-768 (FIPS 203).
// It uses the ENCRYPTION_KEY environment variable (32 bytes, base64 encoded)
// to derive the secret key. The key is hashed (SHA-512) to get the required
// 64-byte seed for ML-KEM key generation.
type MLKEM768 struct {
	decapsKey *mlkem.DecapsulationKey768
	encapKey  *mlkem.EncapsulationKey768
}

// EncapsulationKey returns the public encapsulation key for sharing.
func (m *MLKEM768) EncapsulationKey() []byte {
	if m.encapKey == nil {
		return nil
	}
	return m.encapKey.Bytes()
}

// SecretKey returns the secret decapsulation key for secure storage.
// Returns nil if the key is not initialized from ENCRYPTION_KEY.
func (m *MLKEM768) SecretKey() []byte {
	if m.decapsKey == nil {
		return nil
	}
	return m.decapsKey.Bytes()
}

// initFromEnv initializes ML-KEM from ENCRYPTION_KEY environment variable.
func (m *MLKEM768) initFromEnv() error {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		return errors.New("ENCRYPTION_KEY environment variable is not set")
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding in ENCRYPTION_KEY: %w", err)
	}

	if len(key) != 32 {
		return errors.New("ENCRYPTION_KEY must be 32 bytes (256 bits) when decoded")
	}

	// Hash the 32-byte key to get 64 bytes for ML-KEM seed
	hash := sha512.Sum512(key)
	seed := hash[:64]

	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return fmt.Errorf("failed to create ML-KEM key from ENCRYPTION_KEY: %w", err)
	}

	m.decapsKey = dk
	m.encapKey = dk.EncapsulationKey()
	return nil
}

// Algorithm returns the name of the encryption algorithm.
func (m *MLKEM768) Algorithm() string {
	return "ML-KEM-768"
}

// KeySize returns the size of the shared key produced by ML-KEM.
func (m *MLKEM768) KeySize() int {
	return mlkem.SharedKeySize
}

// Encrypt encrypts plaintext using ML-KEM-768 key encapsulation.
// Initializes from ENCRYPTION_KEY if not already initialized.
func (m *MLKEM768) Encrypt(plaintext string, provider KeyProvider) (string, error) {
	if m.encapKey == nil {
		if err := m.initFromEnv(); err != nil {
			return "", err
		}
	}

	sharedSecret, ciphertext := m.encapKey.Encapsulate()

	aes := &AES256GCM{}
	encrypted, err := aes.EncryptWithKey(plaintext, sharedSecret)
	if err != nil {
		return "", err
	}

	envelope := DataEnvelope{
		Algorithm:    m.Algorithm(),
		KeyID:        "",
		EncryptedKey: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:        "", // AES256GCM handles nonce internally
		Ciphertext:   encrypted,
		Version:      1,
	}

	return envelope.Marshal(), nil
}

// Decrypt decrypts data that was encrypted using ML-KEM-768.
// Initializes from ENCRYPTION_KEY if not already initialized.
func (m *MLKEM768) Decrypt(encrypted string, provider KeyProvider) (string, error) {
	if m.decapsKey == nil {
		if err := m.initFromEnv(); err != nil {
			return "", err
		}
	}

	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
		return "", err
	}

	// Try to decrypt using the embedded ciphertext first
	if envelope.EncryptedKey != "" {
		ciphertext, err := base64.StdEncoding.DecodeString(envelope.EncryptedKey)
		if err != nil {
			return "", err
		}

		sharedSecret, err := m.decapsKey.Decapsulate(ciphertext)
		if err != nil {
			return "", err
		}

		aes := &AES256GCM{}
		return aes.DecryptWithKey(envelope.Ciphertext, sharedSecret)
	}

	// Fall back to provider-based decryption
	if provider == nil {
		return "", errors.New("no decryption key available")
	}

	encryptedKey, err := provider.DecryptKey([]byte(encrypted))
	if err != nil {
		return "", err
	}

	// Re-parse the envelope from decrypted key
	if err := envelope.Unmarshal(string(encryptedKey)); err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.EncryptedKey)
	if err != nil {
		return "", err
	}

	sharedSecret, err := m.decapsKey.Decapsulate(ciphertext)
	if err != nil {
		return "", err
	}

	aes := &AES256GCM{}
	return aes.DecryptWithKey(envelope.Ciphertext, sharedSecret)
}
