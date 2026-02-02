package pocketcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// AES256GCM provides authenticated encryption using AES-256-GCM.
type AES256GCM struct{}

// Algorithm returns the name of the encryption algorithm.
func (a *AES256GCM) Algorithm() string {
	return "AES-256-GCM"
}

// KeySize returns the required key size in bytes.
func (a *AES256GCM) KeySize() int {
	return 32
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
func (a *AES256GCM) Encrypt(plaintext string, provider KeyProvider) (string, error) {
	if provider == nil {
		return "", errors.New("key provider is required")
	}

	key, err := provider.GetKey("aes-main")
	if err != nil {
		return "", err
	}

	return a.encryptWithKey(plaintext, key, provider.KeyID())
}

// encryptWithKey is the internal encryption with a key.
func (a *AES256GCM) encryptWithKey(plaintext string, key []byte, keyID string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertextWithAuthTag := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	envelope := DataEnvelope{
		Algorithm:  a.Algorithm(),
		KeyID:      keyID,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextWithAuthTag),
		Version:    1,
	}

	return envelope.Marshal(), nil
}

// EncryptWithKey encrypts plaintext using the provided key.
func (a *AES256GCM) EncryptWithKey(plaintext string, key []byte) (string, error) {
	return a.encryptWithKey(plaintext, key, "")
}

// Decrypt decrypts encrypted data using AES-256-GCM.
func (a *AES256GCM) Decrypt(encrypted string, provider KeyProvider) (string, error) {
	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
		return "", err
	}

	if provider == nil {
		return "", errors.New("key provider is required")
	}

	key, err := provider.GetKey(envelope.KeyID)
	if err != nil {
		return "", err
	}

	return a.DecryptWithKey(encrypted, key)
}

// DecryptWithKey decrypts encrypted data using the provided key.
func (a *AES256GCM) DecryptWithKey(encrypted string, key []byte) (string, error) {
	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
		return "", err
	}

	if len(key) != 32 {
		return "", errors.New("invalid key size: expected 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return "", errors.New("invalid nonce encoding")
	}

	ciphertextWithAuthTag, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return "", errors.New("invalid ciphertext encoding")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithAuthTag, nil)
	if err != nil {
		return "", errors.New("decryption failed: authentication tag mismatch")
	}

	return string(plaintext), nil
}

// MLKEM768 provides post-quantum encryption using ML-KEM-768 (FIPS 203).
// It uses the KeyProvider to get the encryption key, same as AES256GCM.
// The 32-byte key is hashed (SHA-512) to get the 64-byte seed for ML-KEM.
type MLKEM768 struct {
	decapsKey *mlkem.DecapsulationKey768
	encapKey  *mlkem.EncapsulationKey768
	cacheKey  []byte
}

// EncapsulationKey returns the public encapsulation key for sharing.
func (m *MLKEM768) EncapsulationKey() []byte {
	if m.encapKey == nil {
		return nil
	}
	return m.encapKey.Bytes()
}

// SecretKey returns the secret decapsulation key for secure storage.
func (m *MLKEM768) SecretKey() []byte {
	if m.decapsKey == nil {
		return nil
	}
	return m.decapsKey.Bytes()
}

// initFromProvider initializes ML-KEM keys from the provider.
func (m *MLKEM768) initFromProvider(provider KeyProvider, keyID string) error {
	key, err := provider.GetKey(keyID)
	if err != nil {
		return err
	}

	// Use cached key if available
	if m.cacheKey != nil && string(m.cacheKey) == string(key) {
		return nil
	}

	if len(key) != 32 {
		return errors.New("key must be 32 bytes for ML-KEM-768")
	}

	// Hash the 32-byte key to get 64 bytes for ML-KEM seed
	hash := sha512.Sum512(key)
	seed := hash[:64]

	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return fmt.Errorf("failed to create ML-KEM key: %w", err)
	}

	m.decapsKey = dk
	m.encapKey = dk.EncapsulationKey()
	m.cacheKey = make([]byte, len(key))
	copy(m.cacheKey, key)
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
func (m *MLKEM768) Encrypt(plaintext string, provider KeyProvider) (string, error) {
	if provider == nil {
		return "", errors.New("key provider is required")
	}

	if err := m.initFromProvider(provider, "mlkem-main"); err != nil {
		return "", err
	}

	sharedSecret, ciphertext := m.encapKey.Encapsulate()

	aes := &AES256GCM{}
	encrypted, err := aes.EncryptWithKey(plaintext, sharedSecret)
	if err != nil {
		return "", err
	}

	envelope := DataEnvelope{
		Algorithm:    m.Algorithm(),
		KeyID:        provider.KeyID(),
		EncryptedKey: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:        "", // AES256GCM handles nonce internally
		Ciphertext:   encrypted,
		Version:      1,
	}

	return envelope.Marshal(), nil
}

// Decrypt decrypts data that was encrypted using ML-KEM-768.
func (m *MLKEM768) Decrypt(encrypted string, provider KeyProvider) (string, error) {
	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
		return "", err
	}

	if provider == nil {
		return "", errors.New("key provider is required")
	}

	// Get the appropriate key based on KeyID in envelope
	if err := m.initFromProvider(provider, envelope.KeyID); err != nil {
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
