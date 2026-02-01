package pocketcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
