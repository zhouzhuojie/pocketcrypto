package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AES256GCM provides authenticated encryption using AES-256-GCM.
// This is the default encrypter for column-level encryption.
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
// The key is retrieved from the key provider using "aes-main" as the key ID.
func (a *AES256GCM) Encrypt(plaintext string, provider KeyProvider) (string, error) {
	if provider == nil {
		return "", errors.New("key provider is required")
	}

	key, err := provider.GetKey("aes-main")
	if err != nil {
		return "", err
	}

	// Create envelope with key ID for later decryption
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

	// Seal with nil destination returns: ciphertext || auth_tag
	// The nonce is NOT included in the output when destination is nil
	ciphertextWithAuthTag := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	envelope := DataEnvelope{
		Algorithm:  a.Algorithm(),
		KeyID:      provider.KeyID(),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextWithAuthTag),
		Version:    1,
	}

	return envelope.Marshal(), nil
}

// EncryptWithKey encrypts plaintext using the provided key.
// This is useful for internal use when the key is already available.
func (a *AES256GCM) EncryptWithKey(plaintext string, key []byte) (string, error) {
	if len(key) != a.KeySize() {
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal with nil destination returns: ciphertext || auth_tag
	ciphertextWithAuthTag := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	envelope := DataEnvelope{
		Algorithm:  a.Algorithm(),
		KeyID:      "",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextWithAuthTag),
		Version:    1,
	}

	return envelope.Marshal(), nil
}

// Decrypt decrypts encrypted data using AES-256-GCM.
// The key is retrieved from the key provider using the key ID from the envelope.
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

	if len(key) != a.KeySize() {
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

	// Nonce is stored separately
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return "", errors.New("invalid nonce encoding")
	}

	// Ciphertext is ciphertext || auth_tag
	ciphertextWithAuthTag, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return "", errors.New("invalid ciphertext encoding")
	}

	// Open expects: nonce as second param, ciphertext || auth_tag as third param
	plaintext, err := gcm.Open(nil, nonce, ciphertextWithAuthTag, nil)
	if err != nil {
		return "", errors.New("decryption failed: authentication tag mismatch")
	}

	return string(plaintext), nil
}
