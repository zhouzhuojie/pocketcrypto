package pocketcrypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// MLKEM768 provides post-quantum encryption using ML-KEM-768 (FIPS 203).
type MLKEM768 struct {
	decapsKey *mlkem.DecapsulationKey768
	encapKey  *mlkem.EncapsulationKey768
}

// NewMLKEM768 generates a new ML-KEM-768 key pair.
func newMLKEM768() (*MLKEM768, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &MLKEM768{
		decapsKey: dk,
		encapKey:  dk.EncapsulationKey(),
	}, nil
}

// NewMLKEM768FromSeed creates an ML-KEM-768 key pair from a seed.
func newMLKEM768FromSeed(seed []byte) (*MLKEM768, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &MLKEM768{
		decapsKey: dk,
		encapKey:  dk.EncapsulationKey(),
	}, nil
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
	if m.encapKey == nil {
		return "", errors.New("ML-KEM encapsulation key not initialized")
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
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
		KeyID:        "",
		EncryptedKey: base64.StdEncoding.EncodeToString(ciphertext),
		Ciphertext:   encrypted,
		Version:      1,
	}

	return envelope.Marshal(), nil
}

// Decrypt decrypts data that was encrypted using ML-KEM-768.
func (m *MLKEM768) Decrypt(encrypted string, provider KeyProvider) (string, error) {
	if m.decapsKey == nil {
		return "", errors.New("ML-KEM decapsulation key not initialized")
	}

	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
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

// EncapsulationKeyBytes returns the public encapsulation key.
func (m *MLKEM768) EncapsulationKeyBytes() []byte {
	if m.encapKey == nil {
		return nil
	}
	return m.encapKey.Bytes()
}

// DecapsulationKeyBytes returns the secret key for storage.
func (m *MLKEM768) DecapsulationKeyBytes() []byte {
	if m.decapsKey == nil {
		return nil
	}
	return m.decapsKey.Bytes()
}

// EncapsulationKeySize returns the size of the encapsulation key.
func (m *MLKEM768) EncapsulationKeySize() int {
	return mlkem.EncapsulationKeySize768
}

// CiphertextSize returns the size of ML-KEM-768 ciphertext.
func (m *MLKEM768) CiphertextSize() int {
	return mlkem.CiphertextSize768
}

// SharedKeySize returns the size of the shared key.
func (m *MLKEM768) SharedKeySize() int {
	return mlkem.SharedKeySize
}
