package pocketcrypto

import (
	"crypto/mlkem"
	"encoding/base64"
	"errors"
)

// MLKEM768 provides post-quantum encryption using ML-KEM-768 (FIPS 203).
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
func (m *MLKEM768) SecretKey() []byte {
	if m.decapsKey == nil {
		return nil
	}
	return m.decapsKey.Bytes()
}

// NewMLKEM768 generates a new ML-KEM-768 key pair.
func NewMLKEM768() (*MLKEM768, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &MLKEM768{
		decapsKey: dk,
		encapKey:  dk.EncapsulationKey(),
	}, nil
}

// newMLKEM768 is the internal implementation.
func newMLKEM768() (*MLKEM768, error) {
	return NewMLKEM768()
}

// NewMLKEM768FromSeed creates an ML-KEM-768 key pair from a seed.
func NewMLKEM768FromSeed(seed []byte) (*MLKEM768, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &MLKEM768{
		decapsKey: dk,
		encapKey:  dk.EncapsulationKey(),
	}, nil
}

// newMLKEM768FromSeed is the internal implementation.
func newMLKEM768FromSeed(seed []byte) (*MLKEM768, error) {
	return NewMLKEM768FromSeed(seed)
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

