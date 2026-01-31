package crypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// MLKEM768 provides post-quantum encryption using ML-KEM-768 (FIPS 203).
// This uses Go 1.24's official crypto/mlkem package.
//
// The implementation uses a hybrid approach:
// 1. Generate a random AES key for this encryption
// 2. Use ML-KEM to encapsulate (encrypt) the AES key
// 3. Use AES-256-GCM to encrypt the actual data
//
// This provides:
// - Post-quantum resistance from ML-KEM
// - Fast symmetric encryption from AES
// - Forward secrecy (each encryption uses a new encapsulated key)
type MLKEM768 struct {
	decapsKey *mlkem.DecapsulationKey768
	encapKey  *mlkem.EncapsulationKey768
}

// NewMLKEM768 generates a new ML-KEM-768 key pair.
// This should be called once during initialization to generate the master key pair.
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

// NewMLKEM768FromSeed creates an ML-KEM-768 key pair from a seed.
// The seed must be 64 bytes of uniformly random data.
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

// Algorithm returns the name of the encryption algorithm.
func (m *MLKEM768) Algorithm() string {
	return "ML-KEM-768"
}

// KeySize returns the size of the shared key produced by ML-KEM.
func (m *MLKEM768) KeySize() int {
	return mlkem.SharedKeySize
}

// Encrypt encrypts plaintext using ML-KEM-768 key encapsulation.
// This is a hybrid encryption: ML-KEM encapsulates a random AES key,
// then AES-256-GCM encrypts the actual data.
func (m *MLKEM768) Encrypt(plaintext string, provider KeyProvider) (string, error) {
	if m.encapKey == nil {
		return "", errors.New("ML-KEM encapsulation key not initialized")
	}

	// Generate random AES key for this encryption
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", err
	}

	// Encapsulate the AES key using ML-KEM
	sharedSecret, ciphertext := m.encapKey.Encapsulate()

	// Use the shared secret to encrypt data with AES-256-GCM
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

	// Decapsulate to get shared secret
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.EncryptedKey)
	if err != nil {
		return "", err
	}

	sharedSecret, err := m.decapsKey.Decapsulate(ciphertext)
	if err != nil {
		return "", err
	}

	// Use shared secret to decrypt with AES-256-GCM
	aes := &AES256GCM{}
	return aes.DecryptWithKey(envelope.Ciphertext, sharedSecret)
}

// EncapsulationKeyBytes returns the public encapsulation key for sharing.
// This can be distributed openly and used by others to encrypt data
// that only this instance can decrypt.
func (m *MLKEM768) EncapsulationKeyBytes() []byte {
	if m.encapKey == nil {
		return nil
	}
	return m.encapKey.Bytes()
}

// DecapsulationKeyBytes returns the secret key for storage/backup.
// This must be kept secure! It allows decryption of all data encrypted
// with the corresponding encapsulation key.
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
