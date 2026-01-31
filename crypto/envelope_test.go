package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataEnvelope_MarshalUnmarshal(t *testing.T) {
	envelope := DataEnvelope{
		Algorithm:    "AES-256-GCM",
		KeyID:        "local-master",
		EncryptedKey: "encrypted-key-data",
		Nonce:        "nonce-data",
		Ciphertext:   "ciphertext-data",
		Version:      1,
	}

	json := envelope.Marshal()
	assert.NotEmpty(t, json)

	var decoded DataEnvelope
	err := decoded.Unmarshal(json)
	assert.NoError(t, err)

	assert.Equal(t, envelope.Algorithm, decoded.Algorithm)
	assert.Equal(t, envelope.KeyID, decoded.KeyID)
	assert.Equal(t, envelope.EncryptedKey, decoded.EncryptedKey)
	assert.Equal(t, envelope.Nonce, decoded.Nonce)
	assert.Equal(t, envelope.Ciphertext, decoded.Ciphertext)
	assert.Equal(t, envelope.Version, decoded.Version)
}

func TestDataEnvelope_Versioning(t *testing.T) {
	envelope := DataEnvelope{
		Algorithm: "AES-256-GCM",
		Version:   1,
	}

	json := envelope.Marshal()
	var decoded DataEnvelope
	err := decoded.Unmarshal(json)
	require.NoError(t, err)

	assert.Equal(t, 1, decoded.Version, "version should be preserved")
}

func TestDataEnvelope_InvalidJSON(t *testing.T) {
	var envelope DataEnvelope
	err := envelope.Unmarshal("invalid json")
	assert.Error(t, err)
}

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{"encrypted data", `{"alg":"AES-256-GCM","kid":"test","nonce":"bm9uY2U=","ct":"Y2lwaGVydGV4dA==","v":1}`, true},
		{"plain text", "hello world", false},
		{"empty string", "", false},
		{"invalid json", "{invalid", false},
		{"json without cipher", `{"alg":"test","v":1}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEncrypted(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}
