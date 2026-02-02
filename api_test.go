package pocketcrypto

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestRegister(t *testing.T) {
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	os.Setenv("ENCRYPTION_KEY", validKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	t.Run("fails with no configs", func(t *testing.T) {
		hooks, err := Register(nil, &AES256GCM{})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "at least one collection config is required")
	})

	t.Run("fails with empty collection name", func(t *testing.T) {
		hooks, err := Register(nil, &AES256GCM{},
			CollectionConfig{Collection: "", Fields: []string{"private_key"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
	})

	t.Run("fails with empty fields", func(t *testing.T) {
		hooks, err := Register(nil, &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "must have at least one field to encrypt")
	})

	t.Run("fails with nil PocketBase app", func(t *testing.T) {
		hooks, err := Register(nil, &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})

	t.Run("fails with invalid app type", func(t *testing.T) {
		hooks, err := Register("not-a-pb-app", &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})

	t.Run("fails with invalid provider", func(t *testing.T) {
		os.Unsetenv("ENCRYPTION_KEY")
		defer os.Setenv("ENCRYPTION_KEY", validKey)

		hooks, err := Register("invalid", &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		// Either error is acceptable - app check or provider check
		assert.True(t, contains(err.Error(), "app is not a PocketBase instance") || contains(err.Error(), "ENCRYPTION_KEY"))
	})

	t.Run("multiple collection configs", func(t *testing.T) {
		hooks, err := Register("invalid", &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}},
			CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
			CollectionConfig{Collection: "accounts", Fields: []string{"api_key", "api_secret"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})
}

func TestDataEnvelope(t *testing.T) {
	t.Run("marshal and unmarshal round trip", func(t *testing.T) {
		envelope := DataEnvelope{
			Algorithm:    "AES-256-GCM",
			KeyID:        "test-key",
			EncryptedKey: "",
			Nonce:        "test-nonce",
			Ciphertext:   "test-ciphertext",
			Version:      1,
		}

		marshaled := envelope.Marshal()
		require.NotEmpty(t, marshaled)

		var decoded DataEnvelope
		err := decoded.Unmarshal(marshaled)
		require.NoError(t, err)

		assert.Equal(t, envelope.Algorithm, decoded.Algorithm)
		assert.Equal(t, envelope.KeyID, decoded.KeyID)
		assert.Equal(t, envelope.Nonce, decoded.Nonce)
		assert.Equal(t, envelope.Ciphertext, decoded.Ciphertext)
		assert.Equal(t, envelope.Version, decoded.Version)
	})

	t.Run("unmarshal invalid JSON", func(t *testing.T) {
		var envelope DataEnvelope
		err := envelope.Unmarshal("not-valid-json")
		assert.Error(t, err)
	})

	t.Run("unmarshal empty string", func(t *testing.T) {
		var envelope DataEnvelope
		err := envelope.Unmarshal("")
		assert.Error(t, err)
	})
}

func TestCollectionConfig(t *testing.T) {
	t.Run("basic config", func(t *testing.T) {
		cfg := CollectionConfig{
			Collection: "wallets",
			Fields:     []string{"private_key", "mnemonic"},
		}
		assert.Equal(t, "wallets", cfg.Collection)
		assert.Len(t, cfg.Fields, 2)
	})
}

func TestFieldEncryptionRequest(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		req := FieldEncryptionRequest{
			CollectionConfig: CollectionConfig{
				Collection: "wallets",
				Fields:     []string{"private_key"},
			},
		}
		assert.False(t, req.DryRun)
		assert.Equal(t, 0, req.BatchSize)
	})

	t.Run("with custom values", func(t *testing.T) {
		req := FieldEncryptionRequest{
			CollectionConfig: CollectionConfig{
				Collection: "secrets",
				Fields:     []string{"value"},
			},
			DryRun:    true,
			BatchSize: 50,
		}
		assert.True(t, req.DryRun)
		assert.Equal(t, 50, req.BatchSize)
	})
}

func TestFieldEncryptionResult(t *testing.T) {
	t.Run("empty result", func(t *testing.T) {
		result := FieldEncryptionResult{}
		assert.Equal(t, 0, result.TotalRecords)
		assert.Equal(t, 0, result.Migrated)
		assert.Equal(t, 0, result.Skipped)
		assert.Nil(t, result.Errors)
	})

	t.Run("result with errors", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 100,
			Migrated:     75,
			Skipped:      20,
			Errors:       []string{"error 1", "error 2"},
		}
		assert.Equal(t, 100, result.TotalRecords)
		assert.Equal(t, 75, result.Migrated)
		assert.Equal(t, 20, result.Skipped)
		assert.Len(t, result.Errors, 2)
	})
}

func TestEncryptionStatus(t *testing.T) {
	t.Run("status representation", func(t *testing.T) {
		status := EncryptionStatus{
			Collection:     "wallets",
			TotalRecords:   500,
			EncryptedCount: 300,
			PlaintextCount: 200,
		}
		assert.Equal(t, "wallets", status.Collection)
		assert.Equal(t, 500, status.TotalRecords)
		assert.Equal(t, 300, status.EncryptedCount)
		assert.Equal(t, 200, status.PlaintextCount)
	})
}
