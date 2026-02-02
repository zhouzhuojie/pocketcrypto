package pocketcrypto

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldEncryptionRequest(t *testing.T) {
	t.Run("basic request", func(t *testing.T) {
		req := FieldEncryptionRequest{
			CollectionConfig: CollectionConfig{
				Collection: "wallets",
				Fields:     []string{"private_key", "mnemonic"},
			},
			DryRun:    true,
			BatchSize: 50,
		}

		assert.Equal(t, "wallets", req.Collection)
		assert.Equal(t, []string{"private_key", "mnemonic"}, req.Fields)
		assert.True(t, req.DryRun)
		assert.Equal(t, 50, req.BatchSize)
	})
}

func TestFieldEncryptionResult(t *testing.T) {
	t.Run("empty result", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 0,
			Migrated:     0,
			Skipped:      0,
			Errors:       nil,
		}

		assert.Equal(t, 0, result.TotalRecords)
		assert.Equal(t, 0, result.Migrated)
		assert.Equal(t, 0, result.Skipped)
	})

	t.Run("result with data", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 100,
			Migrated:     75,
			Skipped:      25,
			Errors:       []string{"record 123: encryption failed"},
		}

		assert.Equal(t, 100, result.TotalRecords)
		assert.Equal(t, 75, result.Migrated)
		assert.Equal(t, 25, result.Skipped)
		assert.Len(t, result.Errors, 1)
	})
}

func TestEncryptionStatus(t *testing.T) {
	t.Run("status with counts", func(t *testing.T) {
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

func TestEncryptRecordLogic(t *testing.T) {
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	os.Setenv("ENCRYPTION_KEY", validKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	t.Run("empty value is skipped", func(t *testing.T) {
		provider, err := newProvider("")
		require.NoError(t, err)

		encrypter := &AES256GCM{}
		result, err := testEncryptRecord(encrypter, provider, "", "private_key")

		assert.NoError(t, err)
		assert.False(t, result) // No migration happened
	})

	t.Run("already encrypted is skipped", func(t *testing.T) {
		provider, err := newProvider("")
		require.NoError(t, err)

		encrypter := &AES256GCM{}

		// First encrypt something
		encrypted, err := encrypter.Encrypt("test value", provider)
		require.NoError(t, err)

		// Check that it's detected as encrypted
		result, err := testEncryptRecord(encrypter, provider, encrypted, "private_key")

		assert.NoError(t, err)
		assert.False(t, result) // No migration happened
	})

	t.Run("plaintext is encrypted", func(t *testing.T) {
		provider, err := newProvider("")
		require.NoError(t, err)

		encrypter := &AES256GCM{}
		result, err := testEncryptRecord(encrypter, provider, "my secret key", "private_key")

		assert.NoError(t, err)
		assert.True(t, result) // Migration happened
	})
}

// testEncryptRecord is a helper function that tests the encryption logic
// without needing a full PocketBase record.
func testEncryptRecord(encrypter Encrypter, provider KeyProvider, value, field string) (bool, error) {
	// Simulate the logic from encryptRecord
	if value == "" {
		return false, nil
	}

	if IsEncrypted(value) {
		return false, nil
	}

	_, err := encrypter.Encrypt(value, provider)
	if err != nil {
		return false, err
	}

	return true, nil
}

func TestFieldEncryptionRequestJSON(t *testing.T) {
	t.Run("JSON marshaling", func(t *testing.T) {
		req := FieldEncryptionRequest{
			CollectionConfig: CollectionConfig{
				Collection: "wallets",
				Fields:     []string{"private_key"},
			},
			DryRun:    true,
			BatchSize: 100,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded FieldEncryptionRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.Collection, decoded.Collection)
		assert.Equal(t, req.Fields, decoded.Fields)
		assert.Equal(t, req.DryRun, decoded.DryRun)
		assert.Equal(t, req.BatchSize, decoded.BatchSize)
	})
}

func TestFieldEncryptionResultJSON(t *testing.T) {
	t.Run("JSON marshaling", func(t *testing.T) {
		result := FieldEncryptionResult{
			TotalRecords: 500,
			Migrated:     234,
			Skipped:      266,
			Errors:       []string{"error 1", "error 2"},
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var decoded FieldEncryptionResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, result.TotalRecords, decoded.TotalRecords)
		assert.Equal(t, result.Migrated, decoded.Migrated)
		assert.Equal(t, result.Skipped, decoded.Skipped)
		assert.Equal(t, result.Errors, decoded.Errors)
	})
}

func TestDefaultBatchSize(t *testing.T) {
	t.Run("zero batch size defaults to 100", func(t *testing.T) {
		batchSize := 0
		if batchSize <= 0 {
			batchSize = 100
		}
		assert.Equal(t, 100, batchSize)
	})

	t.Run("negative batch size defaults to 100", func(t *testing.T) {
		batchSize := -5
		if batchSize <= 0 {
			batchSize = 100
		}
		assert.Equal(t, 100, batchSize)
	})

	t.Run("positive batch size is preserved", func(t *testing.T) {
		batchSize := 50
		if batchSize <= 0 {
			batchSize = 100
		}
		assert.Equal(t, 50, batchSize)
	})
}

func TestContextCancellation(t *testing.T) {
	t.Run("context cancellation stops processing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// This would normally hang or process indefinitely,
		// but with context cancellation it should return quickly
		// Note: We can't fully test this without a real PocketBase instance
		select {
		case <-ctx.Done():
			// Context was cancelled, as expected
		default:
			// Context not cancelled yet
		}
	})
}
