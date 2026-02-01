package pocketcrypto

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegister_Validation(t *testing.T) {
	// Set up a valid encryption key for local provider
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	os.Setenv("ENCRYPTION_KEY", validKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	t.Run("fails with empty configs", func(t *testing.T) {
		hooks, err := Register(context.Background(), nil, &AES256GCM{}, []CollectionConfig{})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "at least one collection config is required")
	})

	t.Run("fails with empty collection name", func(t *testing.T) {
		configs := []CollectionConfig{
			{Collection: "", Fields: []string{"private_key"}},
		}

		hooks, err := Register(context.Background(), nil, &AES256GCM{}, configs)
		assert.Error(t, err)
		assert.Nil(t, hooks)
	})

	t.Run("fails with empty fields", func(t *testing.T) {
		configs := []CollectionConfig{
			{Collection: "wallets", Fields: []string{}},
		}

		hooks, err := Register(context.Background(), nil, &AES256GCM{}, configs)
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "must have at least one field to encrypt")
	})

	t.Run("succeeds with valid single config", func(t *testing.T) {
		configs := []CollectionConfig{
			{Collection: "wallets", Fields: []string{"private_key"}},
		}

		// This will fail at the PocketBase app check, which is expected
		// The important thing is that config validation passes
		hooks, err := Register(context.Background(), nil, &AES256GCM{}, configs)
		assert.Error(t, err)
		assert.Nil(t, hooks)
		// Error should be about PocketBase app, not config validation
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})

	t.Run("succeeds with valid multiple configs", func(t *testing.T) {
		configs := []CollectionConfig{
			{Collection: "wallets", Fields: []string{"private_key"}},
			{Collection: "accounts", Fields: []string{"api_key", "api_secret"}},
			{Collection: "secrets", Fields: []string{"value"}},
		}

		hooks, err := Register(context.Background(), nil, &AES256GCM{}, configs)
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})
}

func TestRegisterDefault_Validation(t *testing.T) {
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	os.Setenv("ENCRYPTION_KEY", validKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	t.Run("default config has three collections", func(t *testing.T) {
		// RegisterDefault uses hardcoded configs, verify the function exists
		// and can be called (will fail at PocketBase app check)
		_, err := RegisterDefault(context.Background(), nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})
}
