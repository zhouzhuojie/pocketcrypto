package pocketcrypto

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	validKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	os.Setenv("ENCRYPTION_KEY", validKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	t.Run("fails with no configs", func(t *testing.T) {
		hooks, err := Register(context.Background(), nil, &AES256GCM{})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "at least one collection config is required")
	})

	t.Run("fails with empty collection name", func(t *testing.T) {
		hooks, err := Register(context.Background(), nil, &AES256GCM{},
			CollectionConfig{Collection: "", Fields: []string{"private_key"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
	})

	t.Run("fails with empty fields", func(t *testing.T) {
		hooks, err := Register(context.Background(), nil, &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "must have at least one field to encrypt")
	})

	t.Run("one-call setup", func(t *testing.T) {
		hooks, err := Register(context.Background(), nil, &AES256GCM{},
			CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}})
		assert.Error(t, err)
		assert.Nil(t, hooks)
		assert.Contains(t, err.Error(), "app is not a PocketBase instance")
	})
}
