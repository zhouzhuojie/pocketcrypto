package hooks

import (
	"context"
	"fmt"
	"log"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"pocketcrypto/crypto"
)

// EncryptionHooks registers encryption/decryption hooks for PocketBase.
// This automatically encrypts sensitive fields before saving and decrypts
// them when responding to API requests.
type EncryptionHooks struct {
	app        *pocketbase.PocketBase
	encrypter  crypto.Encrypter
	provider   crypto.KeyProvider
	encryptFields  map[string][]string // collection -> fields to encrypt
	decryptFields  map[string][]string // collection -> fields to decrypt
}

// NewEncryptionHooks creates a new EncryptionHooks instance.
func NewEncryptionHooks(app *pocketbase.PocketBase, encrypter crypto.Encrypter, provider crypto.KeyProvider) *EncryptionHooks {
	return &EncryptionHooks{
		app:           app,
		encrypter:     encrypter,
		provider:      provider,
		encryptFields: make(map[string][]string),
		decryptFields: make(map[string][]string),
	}
}

// AddCollection registers a collection for encryption with the specified fields.
// The fields will be encrypted on create/update and decrypted on response.
func (h *EncryptionHooks) AddCollection(collection string, fields ...string) *EncryptionHooks {
	h.encryptFields[collection] = append(h.encryptFields[collection], fields...)
	h.decryptFields[collection] = append(h.decryptFields[collection], fields...)
	return h
}

// Register registers all the encryption/decryption hooks with the PocketBase app.
func (h *EncryptionHooks) Register() error {
	for collection, fields := range h.encryptFields {
		if err := h.registerCollectionHooks(collection, fields); err != nil {
			return fmt.Errorf("failed to register hooks for %s: %w", collection, err)
		}
	}
	return nil
}

// registerCollectionHooks registers hooks for a specific collection.
func (h *EncryptionHooks) registerCollectionHooks(collection string, fields []string) error {
	// Encrypt on create (before save)
	h.app.OnRecordCreateExecute(collection).BindFunc(func(e *core.RecordEvent) error {
		if e.Type == "create" {
			h.encryptRecord(e.Record, fields)
		}
		return e.Next()
	})

	// Encrypt on update (before save)
	h.app.OnRecordUpdateExecute(collection).BindFunc(func(e *core.RecordEvent) error {
		if e.Type == "update" {
			h.encryptRecord(e.Record, fields)
		}
		return e.Next()
	})

	// Decrypt on view (response)
	h.app.OnRecordViewRequest(collection).BindFunc(func(e *core.RecordRequestEvent) error {
		h.decryptRecord(e.Record, fields)
		return e.Next()
	})

	log.Printf("registered encryption hooks for collection %s on fields %v", collection, fields)
	return nil
}

// encryptRecord encrypts the specified fields in a record.
func (h *EncryptionHooks) encryptRecord(record *core.Record, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || crypto.IsEncrypted(value) {
			continue
		}

		encrypted, err := h.encrypter.Encrypt(value, h.provider)
		if err != nil {
			log.Printf("encryption failed for field %s: %v", field, err)
			continue
		}

		record.Set(field, encrypted)
	}
}

// decryptRecord decrypts the specified fields in a record.
func (h *EncryptionHooks) decryptRecord(record *core.Record, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || !crypto.IsEncrypted(value) {
			continue
		}

		decrypted, err := h.encrypter.Decrypt(value, h.provider)
		if err != nil {
			log.Printf("decryption failed for field %s: %v", field, err)
			continue
		}

		record.Set(field, decrypted)
	}
}

// CollectionConfig holds configuration for encrypting a collection.
type CollectionConfig struct {
	Collection string   // Collection name
	Fields     []string // Fields to encrypt
}

// NewEncryptionHooksFromConfig creates encryption hooks from a configuration.
// This is the recommended factory function for most use cases.
func NewEncryptionHooksFromConfig(
	app *pocketbase.PocketBase,
	encrypter crypto.Encrypter,
	provider crypto.KeyProvider,
	configs []CollectionConfig,
) (*EncryptionHooks, error) {
	hooks := NewEncryptionHooks(app, encrypter, provider)

	for _, cfg := range configs {
		if cfg.Collection == "" {
			return nil, fmt.Errorf("collection name cannot be empty")
		}
		if len(cfg.Fields) == 0 {
			return nil, fmt.Errorf("collection %s must have at least one field to encrypt", cfg.Collection)
		}
		hooks.AddCollection(cfg.Collection, cfg.Fields...)
	}

	return hooks, nil
}

// RegisterEncryption registers encryption hooks with a flexible configuration.
// This is more generic than RegisterDefaultEncryption.
func RegisterEncryption(
	ctx context.Context,
	app *pocketbase.PocketBase,
	encrypter crypto.Encrypter,
	configs []CollectionConfig,
) (*EncryptionHooks, error) {
	provider, err := crypto.NewProviderFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	hooks, err := NewEncryptionHooksFromConfig(app, encrypter, provider, configs)
	if err != nil {
		return nil, err
	}

	if err := hooks.Register(); err != nil {
		return nil, fmt.Errorf("failed to register encryption hooks: %w", err)
	}

	return hooks, nil
}

// RegisterDefaultEncryption registers encryption hooks with sensible defaults
// for a typical crypto application.
// NOTE: Use RegisterEncryption with custom configs for production use.
func RegisterDefaultEncryption(ctx context.Context, app *pocketbase.PocketBase) (*EncryptionHooks, error) {
	// Default configuration for a crypto wallet application
	// Customize these collections/fields based on your actual schema
	configs := []CollectionConfig{
		{Collection: "wallets", Fields: []string{"private_key", "mnemonic", "seed_phrase"}},
		{Collection: "accounts", Fields: []string{"api_key", "api_secret", "private_key"}},
		{Collection: "secrets", Fields: []string{"value"}},
	}

	// Use ML-KEM-768 for post-quantum security by default
	return RegisterEncryption(ctx, app, &crypto.MLKEM768{}, configs)
}
