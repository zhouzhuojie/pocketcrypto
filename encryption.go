package pocketcrypto

import (
	"context"
	"fmt"
	"log"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// RecordLike is an interface for record-like objects that can be encrypted/decrypted.
type RecordLike interface {
	GetString(field string) string
	Set(field string, value any)
}

// EncryptionHooks registers encryption/decryption hooks for PocketBase.
type EncryptionHooks struct {
	app           any
	encrypter     Encrypter
	provider      KeyProvider
	encryptFields map[string][]string
	decryptFields map[string][]string
}

// newEncryptionHooks creates a new EncryptionHooks instance.
func newEncryptionHooks(app any, encrypter Encrypter, provider KeyProvider) *EncryptionHooks {
	return &EncryptionHooks{
		app:           app,
		encrypter:     encrypter,
		provider:      provider,
		encryptFields: make(map[string][]string),
		decryptFields: make(map[string][]string),
	}
}

// AddCollection registers a collection for encryption.
func (h *EncryptionHooks) AddCollection(collection string, fields ...string) *EncryptionHooks {
	h.encryptFields[collection] = append(h.encryptFields[collection], fields...)
	h.decryptFields[collection] = append(h.decryptFields[collection], fields...)
	return h
}

// Register registers all the encryption/decryption hooks.
func (h *EncryptionHooks) Register() error {
	pb, ok := h.app.(*pocketbase.PocketBase)
	if !ok {
		return fmt.Errorf("app is not a PocketBase instance")
	}

	for collection, fields := range h.encryptFields {
		if err := h.registerCollectionHooks(pb, collection, fields); err != nil {
			return fmt.Errorf("failed to register hooks for %s: %w", collection, err)
		}
	}
	return nil
}

// registerCollectionHooks registers hooks for a specific collection.
func (h *EncryptionHooks) registerCollectionHooks(app *pocketbase.PocketBase, collection string, fields []string) error {
	app.OnRecordCreateExecute(collection).BindFunc(func(e *core.RecordEvent) error {
		if e.Type == "create" {
			h.encryptRecord(e.Record, fields)
		}
		return e.Next()
	})

	app.OnRecordUpdateExecute(collection).BindFunc(func(e *core.RecordEvent) error {
		if e.Type == "update" {
			h.encryptRecord(e.Record, fields)
		}
		return e.Next()
	})

	app.OnRecordViewRequest(collection).BindFunc(func(e *core.RecordRequestEvent) error {
		h.decryptRecord(e.Record, fields)
		return e.Next()
	})

	log.Printf("registered encryption hooks for collection %s on fields %v", collection, fields)
	return nil
}

// encryptRecord encrypts the specified fields in a record.
func (h *EncryptionHooks) encryptRecord(record RecordLike, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || IsEncrypted(value) {
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
func (h *EncryptionHooks) decryptRecord(record RecordLike, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || !IsEncrypted(value) {
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

// newEncryptionHooksFromConfig creates encryption hooks from a configuration.
func newEncryptionHooksFromConfig(
	app any,
	encrypter Encrypter,
	provider KeyProvider,
	configs []CollectionConfig,
) (*EncryptionHooks, error) {
	hooks := newEncryptionHooks(app, encrypter, provider)

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

// registerEncryption registers encryption hooks with a flexible configuration.
func registerEncryption(
	ctx context.Context,
	app any,
	encrypter Encrypter,
	configs []CollectionConfig,
) (*EncryptionHooks, error) {
	provider, err := newProvider(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	hooks, err := newEncryptionHooksFromConfig(app, encrypter, provider, configs)
	if err != nil {
		return nil, err
	}

	if err := hooks.Register(); err != nil {
		return nil, fmt.Errorf("failed to register encryption hooks: %w", err)
	}

	return hooks, nil
}

// registerDefaultEncryption registers encryption hooks with sensible defaults.
func registerDefaultEncryption(ctx context.Context, app any) (*EncryptionHooks, error) {
	configs := []CollectionConfig{
		{Collection: "wallets", Fields: []string{"private_key", "mnemonic", "seed_phrase"}},
		{Collection: "accounts", Fields: []string{"api_key", "api_secret", "private_key"}},
		{Collection: "secrets", Fields: []string{"value"}},
	}

	return registerEncryption(ctx, app, &MLKEM768{}, configs)
}
