package pocketcrypto

import (
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
// Supports automatic lazy key rotation - old data is re-encrypted on read.
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
// Supports lazy key rotation: if decryption with current key fails,
// tries the previous key (if available) and re-encrypts with current key.
func (h *EncryptionHooks) decryptRecord(record RecordLike, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || !IsEncrypted(value) {
			continue
		}

		decrypted, rotated, err := h.lazyDecrypt(value)
		if err != nil {
			log.Printf("decryption failed for field %s: %v", field, err)
			continue
		}

		// If rotated (was encrypted with old key), save the re-encrypted value
		if rotated {
			record.Set(field, decrypted) // decrypted contains the re-encrypted value
		} else {
			record.Set(field, decrypted)
		}
	}
}

// lazyDecrypt attempts to decrypt data with the current key.
// If that fails and a previous key exists, tries the previous key.
// On success with previous key, re-encrypts with current key.
//
// Returns: (plaintext OR re-encrypted value, wasRotated, error)
func (h *EncryptionHooks) lazyDecrypt(encrypted string) (string, bool, error) {
	// Try current key first
	plaintext, err := h.encrypter.Decrypt(encrypted, h.provider)
	if err == nil {
		return plaintext, false, nil
	}

	// Try previous key if available
	prevProvider, ok := h.provider.(interface{ GetKey(keyID string) ([]byte, error) })
	if !ok {
		return "", false, fmt.Errorf("decryption failed and provider doesn't support rotation: %w", err)
	}

	// Try to get previous key
	prevKey, err := prevProvider.GetKey("previous")
	if err != nil || prevKey == nil {
		return "", false, fmt.Errorf("decryption failed (no previous key): %w", err)
	}

	// Create a temporary provider with previous key
	tempProvider := &staticProvider{keyID: "previous", key: prevKey}

	// Try decrypt with previous key
	plaintext, err = h.encrypter.Decrypt(encrypted, tempProvider)
	if err != nil {
		return "", false, fmt.Errorf("decryption failed with previous key: %w", err)
	}

	// Re-encrypt with current key (lazy rotation)
	newEncrypted, err := h.encrypter.Encrypt(plaintext, h.provider)
	if err != nil {
		return "", false, fmt.Errorf("re-encryption failed during rotation: %w", err)
	}

	return newEncrypted, true, nil
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

// Register registers encryption hooks for PocketBase with a one-call setup.
//
// Example:
//
//	hooks, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{},
//	    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
//	    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
//	)
func Register(app any, encrypter Encrypter, configs ...CollectionConfig) (*EncryptionHooks, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("at least one collection config is required")
	}

	provider, err := newProvider("")
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

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

	if err := hooks.Register(); err != nil {
		return nil, fmt.Errorf("failed to register encryption hooks: %w", err)
	}

	return hooks, nil
}
