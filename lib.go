// Package pocketcrypto provides column-level encryption for PocketBase
// with support for AES-256-GCM authenticated encryption, post-quantum
// ML-KEM-768 key encapsulation, and multiple key management providers.
//
// # Quick Start
//
// Register encryption hooks for PocketBase collections:
//
//	hooks, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{},
//	    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}},
//	    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
//	)
//
// # Encryption Algorithms
//
// Two encryption algorithms are available:
//   - AES256GCM: Standard AES-256-GCM authenticated encryption
//   - MLKEM768:  Post-quantum ML-KEM-768 key encapsulation (FIPS 203)
//
// # Key Providers
//
// Three key providers are supported:
//   - Local:  Environment variables (ENCRYPTION_KEY)
//   - AWS KMS: AWS Key Management Service
//   - Vault:  HashiCorp Vault
//
// The provider is selected automatically based on environment variables.
package pocketcrypto

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// Register registers encryption hooks for PocketBase with a one-call setup.
//
// This function registers hooks for both existing and future collections:
//   - Existing collections are registered immediately
//   - New collections created via the API are automatically detected and registered
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

	// Validate configs
	for _, cfg := range configs {
		if cfg.Collection == "" {
			return nil, fmt.Errorf("collection name cannot be empty")
		}
		if len(cfg.Fields) == 0 {
			return nil, fmt.Errorf("collection %s must have at least one field to encrypt", cfg.Collection)
		}
	}

	pb, ok := app.(*pocketbase.PocketBase)
	if !ok {
		return nil, fmt.Errorf("app is not a PocketBase instance")
	}

	provider, err := newProvider("")
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	hooks := newEncryptionHooks(app, encrypter, provider)

	for _, cfg := range configs {
		hooks.AddCollection(cfg.Collection, cfg.Fields...)
	}

	// Register hooks for configured collections
	if err := hooks.Register(); err != nil {
		return nil, fmt.Errorf("failed to register encryption hooks: %w", err)
	}

	// Build a filter from configs for dynamic registration
	configMap := make(map[string][]string)
	for _, cfg := range configs {
		configMap[cfg.Collection] = cfg.Fields
	}

	// Register dynamic listener for future collections
	hooks.registerDynamicCollections(pb, configMap)

	return hooks, nil
}

// IsEncrypted checks if the data appears to be encrypted.
func IsEncrypted(data string) bool {
	var envelope DataEnvelope
	return envelope.Unmarshal(data) == nil && envelope.Ciphertext != ""
}

// CollectionConfig holds configuration for encrypting a collection.
type CollectionConfig struct {
	Collection string   `json:"collection"`
	Fields     []string `json:"fields"`
}

// EncryptedRecord represents a record with encrypted fields.
type EncryptedRecord struct {
	ID              string            `json:"id"`
	EncryptedFields map[string]string `json:"encrypted_fields"`
}

// FieldEncryptionRequest extends CollectionConfig with dry-run and batch options.
type FieldEncryptionRequest struct {
	CollectionConfig
	DryRun    bool `json:"dry_run"`
	BatchSize int  `json:"batch_size"`
}

// FieldEncryptionResult contains the outcome of field encryption.
type FieldEncryptionResult struct {
	TotalRecords int      `json:"total_records"`
	Migrated     int      `json:"migrated"`
	Skipped      int      `json:"skipped"`
	Errors       []string `json:"errors"`
}

// EncryptionStatus holds the encryption status for a collection.
type EncryptionStatus struct {
	Collection     string `json:"collection"`
	TotalRecords   int    `json:"total_records"`
	EncryptedCount int    `json:"encrypted_count,omitempty"`
	PlaintextCount int    `json:"plaintext_count,omitempty"`
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

// KeyProvider defines the interface for key management services.
type KeyProvider interface {
	GetKey(keyID string) ([]byte, error)
	EncryptKey(key []byte, keyID string) ([]byte, error)
	DecryptKey(encryptedKey []byte) ([]byte, error)
	KeyID() string
}

// RotatableProvider extends KeyProvider with rotation support.
type RotatableProvider interface {
	KeyProvider
	RotateKey(ctx context.Context) (string, error)
	GetKeyVersion(keyID string, version int) ([]byte, error)
	CurrentKeyVersion() int
}

// Encrypter interface supports multiple encryption algorithms.
type Encrypter interface {
	Encrypt(plaintext string, keyProvider KeyProvider) (string, error)
	Decrypt(encrypted string, keyProvider KeyProvider) (string, error)
	Algorithm() string
	KeySize() int
}

// DataEnvelope holds encrypted data with metadata.
type DataEnvelope struct {
	Algorithm    string `json:"alg"`
	KeyID        string `json:"kid"`
	EncryptedKey string `json:"ek"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ct"`
	Version      int    `json:"v"`
}

// Marshal serializes the envelope to JSON.
func (e *DataEnvelope) Marshal() string {
	data, _ := json.Marshal(e)
	return string(data)
}

// Unmarshal deserializes JSON data into an envelope.
func (e *DataEnvelope) Unmarshal(data string) error {
	return json.Unmarshal([]byte(data), e)
}

// ProviderType defines the type of key provider.
type ProviderType string

const (
	ProviderTypeLocal  ProviderType = "local"
	ProviderTypeAWSKMS ProviderType = "aws-kms"
	ProviderTypeVault  ProviderType = "vault"
)

// KeyVersionInfo contains metadata about a key version.
type KeyVersionInfo struct {
	Version   int
	CreatedAt int64
	Algorithm string
}

// Internal types and functions

// recordHelper interface for encrypting/decrypting record fields.
type recordHelper interface {
	GetString(field string) string
	Set(field string, value any)
}

// unknownProviderTypeError is an error for unknown provider types.
type unknownProviderTypeError struct{}

func (e *unknownProviderTypeError) Error() string {
	return "unknown key provider type"
}

var errUnknownProviderType = &unknownProviderTypeError{}

func newEncryptionHooks(app any, encrypter Encrypter, provider KeyProvider) *EncryptionHooks {
	return &EncryptionHooks{
		app:           app,
		encrypter:     encrypter,
		provider:      provider,
		encryptFields: make(map[string][]string),
		decryptFields: make(map[string][]string),
	}
}

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

	return nil
}

func (h *EncryptionHooks) encryptRecord(record recordHelper, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || IsEncrypted(value) {
			continue
		}

		encrypted, err := h.encrypter.Encrypt(value, h.provider)
		if err != nil {
			continue
		}

		record.Set(field, encrypted)
	}
}

func (h *EncryptionHooks) decryptRecord(record recordHelper, fields []string) {
	for _, field := range fields {
		value := record.GetString(field)
		if value == "" || !IsEncrypted(value) {
			continue
		}

		decrypted, err := h.lazyDecrypt(value)
		if err != nil {
			continue
		}

		record.Set(field, decrypted)
	}
}

func (h *EncryptionHooks) lazyDecrypt(encrypted string) (string, error) {
	plaintext, err := h.encrypter.Decrypt(encrypted, h.provider)
	if err == nil {
		return plaintext, nil
	}

	prevProvider, ok := h.provider.(interface{ GetKey(keyID string) ([]byte, error) })
	if !ok {
		return "", fmt.Errorf("decryption failed and provider doesn't support rotation: %w", err)
	}

	prevKey, err := prevProvider.GetKey("previous")
	if err != nil || prevKey == nil {
		return "", fmt.Errorf("decryption failed (no previous key): %w", err)
	}

	tempProvider := &staticProvider{keyID: "previous", key: prevKey}

	plaintext, err = h.encrypter.Decrypt(encrypted, tempProvider)
	if err != nil {
		return "", fmt.Errorf("decryption failed with previous key: %w", err)
	}

	newEncrypted, err := h.encrypter.Encrypt(plaintext, h.provider)
	if err != nil {
		return "", fmt.Errorf("re-encryption failed during rotation: %w", err)
	}

	return newEncrypted, nil
}

func (h *EncryptionHooks) registerDynamicCollections(app *pocketbase.PocketBase, configMap map[string][]string) {
	registered := make(map[string]bool)

	if app.DB() != nil {
		collections, _ := app.FindAllCollections()
		for _, col := range collections {
			if fields := configMap[col.Name]; len(fields) > 0 && !registered[col.Name] {
				h.registerCollection(app, col.Name, fields...)
				registered[col.Name] = true
			}
		}
	}

	app.OnCollectionAfterCreateSuccess().BindFunc(func(e *core.CollectionEvent) error {
		collectionName := e.Collection.Name
		if fields := configMap[collectionName]; len(fields) > 0 && !registered[collectionName] {
			h.registerCollection(app, collectionName, fields...)
			registered[collectionName] = true
		}
		return nil
	})
}

func (h *EncryptionHooks) registerCollection(app *pocketbase.PocketBase, collection string, fields ...string) {
	if _, exists := h.encryptFields[collection]; exists {
		return
	}
	h.encryptFields[collection] = fields
	h.decryptFields[collection] = fields
	h.registerCollectionHooks(app, collection, fields)
}

// FieldEncrypter handles batch encryption of plaintext fields.
type FieldEncrypter struct {
	app       *pocketbase.PocketBase
	encrypter Encrypter
	provider  KeyProvider
}

func newFieldEncrypter(app *pocketbase.PocketBase, encrypter Encrypter, provider KeyProvider) *FieldEncrypter {
	return &FieldEncrypter{
		app:       app,
		encrypter: encrypter,
		provider:  provider,
	}
}

func (fe *FieldEncrypter) Apply(ctx context.Context, req FieldEncryptionRequest) (*FieldEncryptionResult, error) {
	if req.BatchSize <= 0 {
		req.BatchSize = 100
	}

	result := &FieldEncryptionResult{}

	collection, err := fe.app.FindCollectionByNameOrId(req.Collection)
	if err != nil {
		return nil, fmt.Errorf("collection not found: %w", err)
	}

	var totalCount int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", collection.Name)
	err = fe.app.DB().NewQuery(countQuery).One(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count records: %w", err)
	}
	result.TotalRecords = totalCount

	offset := 0
	for offset < totalCount {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		records, err := fe.findRecords(collection, offset, req.BatchSize)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("fetch failed at offset %d: %v", offset, err))
			offset += req.BatchSize
			continue
		}

		for _, record := range records {
			migrated, err := fe.encryptRecord(record, req.Fields)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("record %s: %v", record.Id, err))
				result.Skipped++
				continue
			}

			if migrated {
				if !req.DryRun {
					if err := fe.app.Save(record); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("update failed for %s: %v", record.Id, err))
						result.Skipped++
						continue
					}
				}
				result.Migrated++
			} else {
				result.Skipped++
			}
		}

		offset += req.BatchSize
	}

	return result, nil
}

func (fe *FieldEncrypter) findRecords(collection *core.Collection, offset, limit int) ([]*core.Record, error) {
	var records []*core.Record
	query := fmt.Sprintf("SELECT * FROM %s LIMIT %d OFFSET %d", collection.Name, limit, offset)
	err := fe.app.DB().NewQuery(query).All(&records)
	return records, err
}

func (fe *FieldEncrypter) encryptRecord(record *core.Record, fields []string) (bool, error) {
	anyMigrated := false

	for _, field := range fields {
		value := record.GetString(field)
		if value == "" {
			continue
		}

		if IsEncrypted(value) {
			continue
		}

		encrypted, err := fe.encrypter.Encrypt(value, fe.provider)
		if err != nil {
			return false, fmt.Errorf("encryption failed for field %s: %w", field, err)
		}

		record.Set(field, encrypted)
		anyMigrated = true
	}

	return anyMigrated, nil
}

func (fe *FieldEncrypter) Status(ctx context.Context, collectionName string) (*EncryptionStatus, error) {
	collection, err := fe.app.FindCollectionByNameOrId(collectionName)
	if err != nil {
		return nil, fmt.Errorf("collection not found: %w", err)
	}

	status := &EncryptionStatus{
		Collection: collectionName,
	}

	var totalCount int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", collection.Name)
	err = fe.app.DB().NewQuery(countQuery).One(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count records: %w", err)
	}
	status.TotalRecords = totalCount

	return status, nil
}

// providerRegistry stores factories for creating KeyProvider instances.
// Built-in providers are registered at initialization.
var providerRegistry = make(map[ProviderType]func() (KeyProvider, error))

func init() {
	// Register built-in providers with type-safe wrappers
	providerRegistry[ProviderTypeLocal] = func() (KeyProvider, error) { return newLocalProvider() }
	providerRegistry[ProviderTypeAWSKMS] = func() (KeyProvider, error) { return newAWSKMSProviderFromEnv() }
	providerRegistry[ProviderTypeVault] = func() (KeyProvider, error) { return newVaultProvider() }
}

// RegisterProvider registers a custom KeyProvider factory for a provider type.
// This allows applications to use custom key management without modifying pocketcrypto.
//
// Example:
//
//	import "github.com/zhouzhuojie/pocketcrypto"
//
//	type MyProvider struct{ ... }
//
//	func (p *MyProvider) GetKey(keyID string) ([]byte, error) { ... }
//	func (p *MyProvider) EncryptKey(key []byte, keyID string) ([]byte, error) { ... }
//	func (p *MyProvider) DecryptKey(encryptedKey []byte) ([]byte, error) { ... }
//	func (p *MyProvider) KeyID() string { ... }
//
//	func newMyProvider() (pocketcrypto.KeyProvider, error) {
//	    return &MyProvider{}, nil
//	}
//
//	func init() {
//	    pocketcrypto.RegisterProvider("my-custom-provider", newMyProvider)
//	}
func RegisterProvider(providerType ProviderType, factory func() (KeyProvider, error)) {
	providerRegistry[providerType] = factory
}

func newProvider(providerType ProviderType) (KeyProvider, error) {
	if providerType == "" {
		providerType = ProviderType(os.Getenv("KEY_PROVIDER"))
	}

	if providerType == "" {
		providerType = ProviderTypeLocal
	}

	factory, ok := providerRegistry[providerType]
	if !ok {
		return nil, errUnknownProviderType
	}

	return factory()
}

type staticProvider struct {
	keyID string
	key   []byte
}

func (p *staticProvider) GetKey(keyID string) ([]byte, error) {
	return p.key, nil
}

func (p *staticProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
	return key, nil
}

func (p *staticProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return encryptedKey, nil
}

func (p *staticProvider) KeyID() string {
	return p.keyID
}
