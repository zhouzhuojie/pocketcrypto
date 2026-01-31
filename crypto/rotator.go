package crypto

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RotatableProvider extends KeyProvider with rotation support.
// Implementations should handle key versioning internally.
type RotatableProvider interface {
	KeyProvider
	// RotateKey rotates to a new key version, returns the new key ID
	RotateKey(ctx context.Context) (string, error)
	// GetKeyVersion retrieves a specific key version
	GetKeyVersion(keyID string, version int) ([]byte, error)
	// CurrentKeyVersion returns the current active key version
	CurrentKeyVersion() int
}

// KeyVersionInfo contains metadata about a key version.
type KeyVersionInfo struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
}

// KeyRotator handles re-encryption of data during key rotation.
// It supports two modes:
// 1. Lazy rotation: Decrypt with old key, re-encrypt with new key on read
// 2. Full rotation: Batch re-encrypt all records via CLI
type KeyRotator struct {
	provider  RotatableProvider
	encrypter Encrypter
}

// NewKeyRotator creates a new KeyRotator.
func NewKeyRotator(provider RotatableProvider, encrypter Encrypter) *KeyRotator {
	return &KeyRotator{
		provider:  provider,
		encrypter: encrypter,
	}
}

// LazyDecrypt decrypts data and re-encrypts it with the current key
// if it was encrypted with an old key version.
// Returns: (decrypted plaintext, new encrypted value, was rotated, error)
// When rotated is true, newEncrypted contains the re-encrypted data.
func (r *KeyRotator) LazyDecrypt(encrypted string, currentProvider KeyProvider) (string, string, bool, error) {
	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
		return "", "", false, err
	}

	// If already using current key, just decrypt
	if envelope.KeyID == currentProvider.KeyID() {
		plaintext, err := r.encrypter.Decrypt(encrypted, currentProvider)
		return plaintext, "", false, err
	}

	// Try to get the old key
	oldKey, err := r.provider.GetKey(envelope.KeyID)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot find key version %s: %w", envelope.KeyID, err)
	}

	// Create a temporary provider for the old key
	oldProvider := &staticProvider{keyID: envelope.KeyID, key: oldKey}

	// Decrypt with old key
	plaintext, err := r.encrypter.Decrypt(encrypted, oldProvider)
	if err != nil {
		return "", "", false, err
	}

	// Re-encrypt with current key (lazy rotation)
	newEncrypted, err := r.encrypter.Encrypt(plaintext, currentProvider)
	if err != nil {
		return "", "", false, err
	}

	return plaintext, newEncrypted, true, nil
}

// RotateCollection re-encrypts all records in a collection with batch processing.
// This is intended for CLI use during scheduled key rotation.
// Records are processed in batches with configurable size for memory efficiency.
// Each batch can be checkpointed for idempotency (resume from last successful batch).
func (r *KeyRotator) RotateCollection(
	ctx context.Context,
	records []EncryptedRecord,
	batchSize int,
	updateRecord func(record *EncryptedRecord) error,
) (migrated, skipped int, err error) {
	if batchSize <= 0 {
		batchSize = 100 // default batch size
	}

	totalRecords := len(records)

	for i := 0; i < totalRecords; i += batchSize {
		end := i + batchSize
		if end > totalRecords {
			end = totalRecords
		}

		batch := records[i:end]
		batchMigrated, batchSkipped, err := r.rotateBatch(ctx, batch, updateRecord)
		migrated += batchMigrated
		skipped += batchSkipped

		log.Printf("key rotation progress: %d/%d records processed (batch %d-%d, migrated=%d, skipped=%d)",
			end, totalRecords, i, end, batchMigrated, batchSkipped)

		if err != nil {
			log.Printf("batch rotation error at batch starting at %d: %v", i, err)
			return migrated, skipped, fmt.Errorf("batch rotation failed at record %d: %w", i, err)
		}
	}

	log.Printf("key rotation completed: %d migrated, %d skipped out of %d total records",
		migrated, skipped, totalRecords)

	return migrated, skipped, nil
}

// rotateBatch processes a single batch of records.
func (r *KeyRotator) rotateBatch(
	ctx context.Context,
	batch []EncryptedRecord,
	updateRecord func(record *EncryptedRecord) error,
) (migrated, skipped int, err error) {
	for _, record := range batch {
		select {
		case <-ctx.Done():
			return migrated, skipped, ctx.Err()
		default:
		}

		updated := false
		for fieldName, encrypted := range record.EncryptedFields {
			_, newEncrypted, rotated, err := r.LazyDecrypt(encrypted, r.provider)
			if err != nil {
				log.Printf("skipping field %s in record %s: %v", fieldName, record.ID, err)
				skipped++
				continue
			}

			if rotated {
				record.EncryptedFields[fieldName] = newEncrypted
				updated = true
			}
		}

		if updated {
			if err := updateRecord(&record); err != nil {
				log.Printf("failed to update record %s: %v", record.ID, err)
				skipped++
				continue
			}
			migrated++
		}
	}

	return migrated, skipped, nil
}

// RotateRecord rotates encryption for a single record.
// This is useful for on-demand rotation or lazy rotation during read.
// Returns the updated record and whether rotation occurred.
func (r *KeyRotator) RotateRecord(record *EncryptedRecord) (*EncryptedRecord, bool, error) {
	updated := false
	for fieldName, encrypted := range record.EncryptedFields {
		_, newEncrypted, rotated, err := r.LazyDecrypt(encrypted, r.provider)
		if err != nil {
			return record, false, err
		}

		if rotated {
			record.EncryptedFields[fieldName] = newEncrypted
			updated = true
		}
	}

	return record, updated, nil
}

// EncryptedRecord represents a record with encrypted fields.
type EncryptedRecord struct {
	ID              string            `json:"id"`
	EncryptedFields map[string]string `json:"encrypted_fields"`
}

// RotateKey creates a new key version.
func (r *KeyRotator) RotateKey(ctx context.Context) error {
	newKeyID, err := r.provider.RotateKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}
	log.Printf("rotated to new key version: %s", newKeyID)
	return nil
}

// staticProvider is a helper provider for a fixed key.
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
