package pocketcrypto

import (
	"context"
	"fmt"
	"log"
)

// KeyRotator handles re-encryption of data during key rotation.
type KeyRotator struct {
	provider  RotatableProvider
	encrypter Encrypter
}

// newKeyRotator creates a new KeyRotator.
func newKeyRotator(provider RotatableProvider, encrypter Encrypter) *KeyRotator {
	return &KeyRotator{
		provider:  provider,
		encrypter: encrypter,
	}
}

// LazyDecrypt decrypts data and re-encrypts it with the current key.
func (r *KeyRotator) LazyDecrypt(encrypted string, currentProvider KeyProvider) (string, string, bool, error) {
	var envelope DataEnvelope
	if err := envelope.Unmarshal(encrypted); err != nil {
		return "", "", false, err
	}

	if envelope.KeyID == currentProvider.KeyID() {
		plaintext, err := r.encrypter.Decrypt(encrypted, currentProvider)
		return plaintext, "", false, err
	}

	oldKey, err := r.provider.GetKey(envelope.KeyID)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot find key version %s: %w", envelope.KeyID, err)
	}

	oldProvider := &staticProvider{keyID: envelope.KeyID, key: oldKey}

	plaintext, err := r.encrypter.Decrypt(encrypted, oldProvider)
	if err != nil {
		return "", "", false, err
	}

	newEncrypted, err := r.encrypter.Encrypt(plaintext, currentProvider)
	if err != nil {
		return "", "", false, err
	}

	return plaintext, newEncrypted, true, nil
}

// RotateCollection re-encrypts all records in a collection.
func (r *KeyRotator) RotateCollection(
	ctx context.Context,
	records []EncryptedRecord,
	batchSize int,
	updateRecord func(record *EncryptedRecord) error,
) (migrated, skipped int, err error) {
	if batchSize <= 0 {
		batchSize = 100
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

		log.Printf("key rotation progress: %d/%d records processed", end, totalRecords)

		if err != nil {
			return migrated, skipped, fmt.Errorf("batch rotation failed at record %d: %w", i, err)
		}
	}

	log.Printf("key rotation completed: %d migrated, %d skipped", migrated, skipped)
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
