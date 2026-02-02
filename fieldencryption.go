package pocketcrypto

import (
	"context"
	"fmt"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

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

// Apply encrypts plaintext fields in the specified collection.
// It processes records in batches and returns a FieldEncryptionResult.
func (fe *FieldEncrypter) Apply(ctx context.Context, req FieldEncryptionRequest) (*FieldEncryptionResult, error) {
	if req.BatchSize <= 0 {
		req.BatchSize = 100
	}

	result := &FieldEncryptionResult{}

	// Get the collection
	collection, err := fe.app.FindCollectionByNameOrId(req.Collection)
	if err != nil {
		return nil, fmt.Errorf("collection not found: %w", err)
	}

	// Get total count using raw query
	var totalCount int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", collection.Name)
	err = fe.app.DB().NewQuery(countQuery).One(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count records: %w", err)
	}
	result.TotalRecords = totalCount

	// Process records in batches
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

// findRecords returns records from a collection with pagination.
func (fe *FieldEncrypter) findRecords(collection *core.Collection, offset, limit int) ([]*core.Record, error) {
	var records []*core.Record
	query := fmt.Sprintf("SELECT * FROM %s LIMIT %d OFFSET %d", collection.Name, limit, offset)
	err := fe.app.DB().NewQuery(query).All(&records)
	return records, err
}

// encryptRecord encrypts plaintext fields in a record.
// Returns true if any field was encrypted, false if all fields were already encrypted or empty.
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

// Status returns the encryption status for a collection.
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

// EncryptionStatus holds the encryption status for a collection.
type EncryptionStatus struct {
	Collection     string `json:"collection"`
	TotalRecords   int    `json:"total_records"`
	EncryptedCount int    `json:"encrypted_count,omitempty"`
	PlaintextCount int    `json:"plaintext_count,omitempty"`
}
