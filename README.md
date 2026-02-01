# PocketCrypto

Column-level encryption for PocketBase.

```go
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
)
```

## Quick Start

```bash
go get github.com/zhouzhuojie/pocketcrypto
```

```go
import "github.com/zhouzhuojie/pocketcrypto"

_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
)
```

## Providers

| Provider | Environment | Description |
|----------|-------------|-------------|
| Local | `ENCRYPTION_KEY`, `ENCRYPTION_KEY_OLD` | 32-byte base64 keys (development) |
| AWS KMS | `KEY_PROVIDER=aws-kms`, `AWS_KMS_KEY_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Managed AWS keys |
| Vault | `KEY_PROVIDER=vault`, `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT_PATH`, `VAULT_KEY_PATH` | HashiCorp secrets |

```bash
# Local (single key for production, or both keys for rotation)
export ENCRYPTION_KEY="$(openssl rand -base64 32)"
export ENCRYPTION_KEY_OLD="old-key-base64-here"  # during rotation

# AWS KMS (credentials auto-loaded from env, ~/.aws/credentials, or IAM role)
export KEY_PROVIDER=aws-kms
export AWS_KMS_KEY_ID=alias/pocketcrypto-key
export AWS_REGION=us-east-1
# Optional: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Vault
export KEY_PROVIDER=vault
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=your-token
export VAULT_MOUNT_PATH=secret  # optional, defaults to "secret"
export VAULT_KEY_PATH=pocketcrypto-key  # optional, defaults to "pocketcrypto/encryption-key"
```

## Key Rotation

PocketCrypto supports two rotation strategies:

### Lazy Rotation (Recommended)

Automatic rotation when data is read. Best for zero-downtime migrations.

**Local Provider Rotation:**
```bash
# Before rotation: only current key
export ENCRYPTION_KEY="new-key-base64"

# During rotation: set old key alongside new key
export ENCRYPTION_KEY="new-key-base64"
export ENCRYPTION_KEY_OLD="old-key-base64"

# After rotation: remove old key
export ENCRYPTION_KEY="new-key-base64"
# (unset ENCRYPTION_KEY_OLD)
```

**KMS/Vault Rotation:**
```go
// 1. Generate new key in provider
newKey := provider.GenerateNewKey()  // or store in Vault

// 2. Use lazy rotation on reads
rotator := pocketcrypto.NewKeyRotator(provider, &pocketcrypto.AES256GCM{})

func getDecrypted(recordID string) (string, error) {
    encrypted := db.GetEncrypted(recordID)
    plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(encrypted, provider)
    if rotated {
        db.Save(recordID, newEncrypted)  // Persist re-encrypted value
    }
    return plaintext, err
}
```

**Production Read Path:**
```
Read Record → Decrypt with current key → Check if rotation needed
  → If old key: decrypt, re-encrypt with new key, save, return plaintext
  → If current key: return plaintext
```

### Batch Rotation

Proactive migration of all encrypted records.

```go
rotator := pocketcrypto.NewKeyRotator(provider, &pocketcrypto.AES256GCM{})

// Step 1: Make new key available in provider
// - Local: set ENCRYPTION_KEY_OLD alongside ENCRYPTION_KEY
// - KMS/Vault: store new key in the service

// Step 2: Migrate all records
migrated, skipped, err := rotator.RotateCollection(
    ctx,
    allRecords,
    100, // batch size
    func(r *pocketcrypto.EncryptedRecord) error {
        return db.BatchSave(r.ID, r.EncryptedFields)
    },
)
fmt.Printf("Migrated: %d, Skipped: %d\n", migrated, skipped)
```

**Production Write Path (During Rotation):**
```
Write Record → Encrypt with current key → Save
  → Works seamlessly with both old and new keys
  → No downtime during rotation
```

## Rotation Checklist

1. **Before rotation:** Store new key (Local: ENCRYPTION_KEY_OLD, KMS/Vault: in service)
2. **During rotation:** Use lazy rotation or batch migration
3. **After rotation:** Verify all records migrated, remove old key

## What You Can't Do

- Search or filter encrypted fields
- Index encrypted fields for fast lookups
- Compare encrypted values

## License

Apache 2.0
