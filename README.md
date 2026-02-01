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

PocketCrypto supports **lazy key rotation** by default:

### How It Works

1. **Encrypt always uses current key**
2. **Decrypt tries current key first**, falls back to previous key if needed
3. **Old data is automatically re-encrypted on read** (lazy rotation)
4. **Proactive batch migration** available for complete migration

### Local Provider Rotation

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

### Production Flow

**Read Path (Automatic Lazy Rotation):**
```
Read Record → Try decrypt with current key → Failed?
  → Try decrypt with previous key → Success?
    → Re-encrypt with current key, save, return plaintext
  → Current key success? Return plaintext
```

**Write Path:**
```
Write Record → Encrypt with current key → Save
  → Works seamlessly during rotation
  → No code changes needed
```

### Proactive Batch Migration

For faster migration or zero reads:

```go
rotator := pocketcrypto.NewKeyRotator(provider, &pocketcrypto.AES256GCM{})

migrated, skipped, err := rotator.RotateAll(
    ctx,
    allRecords,
    func(r *EncryptedRecord) error {
        return db.Save(r.ID, r.EncryptedFields)
    },
)
```

### Rotation Checklist

1. **Before rotation:** Store new key (Local: ENCRYPTION_KEY, KMS/Vault: in service)
2. **During rotation:** Reads automatically lazy-rotate old data
3. **After rotation:** Remove old key (ENCRYPTION_KEY_OLD) when all data migrated

## What You Can't Do

- Search or filter encrypted fields
- Index encrypted fields for fast lookups
- Compare encrypted values

## License

Apache 2.0
